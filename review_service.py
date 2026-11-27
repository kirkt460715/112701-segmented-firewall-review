"""本地审查服务：最小权限调整核对、预期结果比对与执行回执核销。

下发由独立设备团队负责，本模块只做审核与回执核对，不产生任何下发动作。
所有输入均为本地合成记录，时间点以原始记录字段为准，审查时刻由 ``at`` 显式传入。
"""
import argparse
import json
import sys
from pathlib import Path

# 隔离模式（python -I）下脚本目录不自动入 sys.path，这里显式补上，
# 记录目录仍始终以参数形式传入，不从工作目录隐式读取任何代码或数据。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from records_view import load_sources  # noqa: E402

DEVICE_TEAM = "device-team"
SECURITY_OFFICER = "security-officer"


# ---------------------------------------------------------------- 资料整理
def object_rows(policy):
    return [row for row in policy
            if {"gateway", "object", "members"} <= set(row)]


def change_rows(policy):
    return [row for row in policy if "changes" in row]


def expected_rows(policy):
    return [row for row in policy if "records" in row]


def build_object_map(policy):
    """{网关: {对象名: [成员区]}}，同名对象按网关分别解析。"""
    mapping = {}
    for row in object_rows(policy):
        mapping.setdefault(row["gateway"], {})[row["object"]] = list(row["members"])
    return mapping


def compare_named_objects(policy):
    """同名对象在不同网关的成员对应关系，成员不一致即标记 divergent。"""
    names = {}
    for row in object_rows(policy):
        names.setdefault(row["object"], {})[row["gateway"]] = list(row["members"])
    result = []
    for name in sorted(names):
        gateways = names[name]
        signatures = {tuple(members) for members in gateways.values()}
        result.append({
            "object": name,
            "gateways": gateways,
            "divergent": len(gateways) > 1 and len(signatures) > 1,
        })
    return result


def known_gateways(sources):
    policy = sources["policy"]
    receipts = sources["receipts"]
    gateways = set(build_object_map(policy))
    gateways.update(row["gateway"] for row in receipts if "gateway" in row)
    for row in change_rows(policy):
        gateways.update(target["gateway"] for target in row["changes"])
    return gateways


# ---------------------------------------------------------------- 审批时段
def is_revocation(entitlement):
    """带 effective 的是吊销/变更许可；带 expires 的是授予许可。"""
    return "effective" in entitlement


def entitlement_window(entitlement, at):
    """返回 active / pending / expired。"""
    if "expires" in entitlement:
        return "active" if at <= entitlement["expires"] else "expired"
    if "effective" in entitlement:
        return "active" if at >= entitlement["effective"] else "pending"
    return "active"


def active_entitlements(entitlements, at):
    return [row for row in entitlements if entitlement_window(row, at) == "active"]


# ---------------------------------------------------------------- 变更审查
def resolve_members(object_map, gateway, scope):
    return object_map.get(gateway, {}).get(scope)


def review_target(target, object_map, entitlements, at):
    """核对单个网关动作对每个成员区的实际影响与授权依据。"""
    gateway, scope = target["gateway"], target["scope"]
    base = {key: target[key] for key in ("gateway", "scope", "action", "position")}
    members = resolve_members(object_map, gateway, scope)
    if members is None:
        return {
            **base,
            "resolved_members": [],
            "member_findings": [],
            "unconfirmed": [{
                "scope": scope,
                "reason": f"{gateway} 缺少对象 {scope} 的定义，实际影响范围无法确认",
                "responsible": SECURITY_OFFICER,
            }],
        }

    findings, unconfirmed = [], []
    for zone in members:
        related = [row for row in entitlements if row["origin_zone"] == zone]
        if not related:
            unconfirmed.append({
                "zone": zone,
                "reason": "缺少审批材料，归属无法确认",
                "responsible": SECURITY_OFFICER,
            })
            continue
        active_grant = next(
            (row for row in related
             if not is_revocation(row) and entitlement_window(row, at) == "active"),
            None,
        )
        revocation = next((row for row in related if is_revocation(row)), None)
        if active_grant is not None:
            findings.append({
                "zone": zone,
                "decision": "over_reach",
                "entitlement": active_grant["id"],
                "owner": active_grant["owner"],
                "window": entitlement_window(active_grant, at),
                "reason": (f"{active_grant['owner']} 的有效许可 {active_grant['id']} "
                           "仍在批准时段内，共享对象会将其连带收回"),
            })
        elif revocation is not None:
            window = entitlement_window(revocation, at)
            findings.append({
                "zone": zone,
                "decision": "authorized" if window == "active" else "pending",
                "entitlement": revocation["id"],
                "owner": revocation["owner"],
                "window": window,
            })
            if window != "active":
                unconfirmed.append({
                    "zone": zone,
                    "reason": (f"吊销许可 {revocation['id']} 尚未到生效时刻 "
                               f"{revocation['effective']}"),
                    "responsible": SECURITY_OFFICER,
                })
        else:
            unconfirmed.append({
                "zone": zone,
                "reason": "现有审批均已失效，当前归属无法确认",
                "responsible": SECURITY_OFFICER,
            })

    authorized = [item["zone"] for item in findings if item["decision"] == "authorized"]
    return {
        **base,
        "resolved_members": list(members),
        "member_findings": findings,
        "narrow_to": authorized,
        "unconfirmed": unconfirmed,
    }


def rule_order_notes(change_rows_, object_map):
    """记录规则顺序与对象更名对审批范围的影响。"""
    notes = []
    for row in change_rows_:
        for target in row["changes"]:
            gateway, scope = target["gateway"], target["scope"]
            members = resolve_members(object_map, gateway, scope)
            note = {
                "gateway": gateway,
                "scope": scope,
                "position": target.get("position"),
                "members": members or [],
            }
            if members is None:
                note["order_impact"] = "对象定义缺失，顺序影响无法确认"
            elif target.get("position", 1) > 1:
                note["order_impact"] = (
                    f"deny 位于位置 {target['position']}，更早的允许规则会优先命中；"
                    "材料未提供前置规则，实际效果留待设备团队确认")
            else:
                note["order_impact"] = "位于首位，顺序上无前置规则遮挡"
            notes.append(note)
    return notes


def _matching_deny(gateway, zone, change_rows_, object_map):
    for row in change_rows_:
        for target in row["changes"]:
            if target["gateway"] != gateway or target.get("action") != "deny":
                continue
            members = resolve_members(object_map, gateway, target["scope"])
            if members is not None and zone in members:
                return target
    return None


def evaluate_expected(policy, entitlements, at):
    """合成预期许可/拒绝用例逐条与候选策略核对。"""
    object_map = build_object_map(policy)
    changes = change_rows(policy)
    active_services = {
        row["service"] for row in entitlements
        if is_revocation(row) and entitlement_window(row, at) == "active"
    }
    pending_services = {
        row["service"] for row in entitlements
        if is_revocation(row) and entitlement_window(row, at) == "pending"
    }
    checks = []
    for row in expected_rows(policy):
        for gateway, zone, service, wanted in row["records"]:
            if gateway not in object_map:
                checks.append({
                    "gateway": gateway, "zone": zone, "service": service,
                    "expected": wanted, "outcome": "unconfirmed",
                    "detail": "材料中没有该网关的对象定义，无法核对",
                })
                continue
            target = _matching_deny(gateway, zone, changes, object_map)
            if target is None:
                outcome, detail = "not_affected", "候选策略未命中该用例"
            elif service in pending_services:
                outcome, detail = "unconfirmed", (
                    f"吊销业务 {service} 尚未到批准生效时刻，当前结果无法确认")
            elif service not in active_services:
                outcome, detail = "not_affected", (
                    f"{service} 不在本次吊销业务范围内")
            else:
                detail = (f"对象 {target['scope']} 在位置 {target.get('position')} "
                          f"发起 deny，命中 {zone}")
                if target.get("position", 1) > 1:
                    detail += "；前置规则未提供，实际命中顺序留待设备团队确认"
                outcome = "consistent" if wanted == "deny" else "conflict"
            checks.append({
                "gateway": gateway, "zone": zone, "service": service,
                "expected": wanted, "outcome": outcome, "detail": detail,
            })
    return checks


def review_change(sources, at):
    policy, entitlements = sources["policy"], sources["entitlements"]
    object_map = build_object_map(policy)
    changes = change_rows(policy)
    targets = [
        review_target(target, object_map, entitlements, at)
        for row in changes for target in row["changes"]
    ]
    unconfirmed = [
        item for target in targets for item in target["unconfirmed"]
    ]
    return {
        "at": at,
        "object_correspondence": compare_named_objects(policy),
        "entitlement_windows": [
            {
                "id": row["id"],
                "owner": row["owner"],
                "origin_zone": row["origin_zone"],
                "service": row["service"],
                "direction": row["direction"],
                "window": entitlement_window(row, at),
            }
            for row in entitlements
        ],
        "changes": targets,
        "rule_order": rule_order_notes(changes, object_map),
        "expected_checks": evaluate_expected(policy, entitlements, at),
        "unconfirmed": unconfirmed,
    }


# ---------------------------------------------------------------- 回执核销
def receipt_clock(receipts):
    timestamps = [
        value for row in receipts
        for value in (row.get("received"), row.get("observed"), row.get("at"))
        if isinstance(value, int)
    ]
    return max(timestamps, default=0)


def last_verified(receipts, gateway=None):
    """每个网关最近一次经过核实的安全配置（回退基线）。"""
    baseline = {}
    for row in receipts:
        if row.get("verified") is not True or "at" not in row:
            continue
        if gateway is not None and row["gateway"] != gateway:
            continue
        current = baseline.get(row["gateway"])
        if current is None or row["at"] > current["at"]:
            baseline[row["gateway"]] = {
                "revision": row["revision"],
                "at": row["at"],
                "receipt": row["id"],
            }
    return baseline


def reconcile_receipts(sources, candidate=None, at=None):
    """按网关核销回执；旧版本回执永远不能抵消新版本的配置偏差。"""
    policy, receipts = sources["policy"], sources["receipts"]
    if candidate is None:
        candidate = next(row["candidate"] for row in change_rows(policy))
    if at is None:
        at = receipt_clock(receipts)
    gateways = known_gateways(sources)
    per_gateway, stale = {}, []
    for gateway in sorted(gateways):
        rows = [row for row in receipts if row.get("gateway") == gateway]
        entry = {"gateway": gateway, "candidate": candidate}
        accepted = next((
            row for row in rows
            if row.get("revision") == candidate and row.get("state") == "accepted"
        ), None)
        if accepted is not None and accepted.get("applied"):
            entry["state"] = "confirmed"
            entry["receipt"] = accepted["id"]
        elif accepted is not None:
            entry["state"] = "signed_unapplied"
            entry["receipt"] = accepted["id"]
            entry["unconfirmed"] = [{
                "scope": gateway,
                "reason": "已签收但没有生效确认，真实生效区域无法确认",
                "responsible": DEVICE_TEAM,
            }]
        else:
            entry["state"] = "not_signed"
            entry["unconfirmed"] = [{
                "scope": gateway,
                "reason": f"候选版本 {candidate} 没有签收回执，不确定范围留待设备团队",
                "responsible": DEVICE_TEAM,
            }]
        for row in rows:
            # 核实基线由 last_verified 单独保留，不作为陈旧执行回执处理
            if row.get("verified") is not None:
                continue
            if row.get("revision") and row["revision"] != candidate:
                stale.append({
                    "gateway": gateway,
                    "receipt": row["id"],
                    "revision": row["revision"],
                    "received": row.get("received"),
                    "note": (f"旧版本 {row['revision']} 回执不能抵消候选 {candidate} "
                            "上发现的配置偏差"),
                })
        baseline = last_verified(rows).get(gateway)
        if baseline is not None:
            entry["baseline"] = baseline
        observed = [row for row in rows if "observed" in row]
        if observed:
            latest = max(observed, key=lambda row: row["observed"])
            entry["last_observed"] = {
                "revision": latest["revision"],
                "at": latest["observed"],
                "receipt": latest["id"],
            }
        per_gateway[gateway] = entry
    return {
        "at": at,
        "candidate": candidate,
        "gateways": per_gateway,
        "stale_receipts": stale,
        "unconfirmed_gateways": [
            gateway for gateway, entry in per_gateway.items()
            if entry["state"] != "confirmed"
        ],
    }


# ---------------------------------------------------------------- 基线与回退
def _gateway_zones(gateway, policy):
    object_map = build_object_map(policy)
    zones = {
        member for members in object_map.get(gateway, {}).values()
        for member in members
    }
    for row in expected_rows(policy):
        for gw, zone, _service, _want in row["records"]:
            if gw == gateway:
                zones.add(zone)
    return zones


def rollback_check(sources, gateway, at):
    """回退到上次核实基线前，必须按当前约束重新通过核对。"""
    receipts = sources["receipts"]
    entitlements = sources["entitlements"]
    policy = sources["policy"]
    baseline = last_verified(receipts).get(gateway)
    if baseline is None:
        return {
            "gateway": gateway,
            "verdict": "unconfirmed",
            "reason": "没有经过核实的安全配置基线，无法提出回退选项",
        }
    zones = _gateway_zones(gateway, policy)
    conditions, blocked = [], False
    for entitlement in entitlements:
        if entitlement["origin_zone"] not in zones:
            continue
        then = entitlement_window(entitlement, baseline["at"])
        now = entitlement_window(entitlement, at)
        conditions.append({
            "entitlement": entitlement["id"],
            "at_verification": then,
            "now": now,
        })
        if then == "active" and now != "active":
            blocked = True
    return {
        "gateway": gateway,
        "baseline": baseline,
        "at": at,
        "conditions": conditions,
        "verdict": "blocked" if blocked else "usable",
        "note": ("基线条件已变化，回退选项须重新通过当前约束审批"
                 if blocked else "回退选项已按当前约束重新核对通过"),
    }


# ---------------------------------------------------------------- 值班台查询
def lookup_approval(sources, at, owner=None, zone=None, service=None):
    entitlements = sources["entitlements"]
    rows = []
    for row in entitlements:
        if owner is not None and row["owner"] != owner:
            continue
        if zone is not None and row["origin_zone"] != zone:
            continue
        if service is not None and row["service"] != service:
            continue
        rows.append({
            "id": row["id"],
            "owner": row["owner"],
            "origin_zone": row["origin_zone"],
            "service": row["service"],
            "direction": row["direction"],
            "window": entitlement_window(row, at),
        })
    return {"kind": "approval", "at": at, "records": rows}


def lookup_expected(sources, gateway=None):
    rows = []
    for row in expected_rows(sources["policy"]):
        for gw, zone, service, wanted in row["records"]:
            if gateway is not None and gw != gateway:
                continue
            rows.append({
                "gateway": gw, "zone": zone, "service": service,
                "expected": wanted,
            })
    return {"kind": "expected", "records": rows}


def lookup_effective(sources, at=None):
    receipts = sources["receipts"]
    reconciliation = reconcile_receipts(sources, at=at)
    records = []
    for gateway, entry in reconciliation["gateways"].items():
        records.append({
            "gateway": gateway,
            "state": entry["state"],
            "baseline": entry.get("baseline"),
            "last_observed": entry.get("last_observed"),
            "confirmed_effective": entry["state"] == "confirmed",
            "unconfirmed": entry.get("unconfirmed", []),
        })
    return {
        "kind": "effective",
        "at": reconciliation["at"],
        "candidate": reconciliation["candidate"],
        "records": records,
    }


# ---------------------------------------------------------------- 入口
def _add_common(parser):
    parser.add_argument("--records", type=Path,
                        default=Path(__file__).with_name("records"))
    parser.add_argument("--at", type=int, default=None,
                        help="审查时刻，缺省取回执中的最晚时间")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    common = argparse.ArgumentParser(add_help=False)
    _add_common(common)
    sub = parser.add_subparsers(dest="task", required=True)

    sub.add_parser("review", parents=[common],
                   help="核对变更授权、对象对应与预期结果")
    sub.add_parser("receipts", parents=[common], help="按网关核销执行回执")

    rollback = sub.add_parser("rollback", parents=[common],
                              help="基线回退选项的当前约束复核")
    rollback.add_argument("--gateway", required=True)

    lookup = sub.add_parser("lookup", parents=[common], help="值班台分项查询")
    lookup.add_argument("--kind", choices=["approval", "expected", "effective"],
                        required=True)
    lookup.add_argument("--owner")
    lookup.add_argument("--zone")
    lookup.add_argument("--service")
    lookup.add_argument("--gateway")

    args = parser.parse_args()
    sources = load_sources(args.records)
    at = args.at if args.at is not None else receipt_clock(sources["receipts"])

    if args.task == "review":
        result = review_change(sources, at)
    elif args.task == "receipts":
        result = reconcile_receipts(sources, at=at)
    elif args.task == "rollback":
        result = rollback_check(sources, args.gateway, at)
    elif args.task == "lookup":
        if args.kind == "approval":
            result = lookup_approval(sources, at, owner=args.owner,
                                     zone=args.zone, service=args.service)
        elif args.kind == "expected":
            result = lookup_expected(sources, gateway=args.gateway)
        else:
            result = lookup_effective(sources, at=at)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
