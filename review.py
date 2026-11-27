"""本地审查服务：许可范围、候选策略、回执与回退的离线核对。

只读取本地合成资料，不连接设备，也不下发任何配置。输出分为审批、预期
结果、实际生效区域、回退条件和需要交回设备团队的范围。所有时间均取自
原始记录字段；缺少时间、来源或许可字段时标为无法确认，而不是推断。
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from records_view import load_sources


KEEP_ACTIONS = {"keep", "allow", "approve", "approved", "grant", "granted"}
REVOKE_ACTIONS = {"revoke", "revoked", "withdraw", "withdrawn", "deny"}
SIGNED_STATES = {"accepted", "acknowledged", "signed", "received", "applied", "verified"}
APPLIED_STATES = {"applied", "verified", "active"}
DEFAULT_TIME_FIELDS = ("observed", "received", "at", "verified_at", "checked_at")
REQUIRED_SOURCES = ("entitlements", "policy", "receipts")
UNCLEAR_OWNERS = {"joint", "shared", "multiple", "unknown", "none", "tbd", "-"}


class ReviewError(ValueError):
    """资料或参数无法用于审查。"""


def _number(value):
    """只接受有限数值时间；其他值由调用方标为无法确认。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value in (float("inf"), float("-inf")):
        return None
    return int(value) if float(value).is_integer() else value


def _owner_is_clear(owner):
    if not isinstance(owner, str) or not owner.strip():
        return False
    lowered = owner.strip().lower()
    if lowered in UNCLEAR_OWNERS:
        return False
    return not bool(re.search(r"[,;/+&]|\band\b", lowered))


def _unique(values):
    return list(dict.fromkeys(values))


def _time_span(row):
    start = _number(row.get("effective"))
    if start is None:
        start = _number(row.get("from"))
    end = _number(row.get("expires"))
    if end is None:
        end = _number(row.get("until"))
    return start, end


def _directive(row):
    """判断记录是保留、撤销还是临时例外。

    合成资料无显式动作时：``effective`` 表示撤销生效时点，``expires`` 表示
    许可截止时点；两者都有即为有明确批准时段的临时例外。显式的
    ``action`` / ``status`` / ``temporary`` 总是优先。
    """
    action = row.get("action", row.get("status", row.get("decision")))
    if isinstance(action, str):
        lowered = action.strip().lower()
        if lowered in REVOKE_ACTIONS:
            return "revoke"
        if lowered in KEEP_ACTIONS:
            return "keep"
    if row.get("revoked") is True:
        return "revoke"
    if row.get("temporary") is True or row.get("kind") in {"exception", "temporary"}:
        return "exception"
    start, end = _time_span(row)
    if start is not None and end is not None:
        return "exception"
    if start is not None:
        return "revoke"
    if end is not None:
        return "keep"
    return "unconfirmed"


def _normalize_members(value):
    if not isinstance(value, list):
        return None
    members = []
    for member in value:
        if not isinstance(member, str) or not member:
            return None
        members.append(member)
    return _unique(members)


class ObjectIndex:
    """按网关记录同名对象的实际成员，并保留更名信息。"""

    def __init__(self, policy_rows):
        self.by_gateway = {}
        self.conflicts = []
        self.renames = []
        self._alias = {}
        for row in policy_rows:
            if "object" not in row or "gateway" not in row:
                continue
            gateway = row.get("gateway")
            name = row.get("object")
            if not isinstance(gateway, str) or not gateway:
                self.conflicts.append({"record": row.get("id"), "reason": "missing_gateway"})
                continue
            if not isinstance(name, str) or not name:
                self.conflicts.append({"record": row.get("id"), "gateway": gateway,
                                       "reason": "missing_object"})
                continue
            members = _normalize_members(row.get("members"))
            if members is None:
                self.conflicts.append({"record": row.get("id"), "gateway": gateway,
                                       "object": name, "reason": "missing_members"})
                continue
            objects = self.by_gateway.setdefault(gateway, {})
            if name in objects:
                if objects[name]["members"] != members:
                    self.conflicts.append({"record": row.get("id"), "gateway": gateway,
                                           "object": name, "reason": "conflicting_members"})
                objects[name]["records"].append(row.get("id"))
                continue
            aliases = row.get("renamed_from", row.get("aliases", []))
            if isinstance(aliases, str):
                aliases = [aliases]
            aliases = [alias for alias in aliases
                       if isinstance(alias, str) and alias and alias != name]
            objects[name] = {"members": members, "aliases": _unique(aliases),
                             "records": [row.get("id")]}
            for alias in aliases:
                self._alias[(gateway, alias)] = name
                self.renames.append({"gateway": gateway, "object": name, "alias": alias})

    def gateways(self):
        return sorted(self.by_gateway)

    def resolve(self, gateway, scope):
        """返回 {status, members, object, renamed_from}。

        scope 可以是对象名、对象旧名；若名称不存在但恰好是某个对象的成员，
        则按单个来源区解释。无法对应时返回 unconfirmed，而不是猜测。
        """
        objects = self.by_gateway.get(gateway)
        if objects is None:
            return {"status": "unconfirmed", "reason": "gateway_not_in_policy",
                    "members": [], "object": scope, "renamed_from": None}
        if scope in objects:
            return {"status": "confirmed", "members": list(objects[scope]["members"]),
                    "object": scope, "renamed_from": None}
        canonical = self._alias.get((gateway, scope))
        if canonical is not None:
            return {"status": "confirmed", "members": list(objects[canonical]["members"]),
                    "object": canonical, "renamed_from": scope}
        for name, entry in objects.items():
            if scope in entry["members"]:
                return {"status": "confirmed", "members": [scope],
                        "object": None, "renamed_from": None}
        return {"status": "unconfirmed", "reason": "scope_not_found",
                "members": [], "object": scope, "renamed_from": None}

    def divergence(self):
        """同名对象跨网关的成员差异。"""
        names = sorted({name for objects in self.by_gateway.values() for name in objects})
        result = []
        for name in names:
            per_gateway = {gateway: details[name]["members"]
                           for gateway, details in self.by_gateway.items() if name in details}
            if len({tuple(members) for members in per_gateway.values()}) > 1:
                result.append({"object": name, "members_by_gateway": per_gateway})
        return result


def _entitlement_scope(entitlement, index):
    """把许可的批准范围落到网关和实际成员上。"""
    origin = entitlement.get("origin_zone")
    gateway = entitlement.get("gateway")
    object_name = entitlement.get("object")
    entries = []
    unknowns = []

    if gateway is not None:
        if not isinstance(gateway, str) or not gateway:
            return [], [{"reason": "missing_gateway"}]
        gateways = [gateway]
    else:
        gateways = index.gateways()

    for candidate in gateways:
        if object_name is not None:
            if not isinstance(object_name, str) or not object_name:
                unknowns.append({"gateway": candidate, "reason": "missing_object"})
                continue
            resolved = index.resolve(candidate, object_name)
            if resolved["status"] != "confirmed":
                unknowns.append({"gateway": candidate, "object": object_name,
                                 "reason": resolved.get("reason", "object_unconfirmed")})
            else:
                entries.append({"gateway": candidate, "object": resolved["object"],
                                "members": resolved["members"],
                                "renamed_from": resolved["renamed_from"]})
            continue

        matched = False
        for name, details in index.by_gateway.get(candidate, {}).items():
            if origin in details["members"]:
                entries.append({"gateway": candidate, "object": name,
                                "members": list(details["members"]),
                                "renamed_from": None})
                matched = True
        if not matched and origin:
            # 来源区不是该网关任何对象的成员；这里不是可核对的范围。
            continue

    if not entries:
        unknowns.append({"gateway": gateway, "object": object_name,
                         "reason": "no_object_mapping" if object_name is None
                         else "object_not_found"})
    return entries, unknowns


def review_entitlement(entitlement, index, at, time_known=True):
    missing = [field for field in ("owner", "origin_zone", "service", "direction")
               if not isinstance(entitlement.get(field), str)
               or not entitlement.get(field)]
    directive = _directive(entitlement)
    start, end = _time_span(entitlement)
    scope, unknown_scope = _entitlement_scope(entitlement, index)
    reasons = []
    status = "valid"

    if missing:
        status = "unconfirmed"
        reasons.append({"code": "missing_field", "fields": missing})
    if directive == "unconfirmed":
        status = "unconfirmed"
        reasons.append({"code": "no_approved_time"})

    if directive == "exception":
        if start is None or end is None:
            status = "unconfirmed"
            reasons.append({"code": "incomplete_exception_window"})
        elif not time_known:
            status = "unconfirmed"
            reasons.append({"code": "review_time_unknown"})
        elif at < start:
            status = "not_yet_effective"
            reasons.append({"code": "before_window", "start": start})
        elif at > end:
            status = "expired"
            reasons.append({"code": "after_window", "end": end})
    elif directive == "revoke":
        if start is not None and time_known and at < start:
            status = "not_yet_effective"
            reasons.append({"code": "before_effect", "start": start})
    elif directive == "keep":
        if end is not None and time_known and at > end:
            status = "expired"
            reasons.append({"code": "after_expiry", "end": end})

    if not _owner_is_clear(entitlement.get("owner")):
        reasons.append({"code": "owner_unclear", "owner": entitlement.get("owner")})
        if status == "valid":
            status = "unconfirmed"

    renamed = [entry for entry in scope if entry.get("renamed_from")]
    if renamed:
        reasons.append({"code": "renamed_object_scope", "entries": renamed})
    if unknown_scope:
        if status == "valid":
            status = "unconfirmed"
        reasons.append({"code": "scope_unconfirmed", "details": unknown_scope})
    if index.conflicts:
        reasons.append({"code": "policy_conflicts", "count": len(index.conflicts)})

    in_force = status in {"valid", "not_yet_effective"}
    return {
        "id": entitlement.get("id"),
        "directive": directive,
        "status": status,
        "in_force": in_force,
        "owner": entitlement.get("owner"),
        "owner_clear": _owner_is_clear(entitlement.get("owner")),
        "direction": entitlement.get("direction"),
        "origin_zone": entitlement.get("origin_zone"),
        "service": entitlement.get("service"),
        "window": {"start": start, "end": end},
        "scope": scope,
        "unknown_scope": unknown_scope,
        "renamed_scope": renamed,
        "reasons": reasons,
    }


def _rule_origins(rule, index):
    gateway = rule.get("gateway")
    scope = rule.get("scope")
    if not isinstance(gateway, str) or not gateway:
        return {"status": "unconfirmed", "reason": "missing_gateway", "members": []}
    if not isinstance(scope, str) or not scope:
        return {"status": "unconfirmed", "reason": "missing_scope", "members": []}
    return index.resolve(gateway, scope)


def _rule_sort_key(rule):
    position = rule["position"]
    return (position is None, position if position is not None else 0, rule["_order"])


def _compile_rules(candidate, index):
    """编译候选策略中的基础规则与本批变更。"""
    issues = []
    rules = []
    base = candidate.get("base", [])
    if base is None:
        base = []
    if not isinstance(base, list):
        issues.append({"code": "invalid_base"})
        base = []
    changes = candidate.get("changes")

    order = 0
    groups = (("base", base), ("change", changes if isinstance(changes, list) else []))
    for source, rows in groups:
        for offset, row in enumerate(rows):
            if not isinstance(row, dict):
                issues.append({"code": "invalid_rule"})
                continue
            action = row.get("action")
            if not isinstance(action, str) or action.lower() not in {"allow", "deny"}:
                issues.append({"code": "invalid_action", "record": row.get("id")})
                continue
            resolved = _rule_origins(row, index)
            position = _number(row.get("position"))
            if position is None:
                issues.append({"code": "missing_position", "record": row.get("id")})
            label = row.get("id")
            if not isinstance(label, str) or not label:
                label = f"{candidate.get('id', 'candidate')}#{source}:{offset}"
            rules.append({
                "record": label,
                "source": source,
                "gateway": row.get("gateway"),
                "scope": row.get("scope"),
                "object": resolved.get("object"),
                "renamed_from": resolved.get("renamed_from"),
                "origins": resolved.get("members", []),
                "scope_status": resolved["status"],
                "scope_reason": resolved.get("reason"),
                "action": action.lower(),
                "position": position,
                "service": row.get("service"),
                "direction": row.get("direction"),
                "_order": order,
            })
            order += 1
    if changes is None:
        issues.append({"code": "missing_changes"})
    elif not isinstance(changes, list) or not changes:
        issues.append({"code": "empty_changes"})
    rules.sort(key=_rule_sort_key)
    return rules, issues


def _match_rule(rule, gateway, origin, service, direction):
    """返回 yes / no / unconfirmed。"""
    if rule["gateway"] != gateway:
        return "no"
    if rule["scope_status"] != "confirmed":
        return "unconfirmed"
    if rule["service"] is not None and rule["service"] != service:
        return "no"
    if rule["direction"] is not None:
        if direction is None:
            return "unconfirmed"
        if rule["direction"] != direction:
            return "no"
    return "yes" if origin in rule["origins"] else "no"


def evaluate_case(rules, default, gateway, origin, service, direction=None):
    """返回 (result, trace, note)。result 为 None 表示无法确认或候选未涉及。"""
    trace = []
    unknown = False
    for rule in rules:
        matched = _match_rule(rule, gateway, origin, service, direction)
        if matched == "yes":
            trace.append({"rule": rule["record"], "object": rule["object"],
                          "position": rule["position"], "action": rule["action"]})
            return rule["action"], trace, {"code": "rule"}
        if matched == "unconfirmed":
            unknown = True
            trace.append({"rule": rule["record"], "status": "unconfirmed"})
        else:
            trace.append({"rule": rule["record"], "status": "no_match"})
    if unknown:
        return None, trace, {"code": "scope_unconfirmed"}
    if default is None:
        return None, trace, {"code": "no_applicable_rule"}
    return default, trace, {"code": "default", "value": default}


def _order_effects(rules):
    effects = []
    by_gateway = {}
    for rule in rules:
        by_gateway.setdefault(rule["gateway"], []).append(rule)
    for gateway, rows in by_gateway.items():
        rows = sorted(rows, key=_rule_sort_key)
        for position, earlier in enumerate(rows):
            for later in rows[position + 1:]:
                if (earlier["position"] is not None
                        and earlier["position"] == later["position"]):
                    effects.append({"code": "same_position", "gateway": gateway,
                                    "rules": [earlier["record"], later["record"]],
                                    "position": earlier["position"]})
                if earlier["scope_status"] != "confirmed" or later["scope_status"] != "confirmed":
                    continue
                if (earlier["service"] is not None and later["service"] is not None
                        and earlier["service"] != later["service"]):
                    continue
                if (earlier["direction"] is not None and later["direction"] is not None
                        and earlier["direction"] != later["direction"]):
                    continue
                if not set(later["origins"]).issubset(set(earlier["origins"])):
                    continue
                effect = "redundant_rule" if earlier["action"] == later["action"] \
                    else "shadowed_rule"
                effects.append({"code": effect, "gateway": gateway,
                                "earlier": earlier["record"], "later": later["record"],
                                "position": later["position"]})
    return effects


def _expected_cases(policy_rows, candidate_id):
    """挑选与候选版本关联的预期用例。"""
    versions = [row for row in policy_rows
                if isinstance(row.get("changes"), list) and row.get("candidate")]
    selected = []
    issues = []
    for row in policy_rows:
        if not isinstance(row.get("records"), list):
            continue
        linked = row.get("candidate")
        if linked is None:
            if len(versions) == 1:
                linked = versions[0].get("candidate")
            else:
                issues.append({"code": "candidate_link_missing", "record": row.get("id")})
                linked = None
        if linked == candidate_id:
            selected.append(row)
    if not selected:
        issues.append({"code": "no_expected_cases"})
    return selected, issues


def _case_tuple(case):
    if isinstance(case, dict):
        return (case.get("gateway"), case.get("origin_zone", case.get("origin")),
                case.get("service"), case.get("action"),
                case.get("direction"))
    if isinstance(case, list) and 4 <= len(case) <= 5:
        return (case[0], case[1], case[2], case[3],
                case[4] if len(case) == 5 else None)
    return (None, None, None, None, None)


def _review_expected(expected_rows, rules, default, default_declared):
    cases = []
    summary = {"match": 0, "mismatch": 0, "not_affected": 0, "unconfirmed": 0}
    for row in expected_rows:
        for raw in row.get("records", []):
            gateway, origin, service, expected, direction = _case_tuple(raw)
            problems = []
            if not all(isinstance(value, str) and value
                       for value in (gateway, origin, service)):
                problems.append("missing_case_field")
            if not isinstance(expected, str) or expected.lower() not in {"allow", "deny"}:
                problems.append("invalid_expected_action")
            if problems:
                result, trace, note = None, [], {"code": "invalid_case"}
                status = "unconfirmed"
            else:
                result, trace, note = evaluate_case(
                    rules, default, gateway, origin, service, direction)
                if note["code"] == "no_applicable_rule":
                    # 候选中没有规则涉及这条路径，因此本批变更不改变它；
                    # 但也不能据此声称已核对出 allow。
                    status = "not_affected"
                elif result is None:
                    status = "unconfirmed"
                elif result == expected.lower():
                    status = "match"
                else:
                    status = "mismatch"
            summary[status] += 1
            cases.append({
                "gateway": gateway, "origin_zone": origin, "service": service,
                "direction": direction, "expected": expected.lower()
                if isinstance(expected, str) else expected,
                "result": result, "status": status, "trace": trace, "note": note,
                "default_declared": default_declared,
                "problems": problems, "record": row.get("id"),
            })
    return cases, summary


def _by_action(cases):
    grouped = {"allow": {"match": 0, "mismatch": 0, "not_affected": 0,
                         "unconfirmed": 0},
               "deny": {"match": 0, "mismatch": 0, "not_affected": 0,
                        "unconfirmed": 0}}
    for case in cases:
        if case["expected"] in grouped:
            grouped[case["expected"]][case["status"]] += 1
    return grouped


def _shared_impact(change, index, entitlement_reviews):
    """找出会被一次变更连带影响的其他所有者许可。"""
    gateway = change.get("gateway")
    resolved = _rule_origins(change, index)
    if resolved["status"] != "confirmed":
        return {"status": "unconfirmed", "reason": resolved.get("reason"),
                "origins": [], "affected": [], "must_keep": [], "narrow_to": []}
    affected = [
        {"id": review["id"], "origin": review["origin_zone"], "owner": review["owner"],
         "status": review["status"], "directive": review["directive"],
         "service": review["service"], "direction": review["direction"]}
        for review in entitlement_reviews
        if review["origin_zone"] in resolved["members"]
        and any(entry["gateway"] == gateway for entry in review["scope"])
    ]
    must_keep = [item for item in affected
                 if item["directive"] in {"keep", "exception"}
                 and item["status"] == "valid"]
    removable = [item for item in affected
                 if item["directive"] == "revoke" and item["status"] == "valid"]
    narrow_to = _unique(item["origin"] for item in removable)
    return {
        "status": "shared" if len({item["origin"] for item in affected}) > 1 else "single",
        "origins": _unique(item["origin"] for item in affected),
        "affected": affected,
        "must_keep": must_keep,
        "narrow_to": narrow_to,
    }


def _change_dimensions(change):
    return {
        "service": change.get("service"),
        "direction": change.get("direction"),
        "owner": change.get("owner"),
        "missing": [field for field in ("service", "direction")
                    if not isinstance(change.get(field), str) or not change.get(field)],
    }


def _normalize_receipt_state(value):
    return value.strip().lower() if isinstance(value, str) else None


def _receipt_times(row):
    values = [_number(row.get(key))
              for key in ("applied", "verified_at", "at", "received", "observed")]
    return [value for value in values if value is not None]


def _receipts_review(receipt_rows, candidate, gateways, at, drift):
    by_gateway = {}
    for gateway in gateways:
        target = [row for row in receipt_rows
                  if row.get("gateway") == gateway
                  and row.get("revision") == candidate]
        others = [row for row in receipt_rows
                  if row.get("gateway") == gateway
                  and row.get("revision") != candidate]
        signed = any(_normalize_receipt_state(row.get("state")) in SIGNED_STATES
                     or row.get("applied") not in (None, False)
                     or row.get("verified") is True for row in target)
        applied = any(_normalize_receipt_state(row.get("state")) in APPLIED_STATES
                      or row.get("applied") not in (None, False)
                      or row.get("verified") is True for row in target)
        target_times = [time for row in target for time in _receipt_times(row)]
        late_marker = max(target_times) if target_times else at
        stale = []
        for row in others:
            received = _number(row.get("received", row.get("at")))
            observed = _number(row.get("observed"))
            stale.append({
                "record": row.get("id"), "revision": row.get("revision"),
                "received": received, "observed": observed,
                "late": received is not None and received >= late_marker,
                "confirms_candidate": False,
            })
        observed_revisions = _unique(
            row.get("revision") for row in others
            if _number(row.get("observed")) is not None
            or _normalize_receipt_state(row.get("state")) is not None)
        if applied:
            reason = "applied"
        elif not target:
            reason = "no_target_receipt"
        elif signed:
            reason = "signed_but_not_applied"
        else:
            reason = "not_signed"
        by_gateway[gateway] = {
            "gateway": gateway,
            "signed": signed,
            "applied": applied,
            "target_receipts": [row.get("id") for row in target],
            "observed_other_revisions": observed_revisions,
            "actual_revision": candidate if applied else (
                observed_revisions[-1] if observed_revisions else None),
            "uncertain": not applied,
            "reason": reason,
            "stale_receipts": stale,
        }
    uncertain = [gateway for gateway, state in by_gateway.items() if state["uncertain"]]
    stale_rows = [dict(item, gateway=gateway)
                  for gateway, state in by_gateway.items()
                  for item in state["stale_receipts"]]
    return {
        "by_gateway": by_gateway,
        "uncertain_gateways": uncertain,
        "stale_receipts": stale_rows,
        "candidate_mismatches": list(drift),
        "drift_note": "旧版本回执只证明旧配置被观察到，不能清除本次候选策略发现",
    }


def _last_verified(receipt_row):
    return receipt_row.get("verified") is True or \
        _normalize_receipt_state(receipt_row.get("state")) == "verified"


def _rollback_review(receipt_rows, index, entitlement_reviews, at, candidate,
                     expected_rows, time_known):
    verified = [row for row in receipt_rows if _last_verified(row)]
    result = []
    for gateway in index.gateways():
        rows = [row for row in verified if row.get("gateway") == gateway]
        if not rows:
            result.append({"gateway": gateway, "status": "unavailable",
                           "reason": "no_verified_snapshot"})
            continue
        rows.sort(key=lambda row: (
            _number(row.get("at", row.get("received", -1))) or -1,
            str(row.get("id") or "")))
        row = rows[-1]
        revision = row.get("revision")
        if revision == candidate:
            result.append({"gateway": gateway, "status": "not_needed",
                           "revision": revision,
                           "verified_at": _number(row.get("at", row.get("received"))),
                           "conditions": []})
            continue
        conditions = []
        current = {name: details["members"]
                   for name, details in index.by_gateway.get(gateway, {}).items()}
        origins = _unique(member for members in current.values() for member in members)
        active_revocations = [
            review for review in entitlement_reviews
            if review["origin_zone"] in origins
            and review["directive"] == "revoke"
            and review["status"] == "valid"
            and any(entry["gateway"] == gateway for entry in review["scope"])
        ]
        if active_revocations:
            conditions.append({
                "code": "restores_revoked_permission", "status": "failed",
                "origins": _unique(item["origin_zone"] for item in active_revocations),
            })
        else:
            conditions.append({"code": "restores_revoked_permission", "status": "pass"})

        kept = [review for review in entitlement_reviews
                if review["origin_zone"] in origins
                and review["directive"] in {"keep", "exception"}
                and review["status"] == "valid"]
        if not kept:
            conditions.append({"code": "approved_window", "status": "unconfirmed",
                               "reason": "no_active_keep_record"})
        elif not time_known:
            conditions.append({"code": "approved_window", "status": "unconfirmed",
                               "reason": "review_time_unknown"})
        else:
            ends = [review["window"]["end"] for review in kept
                    if review["window"]["end"] is not None]
            conditions.append({
                "code": "approved_window",
                "status": "pass" if not ends or at <= min(ends) else "failed",
                "valid_until": min(ends) if ends else None,
            })

        snapshot = row.get("objects", row.get("object_map"))
        if snapshot is None:
            conditions.append({"code": "object_mapping_unchanged",
                               "status": "unconfirmed", "reason": "snapshot_absent",
                               "current": current})
        else:
            conditions.append({
                "code": "object_mapping_unchanged",
                "status": "pass" if snapshot == current else "failed",
            })

        rollback_rules = row.get("rules")
        if not isinstance(rollback_rules, list):
            conditions.append({"code": "expected_cases_pass", "status": "unconfirmed",
                               "reason": "no_rule_snapshot"})
        else:
            compiled, issues = _compile_rules(
                {"id": row.get("id"), "changes": [], "base": rollback_rules}, index)
            issues = [issue for issue in issues
                      if issue["code"] not in {"missing_changes", "empty_changes"}]
            if issues:
                conditions.append({"code": "expected_cases_pass",
                                   "status": "unconfirmed", "issues": issues})
            else:
                cases, summary = _review_expected(expected_rows, compiled,
                                                  None, False)
                failed = summary["mismatch"]
                unknown = summary["unconfirmed"]
                if failed:
                    conditions.append({"code": "expected_cases_pass",
                                       "status": "failed", "mismatch": failed})
                elif unknown:
                    conditions.append({"code": "expected_cases_pass",
                                       "status": "unconfirmed",
                                       "reason": "cases_unconfirmed"})
                else:
                    conditions.append({"code": "expected_cases_pass", "status": "pass"})

        failed = any(item["status"] == "failed" for item in conditions)
        unknown = any(item["status"] == "unconfirmed" for item in conditions)
        status = "rejected" if failed else (
            "needs_confirmation" if unknown else "allowed")
        result.append({
            "gateway": gateway, "revision": revision,
            "verified_at": _number(row.get("at", row.get("received"))),
            "status": status,
            "conditions": conditions,
            "note": "回退保留上次核实配置，但必须在当前审批与对象映射下重新核对",
        })
    return result


def _gateways_for_review(index, changes, expected_rows, receipt_rows=()):
    gateways = list(index.gateways())
    for change in changes:
        if isinstance(change, dict) and isinstance(change.get("gateway"), str):
            gateways.append(change["gateway"])
    for row in expected_rows:
        for raw in row.get("records", []):
            gateway, _, _, _, _ = _case_tuple(raw)
            if isinstance(gateway, str) and gateway:
                gateways.append(gateway)
    for row in receipt_rows:
        if isinstance(row.get("gateway"), str) and row["gateway"]:
            gateways.append(row["gateway"])
    return _unique(gateways)


def _findings(impacts, expected_summary, receipts, rollback, index):
    findings = []
    for impact in impacts:
        if impact["status"] == "unconfirmed":
            findings.append({"code": "scope_unconfirmed",
                             "reason": impact.get("reason")})
        if impact["must_keep"]:
            findings.append({
                "code": "shared_object_overreach",
                "message": "变更会连带收回其他所有者的有效许可",
                "must_keep": [{"id": item["id"], "owner": item["owner"],
                               "origin": item["origin"]}
                              for item in impact["must_keep"]],
                "narrow_to": impact["narrow_to"] or "需要变更人缩小到具体来源区",
            })
    if expected_summary["mismatch"]:
        findings.append({"code": "expected_mismatch",
                         "count": expected_summary["mismatch"]})
    if expected_summary["unconfirmed"]:
        findings.append({"code": "expected_unconfirmed",
                         "count": expected_summary["unconfirmed"]})
    if receipts["uncertain_gateways"]:
        findings.append({"code": "uncertain_scope_handoff",
                         "gateways": receipts["uncertain_gateways"],
                         "owner": "device-team"})
    if receipts["stale_receipts"]:
        findings.append({"code": "stale_receipt_ignored",
                         "records": [item["record"]
                                     for item in receipts["stale_receipts"]],
                         "message": "旧版本回执不能清除本次发现"})
    for item in rollback:
        if item["status"] == "rejected":
            findings.append({"code": "rollback_constraint_failed",
                             "gateway": item["gateway"]})
        elif item["status"] == "needs_confirmation":
            findings.append({"code": "rollback_needs_confirmation",
                             "gateway": item["gateway"]})
    if index.renames:
        findings.append({"code": "object_renamed", "renames": index.renames,
                         "message": "按当前对象名对应的实际成员核对审批范围"})
    return findings


def review_change(change_row, policy_rows, entitlements, receipt_rows, at,
                  index=None, time_known=True, missing_sources=()):
    index = index or ObjectIndex(policy_rows)
    candidate_id = change_row.get("candidate")
    if not isinstance(candidate_id, str) or not candidate_id:
        candidate_id = None
    changes = [row for row in change_row.get("changes", [])
               if isinstance(row, dict)]
    rules, rule_issues = _compile_rules(change_row, index)
    entitlement_reviews = [
        review_entitlement(row, index, at, time_known) for row in entitlements]
    expected_rows, expected_issues = _expected_cases(policy_rows, candidate_id)
    gateways = _gateways_for_review(index, changes, expected_rows, receipt_rows)

    default = change_row.get("default")
    default = default.lower() if isinstance(default, str) and \
        default.lower() in {"allow", "deny"} else None
    cases, case_summary = _review_expected(
        expected_rows, rules, default, default is not None)

    impacts = [{"scope": _rule_origins(change, index),
                "impact": _shared_impact(change, index, entitlement_reviews),
                "dimensions": _change_dimensions(change),
                "approval_ref": change.get("approval", change.get("entitlement"))}
               for change in changes]
    mismatches = [{"record": case["record"],
                   "case": [case["gateway"], case["origin_zone"], case["service"]],
                   "expected": case["expected"], "result": case["result"]}
                  for case in cases if case["status"] == "mismatch"]
    receipts = _receipts_review(receipt_rows, candidate_id, gateways, at, mismatches)
    rollback = _rollback_review(receipt_rows, index, entitlement_reviews, at,
                                candidate_id, expected_rows, time_known)
    findings = _findings([item["impact"] for item in impacts], case_summary,
                         receipts, rollback, index)

    uncertain = []
    if not candidate_id:
        uncertain.append({"code": "candidate_missing"})
    for issue in rule_issues + expected_issues:
        uncertain.append(issue)
    for source in missing_sources:
        uncertain.append({"code": "source_missing", "source": source})
    if not time_known:
        uncertain.append({"code": "review_time_unknown"})
    for item in entitlement_reviews:
        if item["status"] == "unconfirmed":
            uncertain.append({"code": "entitlement_unconfirmed", "id": item["id"]})
    for case in cases:
        if case["status"] == "unconfirmed":
            uncertain.append({"code": "case_unconfirmed", "record": case["record"],
                              "case": [case["gateway"], case["origin_zone"],
                                       case["service"]]})
    for gateway in receipts["uncertain_gateways"]:
        uncertain.append({"code": "gateway_unconfirmed", "gateway": gateway,
                          "owner": "device-team"})
    for item in rollback:
        if item["status"] == "needs_confirmation":
            uncertain.append({"code": "rollback_unconfirmed", "gateway": item["gateway"]})

    needs_narrowing = any(finding["code"] == "shared_object_overreach"
                          for finding in findings)
    if needs_narrowing:
        status = "needs_narrowing"
    elif case_summary["mismatch"]:
        status = "mismatch"
    elif uncertain:
        status = "needs_confirmation"
    else:
        status = "ready"

    actual_effective = [
        {"gateway": state["gateway"], "revision": state["actual_revision"],
         "confirmed": not state["uncertain"], "reason": state["reason"],
         "source": "receipt"}
        for state in receipts["by_gateway"].values()
    ]

    return {
        "change_id": change_row.get("id"),
        "revision": candidate_id,
        "reviewed_at": at if time_known else None,
        "status": status,
        "approvals": {
            "entitlements": entitlement_reviews,
            "by_change": impacts,
            "note": "从方向、来源区、业务、时段和所有者核对；"
                    "共享对象分开看各网关实际成员",
        },
        "policy": {
            "rules": rules,
            "rule_issues": rule_issues,
            "order_effects": _order_effects(rules),
            "object_mapping": {
                gateway: {name: details["members"]
                          for name, details in objects.items()}
                for gateway, objects in index.by_gateway.items()
            },
            "divergence": index.divergence(),
            "renames": index.renames,
            "conflicts": index.conflicts,
            "default": default,
            "default_declared": default is not None,
        },
        "expected": {
            "records": [row.get("id") for row in expected_rows],
            "cases": cases,
            "summary": case_summary,
            "by_expected_action": _by_action(cases),
            "issues": expected_issues,
        },
        "receipts": receipts,
        "actual_effective": actual_effective,
        "rollback": rollback,
        "findings": findings,
        "uncertain": uncertain,
        "handoff": {"review_only": True,
                    "device_team": [
                        {"gateway": gateway,
                         "reason": receipts["by_gateway"][gateway]["reason"],
                         "scope": "保留给设备团队确认"}
                        for gateway in receipts["uncertain_gateways"]],
                    "next_change": None},
    }


def review_all(directory, at=None, change_id=None):
    sources = load_sources(directory)
    missing = [name for name in REQUIRED_SOURCES if name not in sources]
    entitlements = sources.get("entitlements", [])
    policy_rows = sources.get("policy", [])
    receipt_rows = sources.get("receipts", [])
    index = ObjectIndex(policy_rows)

    if at is not None:
        time_known = True
        at = _number(at)
        if at is None:
            raise ReviewError("审查时点无效")
    else:
        observed = [time for row in receipt_rows for time in _receipt_times(row)]
        time_known = bool(observed)
        at = max(observed) if observed else 0

    changes = [row for row in policy_rows
               if isinstance(row.get("changes"), list) and row.get("id")]
    if change_id is not None:
        selected = [row for row in changes if row.get("id") == change_id]
        if not selected:
            raise ReviewError("变更记录不存在")
        changes = selected

    reports = [
        review_change(row, policy_rows, entitlements, receipt_rows, at, index,
                      time_known, missing)
        for row in changes
    ]
    for position, report in enumerate(reports):
        remaining = [row.get("id") for row in changes[position + 1:]]
        report["handoff"]["next_change"] = remaining[0] if remaining else None
        report["handoff"]["can_continue"] = True

    return {
        "reviewed_at": at if time_known else None,
        "time_known": time_known,
        "missing_sources": missing,
        "unconfirmed_sources": [{"source": name, "reason": "source_missing"}
                                for name in missing],
        "changes": reports,
        "next_change": reports[0]["handoff"]["next_change"] if reports else None,
        "review_only": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path,
                        default=Path(__file__).with_name("records"))
    parser.add_argument("--at", type=float, default=None,
                        help="审查时点；缺省取回执中最晚的观察时间")
    parser.add_argument("--change", help="只审查指定变更记录")
    args = parser.parse_args()
    try:
        result = review_all(args.records, args.at, args.change)
    except (ReviewError, ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
