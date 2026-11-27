"""审查服务测试：最小权限、对象对应、回执核销与回退约束。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from records_view import load_sources
from review_service import (
    DEVICE_TEAM,
    SECURITY_OFFICER,
    build_object_map,
    compare_named_objects,
    entitlement_window,
    evaluate_expected,
    is_revocation,
    last_verified,
    lookup_approval,
    lookup_effective,
    lookup_expected,
    receipt_clock,
    reconcile_receipts,
    review_change,
    review_target,
    rollback_check,
)

ROOT = Path(__file__).parent


class ReviewServiceTests(unittest.TestCase):
    def setUp(self):
        self.sources = load_sources(ROOT / "records")

    # -- 审批时段 ---------------------------------------------------------
    def test_entitlement_windows(self):
        keep_b, revoke_a, data_ok = self.sources["entitlements"]
        self.assertTrue(is_revocation(revoke_a))
        self.assertFalse(is_revocation(keep_b))
        self.assertEqual(entitlement_window(revoke_a, 30), "pending")
        self.assertEqual(entitlement_window(revoke_a, 60), "active")
        self.assertEqual(entitlement_window(keep_b, 60), "active")
        self.assertEqual(entitlement_window(keep_b, 95), "expired")
        self.assertEqual(entitlement_window(data_ok, 60), "active")

    # -- 同名对象对应 -----------------------------------------------------
    def test_same_named_object_differs_across_gateways(self):
        comparison = compare_named_objects(self.sources["policy"])
        support = next(row for row in comparison if row["object"] == "support")
        self.assertTrue(support["divergent"])
        self.assertEqual(support["gateways"]["gw-1"],
                         ["a-support", "b-support"])
        self.assertEqual(support["gateways"]["gw-2"], ["b-support"])

    def test_object_map_is_per_gateway(self):
        mapping = build_object_map(self.sources["policy"])
        self.assertIn("a-support", mapping["gw-1"]["support"])
        self.assertNotIn("a-support", mapping["gw-2"]["support"])

    # -- 最小权限 ---------------------------------------------------------
    def test_deny_on_shared_object_over_reaches_neighbor_county(self):
        review = review_change(self.sources, at=60)
        target = review["changes"][0]
        by_zone = {item["zone"]: item for item in target["member_findings"]}
        self.assertEqual(by_zone["a-support"]["decision"], "authorized")
        self.assertEqual(by_zone["b-support"]["decision"], "over_reach")
        self.assertEqual(by_zone["b-support"]["owner"], "county-b")
        self.assertEqual(target["narrow_to"], ["a-support"])
        self.assertIn("连带收回", by_zone["b-support"]["reason"])

    def test_change_must_be_narrowed_not_revoke_neighbor_permission(self):
        review = review_change(self.sources, at=60)
        target = review["changes"][0]
        self.assertTrue(any(
            item["decision"] == "over_reach" and item["zone"] == "b-support"
            for item in target["member_findings"]
        ))
        # 邻县有效许可在批准时段内，不得随同本县吊销一起收回
        self.assertNotIn("b-support", target["narrow_to"])

    def test_pending_revocation_leaves_unconfirmed_scope(self):
        review = review_change(self.sources, at=10)
        target = review["changes"][0]
        unconfirmed = {item["zone"] for item in target["unconfirmed"]}
        self.assertIn("a-support", unconfirmed)
        by_zone = {item["zone"]: item for item in target["member_findings"]}
        self.assertEqual(by_zone["a-support"]["decision"], "pending")
        self.assertEqual(by_zone["a-support"]["window"], "pending")

    def test_missing_object_definition_is_unconfirmed(self):
        object_map = build_object_map(self.sources["policy"])
        finding = review_target(
            {"gateway": "gw-x", "scope": "ghost", "action": "deny", "position": 1},
            object_map, self.sources["entitlements"], at=60,
        )
        self.assertEqual(len(finding["member_findings"]), 0)
        self.assertEqual(finding["unconfirmed"][0]["responsible"],
                         SECURITY_OFFICER)

    def test_zone_without_entitlement_is_unconfirmed(self):
        object_map = {"gw-1": {"support": ["a-support", "orphan-zone"]}}
        finding = review_target(
            {"gateway": "gw-1", "scope": "support", "action": "deny",
             "position": 1},
            object_map, self.sources["entitlements"], at=60,
        )
        orphan = next(item for item in finding["unconfirmed"]
                      if item.get("zone") == "orphan-zone")
        self.assertIn("归属无法确认", orphan["reason"])

    # -- 规则顺序与预期结果 ----------------------------------------------
    def test_rule_order_notes_record_position_impact(self):
        review = review_change(self.sources, at=60)
        note = review["rule_order"][0]
        self.assertEqual(note["position"], 5)
        self.assertIn("前置规则", note["order_impact"])

    def test_expected_checks_separate_allow_deny_use_cases(self):
        checks = evaluate_expected(self.sources["policy"],
                                   self.sources["entitlements"], at=60)
        keyed = {(c["gateway"], c["zone"]): c for c in checks}
        self.assertEqual(keyed[("gw-1", "a-support")]["outcome"], "consistent")
        self.assertEqual(keyed[("gw-1", "b-support")]["outcome"], "conflict")
        self.assertEqual(keyed[("gw-2", "sensors")]["outcome"], "not_affected")

    def test_pending_window_makes_expectation_unconfirmed(self):
        checks = evaluate_expected(self.sources["policy"],
                                   self.sources["entitlements"], at=10)
        a_support = next(c for c in checks
                         if c["gateway"] == "gw-1" and c["zone"] == "a-support")
        self.assertEqual(a_support["outcome"], "unconfirmed")

    # -- 回执核销 ---------------------------------------------------------
    def test_one_gateway_signed_other_not_keeps_unconfirmed_with_team(self):
        result = reconcile_receipts(self.sources)
        gateways = result["gateways"]
        self.assertEqual(gateways["gw-1"]["state"], "signed_unapplied")
        self.assertEqual(gateways["gw-2"]["state"], "not_signed")
        self.assertEqual(
            gateways["gw-1"]["unconfirmed"][0]["responsible"], DEVICE_TEAM)
        self.assertEqual(
            gateways["gw-2"]["unconfirmed"][0]["responsible"], DEVICE_TEAM)
        self.assertEqual(result["unconfirmed_gateways"], ["gw-1", "gw-2"])

    def test_stale_revision_receipt_cannot_clear_new_deviation(self):
        result = reconcile_receipts(self.sources)
        stale = result["stale_receipts"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["gateway"], "gw-2")
        self.assertEqual(stale[0]["revision"], "r2")
        self.assertIn("不能抵消", stale[0]["note"])
        # 即便 r2 已核实，gw-2 对候选 r3 仍保持未签收
        self.assertEqual(result["gateways"]["gw-2"]["state"], "not_signed")

    def test_receipt_clock_uses_latest_recorded_time(self):
        self.assertEqual(receipt_clock(self.sources["receipts"]), 54)

    def test_last_verified_baseline_is_retained(self):
        baseline = last_verified(self.sources["receipts"])
        self.assertEqual(baseline["gw-2"],
                         {"revision": "r2", "at": 40, "receipt": "expect-r2"})
        self.assertNotIn("gw-1", baseline)

    # -- 回退约束 ---------------------------------------------------------
    def test_rollback_blocked_when_conditions_expire(self):
        result = rollback_check(self.sources, "gw-2", at=130)
        self.assertEqual(result["verdict"], "blocked")
        data = next(item for item in result["conditions"]
                    if item["entitlement"] == "data-ok")
        self.assertEqual(data["at_verification"], "active")
        self.assertEqual(data["now"], "expired")

    def test_rollback_usable_while_constraints_hold(self):
        result = rollback_check(self.sources, "gw-2", at=54)
        self.assertEqual(result["verdict"], "usable")
        self.assertEqual(result["baseline"]["revision"], "r2")

    def test_rollback_without_baseline_is_unconfirmed(self):
        result = rollback_check(self.sources, "gw-1", at=60)
        self.assertEqual(result["verdict"], "unconfirmed")

    # -- 值班台分项查询 ---------------------------------------------------
    def test_duty_lookups_are_separate(self):
        approvals = lookup_approval(self.sources, at=60, owner="county-b")
        self.assertEqual([row["id"] for row in approvals["records"]], ["keep-b"])
        expected = lookup_expected(self.sources, gateway="gw-1")
        self.assertEqual({row["zone"] for row in expected["records"]},
                         {"a-support", "b-support"})
        effective = lookup_effective(self.sources)
        self.assertEqual(effective["kind"], "effective")
        self.assertFalse(any(row["confirmed_effective"]
                             for row in effective["records"]))

    def test_lookup_approval_filter_by_service(self):
        result = lookup_approval(self.sources, at=60, service="upload")
        self.assertEqual([row["id"] for row in result["records"]], ["data-ok"])

    # -- 资料不齐全 -------------------------------------------------------
    def test_unknown_gateway_in_expectation_is_unconfirmed(self):
        policy = list(self.sources["policy"]) + [{
            "id": "expected-x",
            "records": [["gw-x", "a-support", "maint", "deny"]],
        }]
        sources = {**self.sources, "policy": policy}
        checks = evaluate_expected(policy, self.sources["entitlements"], at=60)
        unknown = next(c for c in checks if c["gateway"] == "gw-x")
        self.assertEqual(unknown["outcome"], "unconfirmed")

    # -- CLI --------------------------------------------------------------
    def test_cli_review_and_receipts(self):
        for task in ("review", "receipts"):
            output = subprocess.run(
                [sys.executable, "-I", str(ROOT / "review_service.py"),
                 task, "--at", "60"],
                capture_output=True, text=True, check=True, cwd=ROOT,
            )
            payload = json.loads(output.stdout)
            self.assertIsInstance(payload, dict)


if __name__ == "__main__":
    unittest.main()
