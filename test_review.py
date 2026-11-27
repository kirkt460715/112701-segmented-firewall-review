"""审查服务的定向测试：全部使用合成记录。"""
import json
import tempfile
import unittest
from pathlib import Path

from review import ObjectIndex, ReviewError, review_all, review_entitlement


def write_sources(directory, entitlements=None, policy=None, receipts=None):
    path = Path(directory)
    for name, rows in (("entitlements", entitlements), ("policy", policy),
                       ("receipts", receipts)):
        if rows is None:
            continue
        (path / f"{name}.json").write_text(
            json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return path


ENTITLEMENTS = [
    {"id": "keep-b", "owner": "county-b", "origin_zone": "b-support",
     "service": "maint", "direction": "inbound", "expires": 90},
    {"id": "revoke-a", "owner": "county-a", "origin_zone": "a-support",
     "service": "maint", "direction": "inbound", "effective": 45},
    {"id": "data-ok", "owner": "joint", "origin_zone": "sensors",
     "service": "upload", "direction": "outbound", "expires": 120},
]
POLICY = [
    {"id": "obj-a", "gateway": "gw-1", "object": "support",
     "members": ["a-support", "b-support"]},
    {"id": "obj-b", "gateway": "gw-2", "object": "support",
     "members": ["b-support"]},
    {"id": "rule-review", "candidate": "r3",
     "changes": [{"gateway": "gw-1", "scope": "support", "action": "deny",
                  "position": 5}]},
    {"id": "expected-1", "records": [
        ["gw-1", "b-support", "maint", "allow"],
        ["gw-1", "a-support", "maint", "deny"],
        ["gw-2", "sensors", "upload", "allow"]]},
]
RECEIPTS = [
    {"id": "ack-1", "gateway": "gw-1", "revision": "r3", "state": "accepted",
     "applied": None},
    {"id": "old-2", "gateway": "gw-2", "revision": "r2", "observed": 43,
     "received": 54},
    {"id": "expect-r2", "gateway": "gw-2", "revision": "r2", "verified": True,
     "at": 40},
]


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).with_name("records")
        self.report = review_all(self.directory, at=50)
        self.change = self.report["changes"][0]

    def test_shared_object_is_flagged_for_narrowing(self):
        self.assertEqual(self.change["status"], "needs_narrowing")
        finding = next(item for item in self.change["findings"]
                       if item["code"] == "shared_object_overreach")
        self.assertEqual([item["id"] for item in finding["must_keep"]], ["keep-b"])
        self.assertEqual(finding["narrow_to"], ["a-support"])

    def test_same_object_differs_by_gateway(self):
        divergence = self.change["policy"]["divergence"]
        self.assertEqual(divergence, [{
            "object": "support",
            "members_by_gateway": {"gw-1": ["a-support", "b-support"],
                                   "gw-2": ["b-support"]},
        }])

    def test_expected_cases_split_by_direction(self):
        summary = self.change["expected"]["summary"]
        self.assertEqual(summary["mismatch"], 1)
        self.assertEqual(summary["match"], 1)
        self.assertEqual(summary["not_affected"], 1)
        by_action = self.change["expected"]["by_expected_action"]
        self.assertEqual(by_action["deny"]["match"], 1)
        self.assertEqual(by_action["allow"]["mismatch"], 1)

    def test_one_signed_other_not_leaves_scope_with_device_team(self):
        states = self.change["receipts"]["by_gateway"]
        self.assertTrue(states["gw-1"]["signed"])
        self.assertFalse(states["gw-1"]["applied"])
        self.assertFalse(states["gw-2"]["signed"])
        self.assertEqual(sorted(self.change["receipts"]["uncertain_gateways"]),
                         ["gw-1", "gw-2"])
        handoff = {item["gateway"] for item in self.change["handoff"]["device_team"]}
        self.assertEqual(handoff, {"gw-1", "gw-2"})
        self.assertTrue(self.change["handoff"]["review_only"])

    def test_late_old_receipt_does_not_clear_drift(self):
        stale = self.change["receipts"]["stale_receipts"]
        late = next(item for item in stale if item["record"] == "old-2")
        self.assertTrue(late["late"])
        self.assertFalse(late["confirms_candidate"])
        self.assertEqual(len(self.change["receipts"]["candidate_mismatches"]), 1)

    def test_rollback_keeps_verified_config_but_rechecks_constraints(self):
        rollback = {item["gateway"]: item for item in self.change["rollback"]}
        self.assertEqual(rollback["gw-1"]["status"], "unavailable")
        self.assertEqual(rollback["gw-2"]["status"], "needs_confirmation")
        self.assertEqual(rollback["gw-2"]["revision"], "r2")
        conditions = {item["code"]: item["status"]
                      for item in rollback["gw-2"]["conditions"]}
        self.assertEqual(conditions["restores_revoked_permission"], "pass")
        self.assertEqual(conditions["object_mapping_unchanged"], "unconfirmed")

    def test_owner_unclear_and_scope_missing_are_unconfirmed(self):
        reviews = {item["id"]: item for item in
                   self.change["approvals"]["entitlements"]}
        self.assertEqual(reviews["data-ok"]["status"], "unconfirmed")
        self.assertFalse(reviews["data-ok"]["owner_clear"])
        self.assertTrue(reviews["keep-b"]["in_force"])


class EntitlementWindowTests(unittest.TestCase):
    def setUp(self):
        self.index = ObjectIndex(POLICY)

    def test_exception_only_inside_approved_window(self):
        row = {"id": "temp", "owner": "county-a", "origin_zone": "a-support",
               "service": "maint", "direction": "inbound",
               "effective": 10, "expires": 20}
        self.assertEqual(review_entitlement(row, self.index, 15)["status"], "valid")
        self.assertEqual(review_entitlement(row, self.index, 5)["status"],
                         "not_yet_effective")
        self.assertEqual(review_entitlement(row, self.index, 25)["status"],
                         "expired")

    def test_exception_without_owner_is_not_valid(self):
        row = {"id": "temp", "owner": "shared", "origin_zone": "a-support",
               "service": "maint", "direction": "inbound",
               "effective": 10, "expires": 20}
        review = review_entitlement(row, self.index, 15)
        self.assertEqual(review["status"], "unconfirmed")
        self.assertIn("owner_unclear", [item["code"] for item in review["reasons"]])

    def test_keep_expires(self):
        row = {"id": "keep", "owner": "county-b", "origin_zone": "b-support",
               "service": "maint", "direction": "inbound", "expires": 30}
        self.assertEqual(review_entitlement(row, self.index, 31)["status"], "expired")

    def test_unknown_object_scope_is_unconfirmed(self):
        row = {"id": "keep", "owner": "county-b", "origin_zone": "b-support",
               "service": "maint", "direction": "inbound", "expires": 30,
               "object": "missing-object"}
        review = review_entitlement(row, self.index, 10)
        self.assertEqual(review["status"], "unconfirmed")
        self.assertTrue(review["unknown_scope"])


class RenameTests(unittest.TestCase):
    def test_renamed_object_is_resolved_and_reported(self):
        index = ObjectIndex([
            {"id": "obj", "gateway": "gw-1", "object": "support-new",
             "renamed_from": ["support"], "members": ["a-support"]},
        ])
        resolved = index.resolve("gw-1", "support")
        self.assertEqual(resolved["status"], "confirmed")
        self.assertEqual(resolved["members"], ["a-support"])
        self.assertEqual(resolved["renamed_from"], "support")

        review = review_all(write_sources(
            tempfile.mkdtemp(),
            entitlements=[{"id": "e", "owner": "county-a",
                           "origin_zone": "a-support", "service": "maint",
                           "direction": "inbound", "effective": 10,
                           "object": "support"}],
            policy=[
                {"id": "obj", "gateway": "gw-1", "object": "support-new",
                 "renamed_from": ["support"], "members": ["a-support"]},
                {"id": "change", "candidate": "r9",
                 "changes": [{"gateway": "gw-1", "scope": "support",
                              "action": "deny", "position": 2,
                              "service": "maint", "direction": "inbound"}]},
                {"id": "expected", "records": [
                    ["gw-1", "a-support", "maint", "deny", "inbound"]]},
            ],
            receipts=[{"id": "ack", "gateway": "gw-1", "revision": "r9",
                       "state": "applied", "applied": 60}],
        ), at=60)["changes"][0]
        self.assertIn({"gateway": "gw-1", "object": "support-new",
                       "alias": "support"}, review["policy"]["renames"])
        self.assertEqual(review["expected"]["summary"]["match"], 1)
        self.assertEqual(review["status"], "ready")
        self.assertIn("renamed_object_scope",
                      [item["code"] for item in
                       review["approvals"]["entitlements"][0]["reasons"]])


class SourceAndOrderTests(unittest.TestCase):
    def test_missing_source_marks_unknown_scope(self):
        directory = write_sources(tempfile.mkdtemp(), entitlements=ENTITLEMENTS,
                                  policy=POLICY)
        report = review_all(directory)
        self.assertEqual(report["missing_sources"], ["receipts"])
        self.assertFalse(report["time_known"])
        self.assertIsNone(report["reviewed_at"])
        change = report["changes"][0]
        self.assertEqual(change["status"], "needs_narrowing")
        self.assertIn("source_missing", [item["code"] for item in change["uncertain"]])

    def test_missing_change_id_is_error(self):
        with self.assertRaises(ReviewError):
            review_all(Path(__file__).with_name("records"), change_id="absent")

    def test_order_effects_report_shadowing_and_same_position(self):
        policy = [
            {"id": "obj", "gateway": "gw-1", "object": "support",
             "members": ["a-support"]},
            {"id": "change", "candidate": "rx", "default": "deny",
             "base": [
                 {"id": "allow-all", "gateway": "gw-1", "scope": "support",
                  "action": "allow", "position": 1, "service": "maint",
                  "direction": "inbound"},
                 {"id": "deny-sub", "gateway": "gw-1", "scope": "a-support",
                  "action": "deny", "position": 3, "service": "maint",
                  "direction": "inbound"},
                 {"id": "also-deny", "gateway": "gw-1", "scope": "a-support",
                  "action": "deny", "position": 3, "service": "maint",
                  "direction": "inbound"},
             ],
             "changes": [{"gateway": "gw-1", "scope": "support",
                          "action": "deny", "position": 4,
                          "service": "maint", "direction": "inbound"}]},
            {"id": "expected", "records": [
                ["gw-1", "a-support", "maint", "deny", "inbound"]]},
        ]
        review = review_all(write_sources(
            tempfile.mkdtemp(), entitlements=ENTITLEMENTS, policy=policy,
            receipts=[]), at=60)["changes"][0]
        effects = {item["code"] for item in review["policy"]["order_effects"]}
        self.assertIn("shadowed_rule", effects)
        self.assertIn("same_position", effects)
        self.assertEqual(review["expected"]["summary"]["mismatch"], 1)

    def test_no_declared_default_does_not_invent_allow(self):
        policy = [
            {"id": "obj", "gateway": "gw-1", "object": "support",
             "members": ["a-support"]},
            {"id": "change", "candidate": "ry", "changes": [
                {"gateway": "gw-1", "scope": "support", "action": "deny",
                 "position": 2, "service": "maint", "direction": "inbound"}]},
            {"id": "expected", "records": [
                ["gw-2", "b-support", "maint", "allow", "inbound"]]},
        ]
        review = review_all(write_sources(
            tempfile.mkdtemp(), entitlements=ENTITLEMENTS, policy=policy,
            receipts=[]), at=60)["changes"][0]
        case = review["expected"]["cases"][0]
        self.assertEqual(case["status"], "not_affected")
        self.assertIsNone(case["result"])
        self.assertFalse(case["default_declared"])

    def test_scoped_change_does_not_reach_other_county(self):
        policy = [
            {"id": "obj-a", "gateway": "gw-1", "object": "support",
             "members": ["a-support", "b-support"]},
            {"id": "obj-b", "gateway": "gw-2", "object": "support",
             "members": ["b-support"]},
            {"id": "change", "candidate": "r3", "changes": [
                {"gateway": "gw-1", "scope": "a-support", "action": "deny",
                 "position": 5, "service": "maint", "direction": "inbound"}]},
            {"id": "expected", "records": [
                ["gw-1", "b-support", "maint", "allow", "inbound"]]},
        ]
        review = review_all(write_sources(
            tempfile.mkdtemp(), entitlements=ENTITLEMENTS, policy=policy,
            receipts=[]), at=50)["changes"][0]
        impact = review["approvals"]["by_change"][0]["impact"]
        self.assertEqual(impact["must_keep"], [])
        self.assertEqual(impact["narrow_to"], ["a-support"])
        self.assertNotIn("shared_object_overreach",
                         [item["code"] for item in review["findings"]])

    def test_rollback_rejected_when_snapshot_differs(self):
        policy = POLICY + [
            {"id": "change-2", "candidate": "r4",
             "changes": [{"gateway": "gw-1", "scope": "support",
                          "action": "deny", "position": 6,
                          "service": "maint", "direction": "inbound"}]},
        ]
        receipts = RECEIPTS + [
            {"id": "verified-old", "gateway": "gw-1", "revision": "r1",
             "verified": True, "at": 30,
             "objects": {"support": ["a-support"]},
             "rules": [{"id": "old", "gateway": "gw-1", "scope": "support",
                        "action": "allow", "position": 1, "service": "maint",
                        "direction": "inbound"}]},
        ]
        review = review_all(write_sources(
            tempfile.mkdtemp(), entitlements=ENTITLEMENTS, policy=policy,
            receipts=receipts), at=50, change_id="change-2")["changes"][0]
        rollback = {item["gateway"]: item for item in review["rollback"]}
        self.assertEqual(rollback["gw-1"]["status"], "rejected")
        conditions = {item["code"]: item["status"]
                      for item in rollback["gw-1"]["conditions"]}
        self.assertEqual(conditions["object_mapping_unchanged"], "failed")

    def test_next_change_is_offered_for_duty_desk(self):
        policy = POLICY + [
            {"id": "change-2", "candidate": "r4", "changes": [
                {"gateway": "gw-1", "scope": "support", "action": "deny",
                 "position": 6, "service": "maint", "direction": "inbound"}]},
        ]
        report = review_all(write_sources(
            tempfile.mkdtemp(), entitlements=ENTITLEMENTS, policy=policy,
            receipts=RECEIPTS), at=50)
        self.assertEqual([item["change_id"] for item in report["changes"]],
                         ["rule-review", "change-2"])
        self.assertEqual(report["next_change"], "change-2")
        self.assertTrue(report["changes"][0]["handoff"]["can_continue"])

    def test_report_is_json_serializable(self):
        report = review_all(Path(__file__).with_name("records"), at=50)
        json.dumps(report, ensure_ascii=False)


if __name__ == "__main__":
    unittest.main()
