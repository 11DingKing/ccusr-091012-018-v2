"""
职责冲突模块测试用例
"""
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.authentication.backends import generate_token
from apps.authentication.models import User
from apps.warehouse.models import Category, Goods, StockIn, Unit, Variety
from .models import (
    DutyCheckLog, DutyConflictRecord, DutyConflictRule, DutyDelegation, DutyExemption,
)
from .services import get_effective_permissions


class SodFixture(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user("sod-admin", "testpass123", role="admin")
        self.admin2 = User.objects.create_user("sod-admin-2", "testpass123", role="admin")
        self.plain = User.objects.create_user("sod-user", "testpass123", role="user")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {generate_token(self.admin)}")

        self.unit = Unit.objects.create(name="件", created_by=self.admin)
        self.category = Category.objects.create(name="受控器材", unit=self.unit, created_by=self.admin)
        self.variety = Variety.objects.create(name="记录终端", category=self.category, created_by=self.admin)
        self.goods = Goods.objects.create(
            variety=self.variety, name="执法记录终端", code="DEV-001",
            quantity=Decimal("12"), warning_threshold=Decimal("5"),
        )

    def as_user(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {generate_token(user)}")
        return client

    def make_receipt(self, operator=None, high_risk=True):
        return StockIn.objects.create(
            goods=self.goods, operator=operator or self.admin,
            quantity=Decimal("2"), is_high_risk=high_risk,
        )

    def make_role_combo_rule(self, publish=True, permission_a="unit:create",
                             permission_b="receipt:approve_high_risk"):
        rule = DutyConflictRule.objects.create(
            name="收发权限互斥", rule_type="role_combo",
            permission_a=permission_a, permission_b=permission_b,
            severity="high", created_by=self.admin,
        )
        if publish:
            rule.status = "published"
            rule.save()
        return rule

    def make_self_approval_rule(self, publish=True):
        rule = DutyConflictRule.objects.create(
            name="高风险收件自审", rule_type="self_approval",
            object_type="stock_in", severity="high", created_by=self.admin,
        )
        if publish:
            rule.status = "published"
            rule.save()
        return rule

    def make_delegation(self, delegate=None, permission="receipt:approve_high_risk",
                        delegator=None, hours=1, expired=False):
        now = timezone.now()
        if expired:
            start_at, end_at = now - timedelta(hours=2), now - timedelta(hours=1)
        else:
            start_at, end_at = now - timedelta(hours=1), now + timedelta(hours=hours)
        return DutyDelegation.objects.create(
            delegator=delegator or self.admin,
            delegate=delegate or self.plain,
            permission=permission,
            reason="休假临时代理",
            start_at=start_at, end_at=end_at,
            created_by=self.admin,
        )


class RuleManageTest(SodFixture):
    def test_non_admin_cannot_manage_rules(self):
        client = self.as_user(self.plain)
        self.assertEqual(client.get("/api/sod/rules/").status_code, 403)
        response = client.post("/api/sod/rules/", {
            "name": "越权规则", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "receipt:approve_high_risk",
        }, format="json")
        self.assertEqual(response.status_code, 403)

    def test_create_and_list_rule(self):
        response = self.client.post("/api/sod/rules/", {
            "name": "收发权限互斥", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "receipt:approve_high_risk",
            "severity": "high",
        }, format="json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["status"], "draft")

        listed = self.client.get("/api/sod/rules/")
        self.assertEqual(listed.json()["data"]["total"], 1)

    def test_rule_validation(self):
        # 两个冲突权限不能相同
        same = self.client.post("/api/sod/rules/", {
            "name": "规则一", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "unit:create",
        }, format="json")
        self.assertEqual(same.status_code, 400)

        # 权限必须在权限目录中
        unknown = self.client.post("/api/sod/rules/", {
            "name": "规则二", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "ghost:perm",
        }, format="json")
        self.assertEqual(unknown.status_code, 400)

        # 自审规则必须选择业务对象
        missing_object = self.client.post("/api/sod/rules/", {
            "name": "规则三", "rule_type": "self_approval",
        }, format="json")
        self.assertEqual(missing_object.status_code, 400)

    def test_reject_duplicate_permission_pair(self):
        self.make_role_combo_rule(publish=False)
        duplicate = self.client.post("/api/sod/rules/", {
            "name": "重复规则", "rule_type": "role_combo",
            "permission_a": "receipt:approve_high_risk", "permission_b": "unit:create",
        }, format="json")
        self.assertEqual(duplicate.status_code, 400)

    def test_only_draft_can_be_updated_or_deleted(self):
        rule = self.make_role_combo_rule(publish=True)
        updated = self.client.put(f"/api/sod/rules/{rule.id}/", {
            "name": "改名规则", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "receipt:approve_high_risk",
        }, format="json")
        self.assertEqual(updated.status_code, 400)
        deleted = self.client.delete(f"/api/sod/rules/{rule.id}/")
        self.assertEqual(deleted.status_code, 400)

        rule.status = "draft"
        rule.save()
        updated = self.client.put(f"/api/sod/rules/{rule.id}/", {
            "name": "改名规则", "rule_type": "role_combo",
            "permission_a": "unit:create", "permission_b": "receipt:approve_high_risk",
        }, format="json")
        self.assertEqual(updated.status_code, 200)
        deleted = self.client.delete(f"/api/sod/rules/{rule.id}/")
        self.assertEqual(deleted.status_code, 200)

    def test_permission_catalog_visible_to_admin(self):
        denied = self.as_user(self.plain).get("/api/sod/permissions/")
        self.assertEqual(denied.status_code, 403)

        response = self.client.get("/api/sod/permissions/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        codes = [p["code"] for p in data["permissions"]]
        self.assertIn("unit:create", codes)
        self.assertIn("receipt:approve_high_risk", data["role_permissions"]["admin"])


class RulePublishTest(SodFixture):
    def test_preview_is_readonly(self):
        rule = self.make_role_combo_rule(publish=False)
        response = self.client.get(f"/api/sod/rules/{rule.id}/preview/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        # admin 与 admin2 都同时持有两个冲突权限，plain 不持有
        self.assertEqual(data["affected_count"], 2)
        usernames = {u["username"] for u in data["affected_users"]}
        self.assertEqual(usernames, {"sod-admin", "sod-admin-2"})
        sources = data["affected_users"][0]["sources"]
        self.assertTrue(all(s["type"] == "permission" for s in sources))
        # 预览不写入任何记录，规则保持草稿
        self.assertEqual(DutyConflictRecord.objects.count(), 0)
        rule.refresh_from_db()
        self.assertEqual(rule.status, "draft")

    def test_publish_requires_confirm_and_never_rewrites_users(self):
        rule = self.make_role_combo_rule(publish=False)

        unconfirmed = self.client.post(f"/api/sod/rules/{rule.id}/publish/", {}, format="json")
        self.assertEqual(unconfirmed.status_code, 400)
        self.assertTrue(unconfirmed.json()["data"]["requires_confirmation"])
        rule.refresh_from_db()
        self.assertEqual(rule.status, "draft")
        self.assertEqual(DutyConflictRecord.objects.count(), 0)

        confirmed = self.client.post(
            f"/api/sod/rules/{rule.id}/publish/", {"confirm": True}, format="json"
        )
        self.assertEqual(confirmed.status_code, 200)
        rule.refresh_from_db()
        self.assertEqual(rule.status, "published")
        self.assertEqual(rule.published_by, self.admin)

        # 冲突登记在案，但既有用户的角色与状态不被改写
        self.assertEqual(DutyConflictRecord.objects.filter(rule=rule).count(), 2)
        self.admin.refresh_from_db()
        self.assertEqual(self.admin.role, "admin")
        self.assertTrue(self.admin.is_active)

    def test_disable_rule(self):
        rule = self.make_role_combo_rule(publish=True)
        response = self.client.post(f"/api/sod/rules/{rule.id}/disable/")
        self.assertEqual(response.status_code, 200)
        rule.refresh_from_db()
        self.assertEqual(rule.status, "disabled")


class StaticScanTest(SodFixture):
    def test_scan_records_conflicts_with_permission_sources(self):
        rule = self.make_role_combo_rule(publish=True)
        response = self.client.post("/api/sod/scan/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["conflict_count"], 2)

        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        self.assertEqual(record.status, "open")
        permissions = {s["permission"] for s in record.sources}
        self.assertEqual(permissions, {"unit:create", "receipt:approve_high_risk"})
        self.assertTrue(all(s["type"] == "permission" for s in record.sources))
        self.assertTrue(all(s["role"] == "admin" for s in record.sources))

    def test_scan_counts_active_delegation(self):
        rule = self.make_role_combo_rule(
            publish=True, permission_a="receipt:create",
            permission_b="receipt:approve_high_risk",
        )
        self.make_delegation(delegate=self.plain)
        self.client.post("/api/sod/scan/")

        record = DutyConflictRecord.objects.get(rule=rule, user=self.plain)
        delegation_sources = [s for s in record.sources if s.get("delegation_id")]
        self.assertEqual(len(delegation_sources), 1)
        self.assertEqual(delegation_sources[0]["delegator"], "sod-admin")

    def test_expired_delegation_not_counted(self):
        rule = self.make_role_combo_rule(
            publish=True, permission_a="receipt:create",
            permission_b="receipt:approve_high_risk",
        )
        self.make_delegation(delegate=self.plain, expired=True)
        self.client.post("/api/sod/scan/")
        self.assertFalse(DutyConflictRecord.objects.filter(rule=rule, user=self.plain).exists())

    def test_scan_marks_exempted_user(self):
        rule = self.make_role_combo_rule(publish=True)
        DutyExemption.objects.create(
            user=self.admin, rule=rule, reason="盘点应急",
            expires_at=timezone.now() + timedelta(hours=2), created_by=self.admin,
        )
        self.client.post("/api/sod/scan/")
        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        self.assertEqual(record.status, "exempted")
        other = DutyConflictRecord.objects.get(rule=rule, user=self.admin2)
        self.assertEqual(other.status, "open")

    def test_conflict_list_and_resolve(self):
        rule = self.make_role_combo_rule(publish=True)
        self.client.post("/api/sod/scan/")

        listed = self.client.get("/api/sod/conflicts/")
        self.assertEqual(listed.json()["data"]["total"], 2)
        first = listed.json()["data"]["list"][0]
        self.assertIn("sources", first)

        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        missing_note = self.client.post(f"/api/sod/conflicts/{record.id}/resolve/", {}, format="json")
        self.assertEqual(missing_note.status_code, 400)

        resolved = self.client.post(f"/api/sod/conflicts/{record.id}/resolve/", {
            "resolution_note": "已调整岗位分工",
        }, format="json")
        self.assertEqual(resolved.status_code, 200)
        record.refresh_from_db()
        self.assertEqual(record.status, "resolved")
        self.assertEqual(record.resolved_by, self.admin)


class DelegationTest(SodFixture):
    def test_create_delegation_via_api(self):
        now = timezone.now()
        response = self.client.post("/api/sod/delegations/", {
            "delegator": self.admin.id,
            "delegate": self.plain.id,
            "permission": "receipt:approve_high_risk",
            "reason": "休假临时代理",
            "start_at": (now - timedelta(hours=1)).isoformat(),
            "end_at": (now + timedelta(hours=2)).isoformat(),
        }, format="json")
        self.assertEqual(response.status_code, 200)

        perms, sources = get_effective_permissions(self.plain)
        self.assertIn("receipt:approve_high_risk", perms)
        self.assertEqual(sources["receipt:approve_high_risk"][0]["type"], "delegation")

    def test_delegation_validation(self):
        now = timezone.now()
        # 委托人与代理人不能是同一人
        same = self.client.post("/api/sod/delegations/", {
            "delegator": self.admin.id, "delegate": self.admin.id,
            "permission": "receipt:approve_high_risk", "reason": "测试",
            "start_at": now.isoformat(), "end_at": (now + timedelta(hours=1)).isoformat(),
        }, format="json")
        self.assertEqual(same.status_code, 400)

        # 失效时间必须晚于生效时间
        bad_window = self.client.post("/api/sod/delegations/", {
            "delegator": self.admin.id, "delegate": self.plain.id,
            "permission": "receipt:approve_high_risk", "reason": "测试",
            "start_at": now.isoformat(), "end_at": (now - timedelta(hours=1)).isoformat(),
        }, format="json")
        self.assertEqual(bad_window.status_code, 400)

        # 只能转授自己持有的权限
        not_held = self.client.post("/api/sod/delegations/", {
            "delegator": self.plain.id, "delegate": self.admin2.id,
            "permission": "receipt:approve_high_risk", "reason": "测试",
            "start_at": now.isoformat(), "end_at": (now + timedelta(hours=1)).isoformat(),
        }, format="json")
        self.assertEqual(not_held.status_code, 400)

    def test_delegation_blocked_when_introducing_conflict(self):
        rule = self.make_role_combo_rule(
            publish=True, permission_a="receipt:create",
            permission_b="receipt:approve_high_risk",
        )
        now = timezone.now()
        payload = {
            "delegator": self.admin.id, "delegate": self.plain.id,
            "permission": "receipt:approve_high_risk", "reason": "休假临时代理",
            "start_at": now.isoformat(), "end_at": (now + timedelta(hours=2)).isoformat(),
        }
        blocked = self.client.post("/api/sod/delegations/", payload, format="json")
        self.assertEqual(blocked.status_code, 400)
        conflicts = blocked.json()["data"]["conflicts"]
        self.assertEqual(conflicts[0]["rule_id"], rule.id)
        self.assertEqual(DutyDelegation.objects.count(), 0)

        # 登记紧急豁免后允许建立代理
        DutyExemption.objects.create(
            user=self.plain, rule=rule, reason="夜间值班应急",
            expires_at=now + timedelta(hours=3), created_by=self.admin,
        )
        allowed = self.client.post("/api/sod/delegations/", payload, format="json")
        self.assertEqual(allowed.status_code, 200)

    def test_revoke_delegation_keeps_record(self):
        delegation = self.make_delegation()
        response = self.client.delete(f"/api/sod/delegations/{delegation.id}/")
        self.assertEqual(response.status_code, 200)
        delegation.refresh_from_db()
        self.assertFalse(delegation.is_active)
        perms, _ = get_effective_permissions(self.plain)
        self.assertNotIn("receipt:approve_high_risk", perms)


class SelfApprovalTest(SodFixture):
    def test_operator_cannot_approve_own_high_risk_receipt(self):
        rule = self.make_self_approval_rule(publish=True)
        receipt = self.make_receipt(operator=self.admin)

        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 403)
        self.assertIn("登记人", response.json()["message"])
        self.assertEqual(response.json()["data"]["rule_id"], rule.id)

        receipt.refresh_from_db()
        self.assertEqual(receipt.status, "pending")

        # 阻断留下判断依据
        log = DutyCheckLog.objects.get(user=self.admin, rule=rule)
        self.assertEqual(log.decision, "blocked")
        self.assertIn("高风险收件自审", log.basis)
        # 冲突登记在案，来源为业务关系
        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        self.assertEqual(record.status, "open")
        self.assertEqual(record.sources[0]["type"], "business_relation")

    def test_unit_creator_cannot_approve(self):
        self.make_self_approval_rule(publish=True)
        # 收件由普通用户登记，但移交单位是 admin 创建的
        receipt = self.make_receipt(operator=self.plain)

        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 403)
        relations = response.json()["data"]["relations"]
        self.assertEqual(relations[0]["relation"], "unit_creator")
        self.assertEqual(relations[0]["object_id"], self.unit.id)

    def test_unrelated_admin_can_approve(self):
        self.make_self_approval_rule(publish=True)
        receipt = self.make_receipt(operator=self.plain)

        client2 = self.as_user(self.admin2)
        response = client2.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

        receipt.refresh_from_db()
        self.assertEqual(receipt.status, "approved")
        self.assertEqual(receipt.approved_by, self.admin2)
        self.goods.refresh_from_db()
        self.assertEqual(self.goods.quantity, Decimal("14"))

    def test_unpublished_rule_does_not_block(self):
        self.make_self_approval_rule(publish=False)
        receipt = self.make_receipt(operator=self.admin)
        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

    def test_disabled_rule_does_not_block(self):
        rule = self.make_self_approval_rule(publish=True)
        rule.status = "disabled"
        rule.save()
        receipt = self.make_receipt(operator=self.admin)
        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

    def test_plain_user_lacks_approve_permission(self):
        receipt = self.make_receipt(operator=self.admin)
        response = self.as_user(self.plain).post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 403)
        self.assertIn("审批权限", response.json()["message"])

    def test_delegation_grants_runtime_approve_permission(self):
        self.make_self_approval_rule(publish=True)
        self.make_delegation(delegate=self.plain)
        # 收件与单位都由 admin 创建，plain 与其无创建关系
        receipt = self.make_receipt(operator=self.admin)
        response = self.as_user(self.plain).post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

    def test_expired_delegation_denies_approve(self):
        self.make_delegation(delegate=self.plain, expired=True)
        receipt = self.make_receipt(operator=self.admin)
        response = self.as_user(self.plain).post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 403)

    def test_exemption_allows_with_trail(self):
        rule = self.make_self_approval_rule(publish=True)
        receipt = self.make_receipt(operator=self.admin)
        exemption = DutyExemption.objects.create(
            user=self.admin, rule=rule, reason="夜间突发处置",
            expires_at=timezone.now() + timedelta(hours=2), created_by=self.admin2,
        )

        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

        log = DutyCheckLog.objects.get(user=self.admin, rule=rule)
        self.assertEqual(log.decision, "allowed_exempted")
        self.assertEqual(log.exemption, exemption)
        self.assertIn("夜间突发处置", log.basis)
        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        self.assertEqual(record.status, "exempted")

    def test_expired_exemption_blocks(self):
        rule = self.make_self_approval_rule(publish=True)
        DutyExemption.objects.create(
            user=self.admin, rule=rule, reason="已过期豁免",
            expires_at=timezone.now() - timedelta(hours=1), created_by=self.admin2,
        )
        receipt = self.make_receipt(operator=self.admin)
        response = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 403)

    def test_superadmin_bypass_leaves_trail(self):
        superadmin = User.objects.create_superuser("sod-root", "testpass123")
        rule = self.make_self_approval_rule(publish=True)
        unit = Unit.objects.create(name="箱", created_by=superadmin)
        category = Category.objects.create(name="封存介质", unit=unit, created_by=superadmin)
        variety = Variety.objects.create(name="封存硬盘", category=category, created_by=superadmin)
        goods = Goods.objects.create(
            variety=variety, name="封存硬盘A", code="DEV-002", quantity=Decimal("1"),
        )
        receipt = StockIn.objects.create(
            goods=goods, operator=superadmin, quantity=Decimal("1"), is_high_risk=True,
        )

        with patch("apps.authentication.models.SUPERADMIN_ID", superadmin.id):
            response = self.as_user(superadmin).post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)
        log = DutyCheckLog.objects.get(user=superadmin, rule=rule)
        self.assertEqual(log.decision, "bypassed")

    def test_non_high_risk_receipt_approve_without_rule(self):
        receipt = self.make_receipt(operator=self.admin, high_risk=False)
        response = self.as_user(self.plain).post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(response.status_code, 200)

    def test_check_logs_visible_to_admin(self):
        self.make_self_approval_rule(publish=True)
        receipt = self.make_receipt(operator=self.admin)
        self.client.post(f"/api/stock-in/{receipt.id}/approve/")

        denied = self.as_user(self.plain).get("/api/sod/check-logs/")
        self.assertEqual(denied.status_code, 403)

        response = self.client.get("/api/sod/check-logs/")
        self.assertEqual(response.status_code, 200)
        logs = response.json()["data"]["list"]
        self.assertEqual(logs[0]["decision"], "blocked")
        self.assertIn("登记人", logs[0]["basis"])


class SelfApprovalPreviewTest(SodFixture):
    def test_preview_lists_business_relations(self):
        rule = self.make_self_approval_rule(publish=False)
        receipt = self.make_receipt(operator=self.admin)
        # plain 登记的收件，单位创建人是 admin
        self.make_receipt(operator=self.plain)

        response = self.client.get(f"/api/sod/rules/{rule.id}/preview/")
        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        affected = {u["username"]: u for u in data["affected_users"]}

        # admin 持有审批权限，与两单收件都有创建关系
        self.assertTrue(affected["sod-admin"]["holds_approve_permission"])
        self.assertEqual(len(affected["sod-admin"]["objects"]), 2)
        relations = affected["sod-admin"]["objects"][0]["relations"]
        self.assertEqual(relations[0]["type"], "business_relation")
        # plain 是登记人但不持有审批权限
        self.assertFalse(affected["sod-user"]["holds_approve_permission"])
        # 预览不写入记录
        self.assertEqual(DutyConflictRecord.objects.count(), 0)

    def test_publish_self_approval_registers_conflicts(self):
        rule = self.make_self_approval_rule(publish=False)
        self.make_receipt(operator=self.admin)

        unconfirmed = self.client.post(f"/api/sod/rules/{rule.id}/publish/", {}, format="json")
        self.assertEqual(unconfirmed.status_code, 400)

        confirmed = self.client.post(
            f"/api/sod/rules/{rule.id}/publish/", {"confirm": True}, format="json"
        )
        self.assertEqual(confirmed.status_code, 200)
        record = DutyConflictRecord.objects.get(rule=rule, user=self.admin)
        self.assertEqual(record.sources[0]["type"], "business_relation")


class ReceiptApiTest(SodFixture):
    def test_create_and_list_receipt(self):
        created = self.client.post("/api/stock-in/", {
            "goods": self.goods.id, "quantity": "3",
            "batch_no": "B-001", "is_high_risk": True,
        }, format="json")
        self.assertEqual(created.status_code, 200)
        data = created.json()["data"]
        self.assertEqual(data["status"], "pending")
        self.assertTrue(data["is_high_risk"])
        self.assertEqual(data["operator"], self.admin.id)

        listed = self.client.get("/api/stock-in/")
        self.assertEqual(listed.json()["data"]["total"], 1)

    def test_create_receipt_validates_input(self):
        bad_goods = self.client.post("/api/stock-in/", {
            "goods": 99999, "quantity": "3",
        }, format="json")
        self.assertEqual(bad_goods.status_code, 400)

        bad_quantity = self.client.post("/api/stock-in/", {
            "goods": self.goods.id, "quantity": "0",
        }, format="json")
        self.assertEqual(bad_quantity.status_code, 400)

    def test_approve_twice_rejected(self):
        receipt = self.make_receipt(operator=self.admin, high_risk=False)
        first = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        second = self.client.post(f"/api/stock-in/{receipt.id}/approve/")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 400)

    def test_approve_missing_receipt(self):
        response = self.client.post("/api/stock-in/99999/approve/")
        self.assertEqual(response.status_code, 404)
