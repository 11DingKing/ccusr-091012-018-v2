"""
职责冲突（SoD）模块测试用例
"""
from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.authentication.backends import generate_token
from apps.authentication.models import User
from apps.warehouse.models import Category, Goods, StockIn, Unit, Variety
from .engine import get_effective_permissions, scan_standing_conflicts
from .models import ConflictCheckRecord, Delegation, DutyConflictRule, EmergencyExemption


def future(**kwargs):
    return timezone.now() + timedelta(**kwargs)


class SodFixture(TestCase):
    """公共数据：管理员A（移交单位创建人）、管理员C、普通用户B、代理人D"""

    def setUp(self):
        self.admin_a = User.objects.create_user('admin-a', 'pass12345', role='admin')
        self.admin_c = User.objects.create_user('admin-c', 'pass12345', role='admin')
        self.user_b = User.objects.create_user('user-b', 'pass12345', role='user')
        self.delegate_d = User.objects.create_user('user-d', 'pass12345', role='user')

        # admin_a 创建移交单位及货物链
        self.unit = Unit.objects.create(name='箱', created_by=self.admin_a)
        self.category = Category.objects.create(name='受控器材', unit=self.unit, created_by=self.admin_a)
        self.variety = Variety.objects.create(name='记录终端', category=self.category, created_by=self.admin_a)
        self.goods = Goods.objects.create(
            variety=self.variety, name='执法记录终端', code='DEV-001',
            quantity=Decimal('10'), warning_threshold=Decimal('2'),
        )
        # user_b 登记一笔高风险收件
        self.stock_in = StockIn.objects.create(
            goods=self.goods, operator=self.user_b, quantity=Decimal('3'),
            risk_level='high', status='pending',
        )

    def client_for(self, user):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_token(user)}')
        return client

    def create_rule(self, **kwargs):
        defaults = {
            'name': '测试自审规则',
            'rule_type': 'self_approval',
            'object_type': 'stock_in',
            'action': 'stock_in:approve_high_risk',
            'creator_path': 'goods.variety.category.unit.created_by',
            'severity': 'high',
            'status': 'published',
        }
        defaults.update(kwargs)
        return DutyConflictRule.objects.create(**defaults)

    def create_combo_rule(self, **kwargs):
        defaults = {
            'name': '测试组合规则',
            'rule_type': 'role_combo',
            'permissions': ['unit:create', 'stock_in:approve_high_risk'],
            'severity': 'high',
            'status': 'published',
        }
        defaults.update(kwargs)
        return DutyConflictRule.objects.create(**defaults)


class EffectivePermissionTest(SodFixture):
    """有效权限计算：角色 ∪ 生效代理，且记录来源"""

    def test_role_permissions_expanded(self):
        effective = get_effective_permissions(self.admin_a)
        self.assertIn('unit:create', effective)
        self.assertIn('stock_in:approve_high_risk', effective)
        self.assertEqual(effective['unit:create'][0]['type'], 'role')

        effective_user = get_effective_permissions(self.user_b)
        self.assertIn('unit:create', effective_user)
        self.assertNotIn('stock_in:approve_high_risk', effective_user)

    def test_active_delegation_grants_permission_with_source(self):
        delegation = Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_in:approve_high_risk'], reason='休假代理',
            start_at=future(days=-1), end_at=future(days=1),
        )
        effective = get_effective_permissions(self.delegate_d)
        self.assertIn('stock_in:approve_high_risk', effective)
        source = effective['stock_in:approve_high_risk'][0]
        self.assertEqual(source['type'], 'delegation')
        self.assertEqual(source['delegation_id'], delegation.id)
        self.assertEqual(source['delegator'], 'admin-a')

    def test_expired_or_revoked_delegation_excluded(self):
        Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_in:approve_high_risk'], reason='已过期',
            start_at=future(days=-2), end_at=future(days=-1),
        )
        Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_out:approve'], reason='已撤销',
            start_at=future(days=-1), end_at=future(days=1), is_active=False,
        )
        effective = get_effective_permissions(self.delegate_d)
        self.assertNotIn('stock_in:approve_high_risk', effective)
        self.assertNotIn('stock_out:approve', effective)


class RoleComboRuleTest(SodFixture):
    """静态权限组合冲突：预览、发布、存量冲突报告"""

    def test_preview_finds_conflicting_users_with_sources(self):
        rule = self.create_combo_rule(status='draft')
        client = self.client_for(self.admin_a)
        response = client.post(f'/api/sod/rules/{rule.id}/preview/')
        self.assertEqual(response.status_code, 200)

        data = response.json()['data']
        # admin_a 与 admin_c 都同时持有两个权限
        self.assertEqual(data['affected_user_count'], 2)
        usernames = {u['user']['username'] for u in data['affected_users']}
        self.assertEqual(usernames, {'admin-a', 'admin-c'})
        # 冲突可溯源到具体权限及其来源
        matched = data['affected_users'][0]['matched_permissions']
        codes = {p['code'] for p in matched}
        self.assertEqual(codes, {'unit:create', 'stock_in:approve_high_risk'})
        self.assertEqual(matched[0]['sources'][0]['type'], 'role')

    def test_delegation_pushes_user_into_combo_conflict(self):
        # user_d 角色只持有 unit:create，代理获得审批权限后构成组合冲突
        Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_in:approve_high_risk'], reason='临时顶岗',
            start_at=future(days=-1), end_at=future(days=1),
        )
        rule = self.create_combo_rule()
        conflicts = scan_standing_conflicts()
        by_user = {c['user']['username']: c for c in conflicts}
        self.assertIn('user-d', by_user)
        approve_perm = next(
            p for p in by_user['user-d']['matched_permissions']
            if p['code'] == 'stock_in:approve_high_risk'
        )
        self.assertEqual(approve_perm['sources'][0]['type'], 'delegation')

    def test_publish_snapshots_impact_and_keeps_users_unchanged(self):
        rule = self.create_combo_rule(status='draft')
        client = self.client_for(self.admin_a)
        response = client.post(f'/api/sod/rules/{rule.id}/publish/')
        self.assertEqual(response.status_code, 200)

        rule.refresh_from_db()
        self.assertEqual(rule.status, 'published')
        self.assertEqual(rule.published_by, self.admin_a)
        self.assertIsNotNone(rule.published_at)
        # 发布影响快照留痕
        self.assertEqual(rule.publish_impact['affected_user_count'], 2)
        self.assertEqual(rule.publish_impact['evaluated_by'], 'admin-a')
        # 已有用户不被无声改写：角色与权限保持原样
        self.admin_a.refresh_from_db()
        self.admin_c.refresh_from_db()
        self.assertEqual(self.admin_a.role, 'admin')
        self.assertEqual(self.admin_c.role, 'admin')
        # 存量冲突在冲突总览中可见而非被清除
        conflicts = scan_standing_conflicts()
        self.assertEqual(len(conflicts), 2)

    def test_draft_rule_not_counted_in_standing_conflicts(self):
        self.create_combo_rule(status='draft')
        self.assertEqual(scan_standing_conflicts(), [])


class SelfApprovalEnforcementTest(SodFixture):
    """业务自审冲突：创建人（含其代理人）不得批准自己的对象"""

    def setUp(self):
        super().setUp()
        self.rule = self.create_rule()
        self.approve_url = f'/api/stock-in/{self.stock_in.id}/approve/'

    def test_unit_creator_cannot_approve_high_risk_receipt(self):
        client = self.client_for(self.admin_a)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertIn('职责冲突', response.json()['message'])

        self.stock_in.refresh_from_db()
        self.assertEqual(self.stock_in.status, 'pending')

        # 留痕：阻止记录含业务关系与权限来源
        record = ConflictCheckRecord.objects.get(user=self.admin_a, rule=self.rule)
        self.assertEqual(record.result, 'blocked')
        self.assertEqual(record.object_id, self.stock_in.id)
        self.assertEqual(record.basis['relation']['kind'], 'self')
        self.assertEqual(record.basis['relation']['creator']['username'], 'admin-a')
        self.assertEqual(record.basis['action'], 'stock_in:approve_high_risk')
        self.assertTrue(record.basis['action_sources'])

    def test_unrelated_admin_can_approve(self):
        client = self.client_for(self.admin_c)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 200)

        self.stock_in.refresh_from_db()
        self.assertEqual(self.stock_in.status, 'approved')
        self.assertEqual(self.stock_in.approved_by, self.admin_c)
        self.assertIsNotNone(self.stock_in.approved_at)
        self.assertFalse(ConflictCheckRecord.objects.exists())

    def test_user_without_permission_forbidden(self):
        client = self.client_for(self.user_b)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertIn('审批权限', response.json()['message'])

    def test_delegate_of_creator_also_blocked(self):
        Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_in:approve_high_risk'], reason='休假代理',
            start_at=future(days=-1), end_at=future(days=1),
        )
        client = self.client_for(self.delegate_d)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 403)

        record = ConflictCheckRecord.objects.get(user=self.delegate_d)
        self.assertEqual(record.basis['relation']['kind'], 'delegation')
        self.assertEqual(record.basis['relation']['creator']['username'], 'admin-a')

    def test_delegate_can_approve_unrelated_receipt(self):
        # 代理人审批与委托人无关的收件不受影响
        other_unit = Unit.objects.create(name='台', created_by=self.admin_c)
        other_category = Category.objects.create(name='影像设备', unit=other_unit, created_by=self.admin_c)
        other_variety = Variety.objects.create(name='摄像机', category=other_category, created_by=self.admin_c)
        other_goods = Goods.objects.create(
            variety=other_variety, name='高清摄像机', code='CAM-001', quantity=Decimal('5'),
        )
        other_receipt = StockIn.objects.create(
            goods=other_goods, operator=self.user_b, quantity=Decimal('1'),
            risk_level='high', status='pending',
        )
        Delegation.objects.create(
            delegator=self.admin_a, delegate=self.delegate_d,
            permissions=['stock_in:approve_high_risk'], reason='休假代理',
            start_at=future(days=-1), end_at=future(days=1),
        )
        client = self.client_for(self.delegate_d)
        response = client.post(f'/api/stock-in/{other_receipt.id}/approve/', {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 200)

    def test_exemption_allows_with_evidence(self):
        exemption = EmergencyExemption.objects.create(
            user=self.admin_a, rule=self.rule, reason='夜间紧急入库，单人值守',
            approved_by=self.admin_c, start_at=future(hours=-1), end_at=future(hours=2),
        )
        client = self.client_for(self.admin_a)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 200)

        self.stock_in.refresh_from_db()
        self.assertEqual(self.stock_in.status, 'approved')

        # 留痕：豁免放行记录含豁免依据
        record = ConflictCheckRecord.objects.get(user=self.admin_a, rule=self.rule)
        self.assertEqual(record.result, 'exempted')
        self.assertEqual(record.basis['exemption']['id'], exemption.id)
        self.assertEqual(record.basis['exemption']['reason'], '夜间紧急入库，单人值守')
        self.assertEqual(record.basis['exemption']['approved_by'], 'admin-c')

    def test_expired_exemption_does_not_apply(self):
        EmergencyExemption.objects.create(
            user=self.admin_a, rule=self.rule, reason='已过期的豁免',
            approved_by=self.admin_c, start_at=future(days=-2), end_at=future(days=-1),
        )
        client = self.client_for(self.admin_a)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 403)
        record = ConflictCheckRecord.objects.get(user=self.admin_a)
        self.assertEqual(record.result, 'blocked')

    def test_draft_rule_does_not_enforce(self):
        self.rule.status = 'draft'
        self.rule.save()
        client = self.client_for(self.admin_a)
        response = client.post(self.approve_url, {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 200)

    def test_reject_not_blocked_by_sod(self):
        # 拒绝自己的收件无利益冲突，不触发自审拦截
        client = self.client_for(self.admin_a)
        response = client.post(self.approve_url, {'decision': 'reject', 'remark': '单据不全'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.stock_in.refresh_from_db()
        self.assertEqual(self.stock_in.status, 'rejected')


class SelfApprovalPreviewTest(SodFixture):
    """自审规则影响预览：定位到具体业务对象"""

    def test_preview_lists_creators_with_pending_objects(self):
        rule = self.create_rule(status='draft')
        client = self.client_for(self.admin_a)
        response = client.post(f'/api/sod/rules/{rule.id}/preview/')
        self.assertEqual(response.status_code, 200)

        data = response.json()['data']
        self.assertEqual(data['affected_user_count'], 1)
        affected = data['affected_users'][0]
        self.assertEqual(affected['user']['username'], 'admin-a')
        self.assertEqual(affected['creator_path'], 'goods.variety.category.unit.created_by')
        self.assertEqual(affected['pending_object_count'], 1)
        self.assertEqual(affected['pending_objects'][0]['id'], self.stock_in.id)
        self.assertEqual(affected['action'], 'stock_in:approve_high_risk')

    def test_preview_ignores_users_without_action_permission(self):
        # 普通用户创建了单位但不持有审批权限，不构成影响
        unit = Unit.objects.create(name='袋', created_by=self.user_b)
        category = Category.objects.create(name='耗材', unit=unit, created_by=self.user_b)
        variety = Variety.objects.create(name='封存袋', category=category, created_by=self.user_b)
        goods = Goods.objects.create(variety=variety, name='证物封存袋', code='BAG-001', quantity=Decimal('100'))
        StockIn.objects.create(
            goods=goods, operator=self.admin_c, quantity=Decimal('10'),
            risk_level='high', status='pending',
        )
        rule = self.create_rule(status='draft')
        client = self.client_for(self.admin_a)
        data = client.post(f'/api/sod/rules/{rule.id}/preview/').json()['data']
        usernames = {u['user']['username'] for u in data['affected_users']}
        self.assertNotIn('user-b', usernames)
        self.assertIn('admin-a', usernames)


class RuleLifecycleApiTest(SodFixture):
    """规则生命周期：创建→预览→发布→停用，及权限与校验"""

    def test_non_admin_forbidden(self):
        client = self.client_for(self.user_b)
        self.assertEqual(client.get('/api/sod/rules/').status_code, 403)
        self.assertEqual(client.get('/api/sod/permissions/').status_code, 403)
        self.assertEqual(client.get('/api/sod/conflicts/').status_code, 403)

    def test_create_validate_and_publish_flow(self):
        client = self.client_for(self.admin_a)

        # 组合规则至少需要2个权限
        bad = client.post('/api/sod/rules/', {
            'name': '无效规则', 'rule_type': 'role_combo', 'permissions': ['unit:create'],
        }, format='json')
        self.assertEqual(bad.status_code, 400)

        # 未知权限代码被拒绝
        unknown = client.post('/api/sod/rules/', {
            'name': '未知权限规则', 'rule_type': 'role_combo',
            'permissions': ['unit:create', 'not:a:permission'],
        }, format='json')
        self.assertEqual(unknown.status_code, 400)

        # 自审规则需要有效的对象类型与创建人路径
        bad_path = client.post('/api/sod/rules/', {
            'name': '无效路径规则', 'rule_type': 'self_approval',
            'object_type': 'stock_in', 'action': 'stock_in:approve_high_risk',
            'creator_path': 'no.such.path',
        }, format='json')
        self.assertEqual(bad_path.status_code, 400)

        created = client.post('/api/sod/rules/', {
            'name': '创建与审批互斥', 'rule_type': 'role_combo',
            'permissions': ['unit:create', 'stock_in:approve_high_risk'],
            'severity': 'high', 'description': '审计发现',
        }, format='json')
        self.assertEqual(created.status_code, 200)
        rule_id = created.json()['data']['id']
        self.assertEqual(created.json()['data']['status'], 'draft')

        # 草稿可修改
        updated = client.put(f'/api/sod/rules/{rule_id}/', {
            'name': '创建与审批互斥', 'rule_type': 'role_combo',
            'permissions': ['unit:create', 'stock_in:approve_high_risk'],
            'severity': 'medium',
        }, format='json')
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()['data']['severity'], 'medium')

        # 发布后不可再修改或删除
        client.post(f'/api/sod/rules/{rule_id}/publish/')
        self.assertEqual(client.put(f'/api/sod/rules/{rule_id}/', {
            'name': '改名', 'rule_type': 'role_combo',
            'permissions': ['unit:create', 'stock_in:approve_high_risk'],
        }, format='json').status_code, 400)
        self.assertEqual(client.delete(f'/api/sod/rules/{rule_id}/').status_code, 400)

        # 停用后不再产生存量冲突
        self.assertEqual(client.post(f'/api/sod/rules/{rule_id}/disable/').status_code, 200)
        self.assertEqual(scan_standing_conflicts(), [])

    def test_seeded_audit_rules_exist_as_draft(self):
        # 数据迁移预置的审计规则为草稿，不静默改变现有行为
        names = set(DutyConflictRule.objects.filter(status='draft').values_list('name', flat=True))
        self.assertIn('移交单位创建与高风险收件审批权限互斥', names)
        self.assertIn('创建移交单位者不得审批该单位高风险收件', names)

    def test_permission_catalog_endpoint(self):
        client = self.client_for(self.admin_a)
        data = client.get('/api/sod/permissions/').json()['data']
        codes = {p['code'] for p in data['permissions']}
        self.assertIn('stock_in:approve_high_risk', codes)
        roles = {r['role'] for r in data['role_permissions']}
        self.assertEqual(roles, {'user', 'admin', 'superadmin'})
        self.assertEqual(data['object_types'][0]['object_type'], 'stock_in')


class DelegationApiTest(SodFixture):
    """临时代理登记与校验"""

    def test_create_and_revoke_delegation(self):
        client = self.client_for(self.admin_a)
        created = client.post('/api/sod/delegations/', {
            'delegator': self.admin_a.id, 'delegate': self.delegate_d.id,
            'permissions': ['stock_in:approve_high_risk'],
            'reason': '休假一周，工作交接',
            'start_at': future(hours=-1).isoformat(),
            'end_at': future(days=7).isoformat(),
        }, format='json')
        self.assertEqual(created.status_code, 200)
        delegation_id = created.json()['data']['id']
        self.assertTrue(created.json()['data']['in_effect'])

        revoked = client.post(f'/api/sod/delegations/{delegation_id}/revoke/')
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(revoked.json()['data']['in_effect'])

    def test_delegation_validation(self):
        client = self.client_for(self.admin_a)
        base = {
            'delegator': self.admin_a.id, 'delegate': self.delegate_d.id,
            'permissions': ['stock_in:approve_high_risk'], 'reason': '交接',
            'start_at': future(hours=-1).isoformat(), 'end_at': future(days=1).isoformat(),
        }
        # 不能代理给自己
        self_delegation = {**base, 'delegate': self.admin_a.id}
        self.assertEqual(client.post('/api/sod/delegations/', self_delegation, format='json').status_code, 400)
        # 委托人不持有的权限不能代理
        not_held = {**base, 'delegator': self.user_b.id}
        self.assertEqual(client.post('/api/sod/delegations/', not_held, format='json').status_code, 400)
        # 失效时间必须晚于生效时间
        bad_window = {**base, 'end_at': future(days=-1).isoformat()}
        self.assertEqual(client.post('/api/sod/delegations/', bad_window, format='json').status_code, 400)
        # 代理依据必填
        no_reason = {**base, 'reason': ''}
        self.assertEqual(client.post('/api/sod/delegations/', no_reason, format='json').status_code, 400)


class ExemptionApiTest(SodFixture):
    """紧急豁免登记与校验"""

    def setUp(self):
        super().setUp()
        self.rule = self.create_rule()

    def test_create_and_revoke_exemption(self):
        client = self.client_for(self.admin_c)
        created = client.post('/api/sod/exemptions/', {
            'user': self.admin_a.id, 'rule': self.rule.id,
            'reason': '突发事件，单人值守',
            'start_at': future(hours=-1).isoformat(),
            'end_at': future(hours=4).isoformat(),
        }, format='json')
        self.assertEqual(created.status_code, 200)
        exemption_id = created.json()['data']['id']
        self.assertEqual(created.json()['data']['approved_by'], self.admin_c.id)

        revoked = client.post(f'/api/sod/exemptions/{exemption_id}/revoke/')
        self.assertEqual(revoked.status_code, 200)
        self.assertFalse(revoked.json()['data']['in_effect'])

    def test_exemption_validation(self):
        client = self.client_for(self.admin_c)
        base = {
            'user': self.admin_a.id, 'rule': self.rule.id, 'reason': '紧急情况',
            'start_at': future(hours=-1).isoformat(), 'end_at': future(hours=2).isoformat(),
        }
        # 不能为本人批准豁免
        self_exemption = {**base, 'user': self.admin_c.id}
        response = client.post('/api/sod/exemptions/', self_exemption, format='json')
        self.assertEqual(response.status_code, 400)
        # 草稿规则不能设置豁免
        draft_rule = self.create_rule(name='草稿规则', status='draft')
        draft = {**base, 'rule': draft_rule.id}
        self.assertEqual(client.post('/api/sod/exemptions/', draft, format='json').status_code, 400)
        # 豁免依据必填
        no_reason = {**base, 'reason': ''}
        self.assertEqual(client.post('/api/sod/exemptions/', no_reason, format='json').status_code, 400)


class ConflictOverviewTest(SodFixture):
    """冲突总览：管理员看到冲突来自哪些权限和业务关系"""

    def test_overview_combines_standing_conflicts_and_records(self):
        self.create_combo_rule()
        rule = self.create_rule()
        EmergencyExemption.objects.create(
            user=self.admin_a, rule=rule, reason='紧急放行',
            approved_by=self.admin_c, start_at=future(hours=-1), end_at=future(hours=1),
        )
        client = self.client_for(self.admin_a)
        client.post(f'/api/stock-in/{self.stock_in.id}/approve/', {'decision': 'approve'}, format='json')

        response = client.get('/api/sod/conflicts/')
        self.assertEqual(response.status_code, 200)
        data = response.json()['data']

        # 存量冲突：命中权限及来源可见
        self.assertEqual(data['standing_conflict_count'], 2)
        standing = data['standing_conflicts'][0]
        self.assertIn('matched_permissions', standing)
        self.assertEqual(standing['rule']['rule_type'], 'role_combo')

        # 判定记录：业务关系与豁免依据可见
        self.assertEqual(len(data['recent_records']), 1)
        record = data['recent_records'][0]
        self.assertEqual(record['result'], 'exempted')
        self.assertEqual(record['basis']['relation']['creator_path_label'], '移交单位创建人')
        self.assertEqual(record['basis']['exemption']['reason'], '紧急放行')

    def test_records_endpoint_filters(self):
        rule = self.create_rule()
        client = self.client_for(self.admin_a)
        client.post(f'/api/stock-in/{self.stock_in.id}/approve/', {'decision': 'approve'}, format='json')

        response = client.get(f'/api/sod/records/?result=blocked&rule={rule.id}')
        self.assertEqual(response.status_code, 200)
        data = response.json()['data']
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['list'][0]['user_name'], 'admin-a')

        empty = client.get('/api/sod/records/?result=exempted')
        self.assertEqual(empty.json()['data']['total'], 0)


class StockInFlowTest(SodFixture):
    """收件登记与审批流程"""

    def test_normal_receipt_approved_immediately(self):
        client = self.client_for(self.user_b)
        response = client.post('/api/stock-in/', {
            'goods': self.goods.id, 'quantity': '2', 'risk_level': 'normal',
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['data']['status'], 'approved')

    def test_high_risk_receipt_pending_then_approved(self):
        client = self.client_for(self.user_b)
        created = client.post('/api/stock-in/', {
            'goods': self.goods.id, 'quantity': '2', 'risk_level': 'high',
            'batch_no': 'B20261003',
        }, format='json')
        self.assertEqual(created.status_code, 200)
        self.assertEqual(created.json()['data']['status'], 'pending')

        admin_client = self.client_for(self.admin_c)
        approved = admin_client.post(
            f"/api/stock-in/{created.json()['data']['id']}/approve/",
            {'decision': 'approve'}, format='json',
        )
        self.assertEqual(approved.status_code, 200)
        self.assertEqual(approved.json()['data']['status'], 'approved')

    def test_approve_guards(self):
        # 普通收件无需审批
        normal = StockIn.objects.create(
            goods=self.goods, operator=self.user_b, quantity=Decimal('1'),
            risk_level='normal', status='approved',
        )
        client = self.client_for(self.admin_c)
        response = client.post(f'/api/stock-in/{normal.id}/approve/', {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 400)

        # 重复审批被拒绝
        approved = StockIn.objects.create(
            goods=self.goods, operator=self.user_b, quantity=Decimal('1'),
            risk_level='high', status='approved', approved_by=self.admin_c,
        )
        response = client.post(f'/api/stock-in/{approved.id}/approve/', {'decision': 'approve'}, format='json')
        self.assertEqual(response.status_code, 400)

        # 不存在的收件
        self.assertEqual(
            client.post('/api/stock-in/99999/approve/', {'decision': 'approve'}, format='json').status_code,
            404,
        )

    def test_list_filters(self):
        client = self.client_for(self.user_b)
        response = client.get('/api/stock-in/?risk_level=high&status=pending')
        self.assertEqual(response.status_code, 200)
        data = response.json()['data']
        self.assertEqual(data['total'], 1)
        self.assertEqual(data['list'][0]['id'], self.stock_in.id)
