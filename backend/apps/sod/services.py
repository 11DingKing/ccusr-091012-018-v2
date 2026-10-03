"""
职责冲突判断引擎

所有判断（静态组合扫描、业务自审阻断、临时代理校验）都汇总在这里，
保证临时代理与紧急豁免在每一处判断中被一致地纳入，并统一留下依据。
"""
from django.utils import timezone
from apps.authentication.models import User
from .models import (
    DutyConflictRule, DutyDelegation, DutyExemption,
    DutyConflictRecord, DutyCheckLog,
)
from .permissions import PERMISSION_CATALOG, get_role_permissions, permission_name

# 高风险收件审批权限，业务自审与影响预览共用
HIGH_RISK_APPROVE_PERMISSION = 'receipt:approve_high_risk'


def get_active_delegations(user, at=None):
    """用户作为代理人、当前生效的临时代理"""
    at = at or timezone.now()
    return list(DutyDelegation.objects.filter(
        delegate=user, is_active=True, start_at__lte=at, end_at__gte=at
    ).select_related('delegator'))


def get_effective_permissions(user, at=None):
    """
    有效权限 = 角色权限 + 生效中的临时代理权限。
    返回 (权限集合, 来源字典)，来源字典记录每项权限来自哪个角色或哪条代理，
    用于向管理员说明"冲突来自哪些权限"。
    """
    at = at or timezone.now()
    sources = {}
    for perm in get_role_permissions(user.role):
        sources.setdefault(perm, []).append({
            'type': 'role',
            'role': user.role,
            'role_name': dict(User.ROLE_CHOICES).get(user.role, user.role),
        })
    for delegation in get_active_delegations(user, at):
        sources.setdefault(delegation.permission, []).append({
            'type': 'delegation',
            'delegation_id': delegation.id,
            'delegator': delegation.delegator.username,
            'reason': delegation.reason,
        })
    return set(sources.keys()), sources


def get_active_exemption(user, rule, at=None):
    """用户对某条规则当前有效的紧急豁免"""
    at = at or timezone.now()
    return DutyExemption.objects.filter(
        user=user, rule=rule, is_active=True, expires_at__gt=at
    ).first()


# ==================== 静态角色组合检查 ====================

def _permission_source_entries(perm, origins):
    """把某项权限的来源（角色/代理）展开为冲突来源条目"""
    entries = []
    for origin in origins:
        entries.append({
            'type': 'permission',
            'permission': perm,
            'permission_name': permission_name(perm),
            'via': origin['type'],
            **{k: v for k, v in origin.items() if k != 'type'},
        })
    return entries


def evaluate_role_combo_rule(rule, user, at=None):
    """
    静态组合检查：用户同时持有规则的两个冲突权限时，
    返回冲突来源列表（说明每项权限来自角色还是代理），否则返回 None。
    """
    perms, sources = get_effective_permissions(user, at)
    needed = [rule.permission_a, rule.permission_b]
    if not all(p in perms for p in needed):
        return None
    conflict_sources = []
    for perm in needed:
        conflict_sources.extend(_permission_source_entries(perm, sources[perm]))
    return conflict_sources


def upsert_conflict_record(rule, user, sources, at=None):
    """登记或刷新冲突记录；存在有效豁免时标记为已豁免。绝不改写用户本身。"""
    at = at or timezone.now()
    status = 'exempted' if get_active_exemption(user, rule, at) else 'open'
    record, created = DutyConflictRecord.objects.get_or_create(
        rule=rule, user=user,
        defaults={'sources': sources, 'status': status},
    )
    if not created:
        record.sources = sources
        # 已解决的记录保持解决结论，不被扫描重新打开
        if record.status != 'resolved':
            record.status = status
        record.save()
    return record


def run_static_scan(rules=None, users=None, at=None):
    """
    静态扫描：对所有已发布的组合规则逐用户评估，生成/刷新冲突记录。
    只读用户数据，不修改任何用户的角色或权限。
    """
    at = at or timezone.now()
    if rules is None:
        rules = DutyConflictRule.objects.filter(rule_type='role_combo', status='published')
    if users is None:
        users = User.objects.filter(is_active=True)
    records = []
    for rule in rules:
        for user in users:
            sources = evaluate_role_combo_rule(rule, user, at)
            if sources:
                records.append(upsert_conflict_record(rule, user, sources, at))
    return records


# ==================== 创建人自审检查（业务阻断） ====================

def collect_creator_relations(user, object_type, obj):
    """
    收集用户与业务对象之间的创建关系（冲突来自哪些业务关系）。
    收件（stock_in）：登记人本人、或收件货物所属移交单位的创建人。
    """
    relations = []
    if object_type == 'stock_in':
        if obj.operator_id == user.id:
            relations.append({
                'type': 'business_relation',
                'relation': 'operator',
                'relation_name': '收件登记人',
                'object_type': 'stock_in',
                'object_id': obj.id,
            })
        unit = None
        if obj.goods_id and obj.goods.variety_id and obj.goods.variety.category_id:
            unit = obj.goods.variety.category.unit
        if unit and unit.created_by_id == user.id:
            relations.append({
                'type': 'business_relation',
                'relation': 'unit_creator',
                'relation_name': '移交单位创建人',
                'object_type': 'unit',
                'object_id': unit.id,
                'object_name': unit.name,
            })
    return relations


def _relation_label(relation):
    label = relation['relation_name']
    if relation.get('object_name'):
        label += f"「{relation['object_name']}」"
    return label


def evaluate_self_approval(user, object_type, obj, at=None):
    """
    创建人自审判断。返回判定字典：
    allowed / decision / rule / relations / exemption / basis。
    命中已发布规则时写入判断日志与冲突记录，留下依据。
    """
    at = at or timezone.now()
    relations = collect_creator_relations(user, object_type, obj)
    verdict = {
        'allowed': True, 'decision': 'allowed', 'rule': None,
        'relations': relations, 'exemption': None, 'basis': '',
    }
    if not relations:
        return verdict

    rules = list(DutyConflictRule.objects.filter(
        rule_type='self_approval', object_type=object_type, status='published'
    ))
    if not rules:
        return verdict

    rule = rules[0]
    verdict['rule'] = rule
    relation_text = '、'.join(_relation_label(r) for r in relations)

    if user.is_super_admin:
        # 超级管理员是系统信任根，不阻断，但留下绕过依据
        verdict['decision'] = 'bypassed'
        verdict['basis'] = (
            f"用户 {user.username} 是该对象的{relation_text}，命中规则「{rule.name}」，"
            f"因其为超级管理员，按系统策略绕过阻断。"
        )
        DutyCheckLog.objects.create(
            user=user, rule=rule, check_type='self_approval',
            object_type=object_type, object_id=obj.id,
            decision='bypassed', basis=verdict['basis'],
        )
        return verdict

    exemption = get_active_exemption(user, rule, at)
    if exemption:
        verdict['decision'] = 'allowed_exempted'
        verdict['exemption'] = exemption
        verdict['basis'] = (
            f"用户 {user.username} 是该对象的{relation_text}，命中规则「{rule.name}」；"
            f"存在有效紧急豁免（依据：{exemption.reason}，"
            f"失效时间：{timezone.localtime(exemption.expires_at):%Y-%m-%d %H:%M}），豁免放行。"
        )
        DutyCheckLog.objects.create(
            user=user, rule=rule, check_type='self_approval',
            object_type=object_type, object_id=obj.id,
            decision='allowed_exempted', basis=verdict['basis'], exemption=exemption,
        )
        upsert_conflict_record(rule, user, relations, at)
        return verdict

    verdict['allowed'] = False
    verdict['decision'] = 'blocked'
    verdict['basis'] = (
        f"用户 {user.username} 是该对象的{relation_text}，命中规则「{rule.name}」，"
        f"无有效紧急豁免，已阻止。"
    )
    DutyCheckLog.objects.create(
        user=user, rule=rule, check_type='self_approval',
        object_type=object_type, object_id=obj.id,
        decision='blocked', basis=verdict['basis'],
    )
    upsert_conflict_record(rule, user, relations, at)
    return verdict


# ==================== 影响预览与发布 ====================

def preview_rule_impact(rule, at=None):
    """
    影响预览：只读评估规则发布后会影响哪些既有用户，
    列出冲突来源（权限/业务关系），不写入任何数据。
    """
    at = at or timezone.now()
    if rule.rule_type == 'role_combo':
        affected = []
        for user in User.objects.filter(is_active=True).order_by('id'):
            sources = evaluate_role_combo_rule(rule, user, at)
            if sources:
                affected.append({
                    'user_id': user.id,
                    'username': user.username,
                    'role': user.role,
                    'sources': sources,
                    'exempted': bool(get_active_exemption(user, rule, at)),
                })
        return {'affected_count': len(affected), 'affected_users': affected}

    # self_approval：找出与在途高风险收件存在创建关系、且当前能审批的用户
    from apps.warehouse.models import StockIn
    affected = {}
    pending = StockIn.objects.filter(
        status='pending', is_high_risk=True
    ).select_related('goods__variety__category__unit', 'operator')
    for receipt in pending:
        candidate_ids = {receipt.operator_id}
        unit = None
        if receipt.goods_id and receipt.goods.variety_id and receipt.goods.variety.category_id:
            unit = receipt.goods.variety.category.unit
        if unit and unit.created_by_id:
            candidate_ids.add(unit.created_by_id)
        candidate_ids.discard(None)
        users = User.objects.in_bulk(candidate_ids)
        for uid, candidate in users.items():
            if not candidate.is_active:
                continue
            relations = collect_creator_relations(candidate, 'stock_in', receipt)
            if not relations:
                continue
            perms, _ = get_effective_permissions(candidate, at)
            entry = affected.setdefault(uid, {
                'user_id': uid,
                'username': candidate.username,
                'role': candidate.role,
                'holds_approve_permission': HIGH_RISK_APPROVE_PERMISSION in perms,
                'exempted': bool(get_active_exemption(candidate, rule, at)),
                'objects': [],
            })
            entry['objects'].append({
                'object_type': 'stock_in',
                'object_id': receipt.id,
                'relations': relations,
            })
    affected_users = list(affected.values())
    return {'affected_count': len(affected_users), 'affected_users': affected_users}


def publish_rule(rule, operator, confirm=False, at=None):
    """
    发布规则。存在受影响用户时必须显式确认；
    发布只生成冲突记录，绝不改写既有用户的角色或权限。
    返回 (是否已发布, 影响预览)。
    """
    at = at or timezone.now()
    impact = preview_rule_impact(rule, at)
    if impact['affected_count'] and not confirm:
        return False, impact

    rule.status = 'published'
    rule.published_by = operator
    rule.published_at = at
    rule.save(update_fields=['status', 'published_by', 'published_at', 'updated_at'])

    # 只登记冲突记录，绝不改写既有用户的角色或权限
    users = User.objects.in_bulk([u['user_id'] for u in impact['affected_users']])
    for item in impact['affected_users']:
        if rule.rule_type == 'role_combo':
            sources = item['sources']
        else:
            sources = []
            for obj in item['objects']:
                sources.extend(obj['relations'])
        upsert_conflict_record(rule, users[item['user_id']], sources, at)
    return True, impact


def check_delegation_conflicts(delegator, delegate, permission, at=None):
    """
    校验临时代理：模拟代理人获得该权限后是否违反已发布的组合规则。
    返回冲突列表，每项含规则与来源说明；存在有效豁免的冲突不返回。
    """
    at = at or timezone.now()
    conflicts = []
    perms, sources = get_effective_permissions(delegate, at)
    perms = set(perms) | {permission}
    sources = {k: list(v) for k, v in sources.items()}
    sources.setdefault(permission, []).append({
        'type': 'delegation',
        'delegation_id': None,
        'delegator': delegator.username,
        'reason': '（本次新增代理）',
    })
    rules = DutyConflictRule.objects.filter(rule_type='role_combo', status='published')
    for rule in rules:
        needed = [rule.permission_a, rule.permission_b]
        if not all(p in perms for p in needed):
            continue
        if get_active_exemption(delegate, rule, at):
            continue
        conflict_sources = []
        for perm in needed:
            conflict_sources.extend(_permission_source_entries(perm, sources[perm]))
        conflicts.append({'rule': rule, 'sources': conflict_sources})
    return conflicts
