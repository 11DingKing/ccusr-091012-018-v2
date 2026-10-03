"""
职责冲突判定引擎

判定原则：
- 有效权限 = 角色权限 ∪ 生效中的临时代理授予的权限，每个权限都记录来源；
- 静态组合冲突（role_combo）：用户同时拥有规则中的全部权限即构成冲突，
  用于影响预览与存量冲突报告，不拦截具体操作；
- 业务自审冲突（self_approval）：业务对象的创建人（含其临时代理人）
  不得对该对象执行受控动作，触发即拦截并留痕；
- 紧急豁免在生效期内可放行，但每次放行同样留痕并记录豁免依据。
"""
import logging

from django.apps import apps as django_apps
from django.utils import timezone

from apps.authentication.models import User
from apps.core.exceptions import PermissionException
from .models import ConflictCheckRecord, Delegation, DutyConflictRule, EmergencyExemption
from .permissions import permission_label, role_permissions

logger = logging.getLogger('apps')


# 业务对象注册表：自审规则如何定位创建人、如何取待处理对象
OBJECT_REGISTRY = {
    'stock_in': {
        'label': '收件记录',
        'model': 'StockIn',
        'creator_paths': {
            'operator': '收件登记人',
            'goods.variety.category.unit.created_by': '移交单位创建人',
        },
        'pending_status': 'pending',
    },
}


def get_object_registry():
    """业务对象注册表（含模型与待处理对象查询，惰性加载避免循环导入）"""
    registry = {}
    for object_type, config in OBJECT_REGISTRY.items():
        model = django_apps.get_model('warehouse', config['model'])
        registry[object_type] = {
            **config,
            'model_class': model,
            'pending_objects': lambda m=model, s=config['pending_status']: m.objects.filter(status=s),
        }
    return registry


def resolve_path(obj, path):
    """沿点分路径解析对象属性，任一环节为空则返回 None"""
    current = obj
    for part in path.split('.'):
        if current is None:
            return None
        current = getattr(current, part, None)
    return current


def get_active_delegations_to(user, at=None):
    """用户当前生效的临时代理（作为代理人）"""
    at = at or timezone.now()
    return Delegation.objects.filter(
        delegate=user, is_active=True, start_at__lte=at, end_at__gte=at
    ).select_related('delegator')


def get_effective_permissions(user, at=None):
    """有效权限及来源

    返回 {权限代码: [来源, ...]}，来源形如：
    - {'type': 'role', 'role': 'admin', 'role_display': '管理员'}
    - {'type': 'delegation', 'delegation_id': 1, 'delegator_id': 2, 'delegator': 'wang', 'end_at': '...'}
    """
    at = at or timezone.now()
    effective = {}
    for code in role_permissions(user.role):
        effective.setdefault(code, []).append({
            'type': 'role',
            'role': user.role,
            'role_display': user.get_role_display(),
        })
    for delegation in get_active_delegations_to(user, at):
        for code in delegation.permissions or []:
            effective.setdefault(code, []).append({
                'type': 'delegation',
                'delegation_id': delegation.id,
                'delegator_id': delegation.delegator_id,
                'delegator': delegation.delegator.username,
                'end_at': delegation.end_at.isoformat(),
            })
    return effective


def has_permission(user, code, at=None):
    """用户当前是否持有指定权限（含临时代理获得）"""
    return code in get_effective_permissions(user, at)


# ==================== 静态组合冲突 ====================

def evaluate_role_combo(rule, user, at=None):
    """评估单个用户是否命中权限组合冲突规则，命中返回冲突详情，否则 None"""
    required = rule.permissions or []
    if len(required) < 2:
        return None
    effective = get_effective_permissions(user, at)
    if not all(code in effective for code in required):
        return None
    return {
        'user': {'id': user.id, 'username': user.username, 'role': user.role},
        'matched_permissions': [
            {'code': code, 'label': permission_label(code), 'sources': effective[code]}
            for code in required
        ],
    }


def scan_role_combo_impact(rule, at=None):
    """权限组合规则影响预览：扫描全部启用用户，列出将构成冲突的用户"""
    affected = []
    for user in User.objects.filter(is_active=True).order_by('id'):
        violation = evaluate_role_combo(rule, user, at)
        if violation:
            affected.append(violation)
    return {
        'rule_type': 'role_combo',
        'affected_user_count': len(affected),
        'affected_users': affected,
    }


# ==================== 业务自审冲突 ====================

def scan_self_approval_impact(rule, at=None):
    """自审规则影响预览

    扫描现有待处理业务对象，找出"创建了对象、且持有受控动作权限"的用户：
    规则发布后，这些用户将无法再审批自己创建的对象。
    """
    registry = get_object_registry()
    config = registry.get(rule.object_type)
    if not config or not rule.creator_path:
        return {'rule_type': 'self_approval', 'affected_user_count': 0, 'affected_users': []}

    at = at or timezone.now()
    by_user = {}
    for obj in config['pending_objects']().order_by('id'):
        creator = resolve_path(obj, rule.creator_path)
        if creator is None:
            continue
        entry = by_user.setdefault(creator.id, {'user': creator, 'objects': []})
        entry['objects'].append({'id': obj.id, 'label': str(obj)})

    affected = []
    for entry in by_user.values():
        user = entry['user']
        effective = get_effective_permissions(user, at)
        if rule.action not in effective:
            continue
        affected.append({
            'user': {'id': user.id, 'username': user.username, 'role': user.role},
            'action': rule.action,
            'action_label': permission_label(rule.action),
            'action_sources': effective[rule.action],
            'creator_path': rule.creator_path,
            'creator_path_label': config['creator_paths'].get(rule.creator_path, rule.creator_path),
            'pending_object_count': len(entry['objects']),
            'pending_objects': entry['objects'][:20],
        })
    affected.sort(key=lambda item: item['user']['id'])
    return {
        'rule_type': 'self_approval',
        'affected_user_count': len(affected),
        'affected_users': affected,
    }


def scan_rule_impact(rule, at=None):
    """规则影响预览入口"""
    if rule.rule_type == 'role_combo':
        return scan_role_combo_impact(rule, at)
    return scan_self_approval_impact(rule, at)


def check_business_action(user, action, obj, object_type, object_label=''):
    """业务动作自审检查

    对已发布的自审规则逐一判定：
    - 无冲突：正常返回；
    - 有冲突且存在生效的紧急豁免：写入"豁免放行"记录后放行；
    - 有冲突且无豁免：写入"已阻止"记录并抛出 PermissionException。
    """
    now = timezone.now()
    rules = DutyConflictRule.objects.filter(
        status='published',
        rule_type='self_approval',
        object_type=object_type,
        action=action,
    )
    registry = get_object_registry()
    config = registry.get(object_type, {})

    for rule in rules:
        creator = resolve_path(obj, rule.creator_path)
        if creator is None:
            continue

        relation = _match_creator_relation(user, creator, rule, config, now)
        if relation is None:
            continue

        basis = _build_basis(user, rule, action, relation, now)
        exemption = EmergencyExemption.objects.filter(
            user=user, rule=rule, is_active=True, start_at__lte=now, end_at__gte=now
        ).select_related('approved_by').first()

        if exemption:
            basis['exemption'] = {
                'id': exemption.id,
                'reason': exemption.reason,
                'approved_by': exemption.approved_by.username if exemption.approved_by else None,
                'end_at': exemption.end_at.isoformat(),
            }
            _write_record(user, rule, action, obj, object_type, object_label, 'exempted', basis)
            logger.warning(
                f"SoD exempted: user={user.username} rule={rule.name} "
                f"action={action} object={object_type}#{obj.pk} exemption={exemption.id}"
            )
            continue

        _write_record(user, rule, action, obj, object_type, object_label, 'blocked', basis)
        logger.warning(
            f"SoD blocked: user={user.username} rule={rule.name} "
            f"action={action} object={object_type}#{obj.pk}"
        )
        raise PermissionException(
            f'职责冲突：{rule.name}（{relation["description"]}），操作已阻止并留痕'
        )


def _match_creator_relation(user, creator, rule, config, at):
    """判断用户与业务对象创建人之间是否构成需回避的关系"""
    path_label = config.get('creator_paths', {}).get(rule.creator_path, rule.creator_path)
    if creator.id == user.id:
        return {
            'kind': 'self',
            'creator_path': rule.creator_path,
            'creator_path_label': path_label,
            'creator': {'id': creator.id, 'username': creator.username},
            'description': f'本人即为{path_label}',
        }
    # 临时代理纳入判断：用户持有创建人授予的生效代理，视同创建人本人行事
    delegation = Delegation.objects.filter(
        delegator=creator, delegate=user, is_active=True,
        start_at__lte=at, end_at__gte=at,
    ).first()
    if delegation:
        return {
            'kind': 'delegation',
            'creator_path': rule.creator_path,
            'creator_path_label': path_label,
            'creator': {'id': creator.id, 'username': creator.username},
            'delegation': {
                'id': delegation.id,
                'delegator': creator.username,
                'end_at': delegation.end_at.isoformat(),
            },
            'description': f'持有{path_label}（{creator.username}）的临时代理',
        }
    return None


def _build_basis(user, rule, action, relation, at):
    """组装判定依据：命中的业务关系 + 用户动作权限来源 + 生效代理"""
    effective = get_effective_permissions(user, at)
    return {
        'rule': {
            'id': rule.id,
            'name': rule.name,
            'rule_type': rule.rule_type,
            'severity': rule.severity,
        },
        'relation': relation,
        'action': action,
        'action_label': permission_label(action),
        'action_sources': effective.get(action, []),
        'active_delegations': [
            {
                'id': d.id,
                'delegator': d.delegator.username,
                'permissions': d.permissions,
                'end_at': d.end_at.isoformat(),
            }
            for d in get_active_delegations_to(user, at)
        ],
    }


def _write_record(user, rule, action, obj, object_type, object_label, result, basis):
    """写入冲突判定记录"""
    return ConflictCheckRecord.objects.create(
        user=user,
        rule=rule,
        action=action,
        object_type=object_type,
        object_id=getattr(obj, 'pk', None),
        object_label=object_label or str(obj),
        result=result,
        basis=basis,
    )


# ==================== 存量冲突报告 ====================

def scan_standing_conflicts(at=None):
    """扫描全部已发布的权限组合规则，返回当前存量冲突（不修改任何用户）"""
    rules = DutyConflictRule.objects.filter(status='published', rule_type='role_combo')
    conflicts = []
    for rule in rules:
        for user in User.objects.filter(is_active=True).order_by('id'):
            violation = evaluate_role_combo(rule, user, at)
            if violation:
                conflicts.append({
                    'rule': {
                        'id': rule.id,
                        'name': rule.name,
                        'rule_type': rule.rule_type,
                        'severity': rule.severity,
                    },
                    **violation,
                })
    return conflicts
