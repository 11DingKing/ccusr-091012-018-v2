"""
职责冲突管理视图
"""
import logging
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from apps.core.response import success_response, error_response
from .models import (
    DutyConflictRule, DutyDelegation, DutyExemption,
    DutyConflictRecord, DutyCheckLog,
)
from .permissions import PERMISSION_CATALOG, ROLE_PERMISSIONS
from .serializers import (
    DutyConflictRuleSerializer, DutyConflictRuleCreateSerializer,
    DutyDelegationSerializer, DutyDelegationCreateSerializer,
    DutyExemptionSerializer, DutyExemptionCreateSerializer,
    DutyConflictRecordSerializer, DutyCheckLogSerializer,
)
from . import services

logger = logging.getLogger('apps')


def _admin_required(request):
    """职责冲突规则仅管理员可管理"""
    if not request.user.is_admin:
        return error_response(message='无权限操作', code=403)
    return None


def _first_error(errors):
    first_error = list(errors.values())[0]
    if isinstance(first_error, list):
        first_error = first_error[0]
    return str(first_error)


def _paginate(request, queryset):
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    start = (page - 1) * page_size
    end = start + page_size
    return queryset.count(), queryset[start:end], page, page_size


# ==================== 权限目录 ====================

class PermissionCatalogView(APIView):
    """权限目录与角色权限映射（说明冲突来自哪些权限）"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied
        return success_response(data={
            'permissions': [
                {'code': code, 'name': name}
                for code, name in PERMISSION_CATALOG.items()
            ],
            'role_permissions': {
                role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()
            },
        })


# ==================== 冲突规则 ====================

class RuleListView(APIView):
    """职责冲突规则列表"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied

        queryset = DutyConflictRule.objects.all()
        rule_type = request.query_params.get('rule_type')
        status = request.query_params.get('status')
        if rule_type:
            queryset = queryset.filter(rule_type=rule_type)
        if status:
            queryset = queryset.filter(status=status)

        total, rules, page, page_size = _paginate(request, queryset)
        serializer = DutyConflictRuleSerializer(rules, many=True)
        return success_response(data={
            'list': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size
        })

    def post(self, request):
        """创建规则（草稿状态，发布前需先影响预览）"""
        denied = _admin_required(request)
        if denied:
            return denied

        serializer = DutyConflictRuleCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        rule = DutyConflictRule.objects.create(
            created_by=request.user,
            **serializer.validated_data
        )
        logger.info(f"User {request.user.username} created duty conflict rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='创建成功')


class RuleDetailView(APIView):
    """职责冲突规则详情"""
    permission_classes = [IsAuthenticated]

    def _get_rule(self, pk):
        try:
            return DutyConflictRule.objects.get(pk=pk)
        except DutyConflictRule.DoesNotExist:
            return None

    def get(self, request, pk):
        denied = _admin_required(request)
        if denied:
            return denied
        rule = self._get_rule(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        return success_response(data=DutyConflictRuleSerializer(rule).data)

    def put(self, request, pk):
        """更新规则（仅草稿可修改，已发布规则先停用再调整）"""
        denied = _admin_required(request)
        if denied:
            return denied
        rule = self._get_rule(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'draft':
            return error_response(message='仅草稿状态的规则可以修改')

        serializer = DutyConflictRuleCreateSerializer(
            data=request.data, context={'instance': rule}
        )
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        for field, value in serializer.validated_data.items():
            setattr(rule, field, value)
        rule.save()
        logger.info(f"User {request.user.username} updated duty conflict rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='更新成功')

    def delete(self, request, pk):
        """删除规则（仅草稿可删除）"""
        denied = _admin_required(request)
        if denied:
            return denied
        rule = self._get_rule(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'draft':
            return error_response(message='仅草稿状态的规则可以删除')

        name = rule.name
        rule.delete()
        logger.info(f"User {request.user.username} deleted duty conflict rule {name}")
        return success_response(message='删除成功')


class RulePreviewView(APIView):
    """影响预览：发布前只读评估受影响的既有用户，不写入任何数据"""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            rule = DutyConflictRule.objects.get(pk=pk)
        except DutyConflictRule.DoesNotExist:
            return error_response(message='规则不存在', code=404)

        impact = services.preview_rule_impact(rule)
        return success_response(data={
            'rule_id': rule.id,
            'rule_name': rule.name,
            'rule_status': rule.status,
            **impact,
        })


class RulePublishView(APIView):
    """
    发布规则。发布只生成冲突记录供管理员处置，
    绝不改写既有用户的角色或权限；存在受影响用户时必须显式确认。
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            rule = DutyConflictRule.objects.get(pk=pk)
        except DutyConflictRule.DoesNotExist:
            return error_response(message='规则不存在', code=404)
        if rule.status == 'published':
            return error_response(message='规则已发布，无需重复发布')

        confirm = request.data.get('confirm') is True
        published, impact = services.publish_rule(rule, request.user, confirm=confirm)
        if not published:
            return error_response(
                message=f"发布将影响 {impact['affected_count']} 个既有用户，请确认影响预览后携带 confirm=true 重新发布",
                data={'requires_confirmation': True, **impact}
            )

        logger.info(
            f"User {request.user.username} published duty conflict rule {rule.name}, "
            f"affected {impact['affected_count']} users"
        )
        return success_response(data={
            'rule': DutyConflictRuleSerializer(rule).data,
            'affected_count': impact['affected_count'],
            'affected_users': impact['affected_users'],
        }, message='发布成功，既有用户权限未被改动，冲突已登记待处置')


class RuleDisableView(APIView):
    """停用规则"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            rule = DutyConflictRule.objects.get(pk=pk)
        except DutyConflictRule.DoesNotExist:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'published':
            return error_response(message='仅已发布的规则可以停用')

        rule.status = 'disabled'
        rule.save(update_fields=['status', 'updated_at'])
        logger.info(f"User {request.user.username} disabled duty conflict rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='停用成功')


# ==================== 静态扫描与冲突记录 ====================

class ScanView(APIView):
    """静态扫描：按已发布的组合规则检查所有既有用户，生成冲突记录"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        denied = _admin_required(request)
        if denied:
            return denied
        records = services.run_static_scan()
        logger.info(
            f"User {request.user.username} ran duty conflict scan, "
            f"{len(records)} conflict records"
        )
        return success_response(data={
            'conflict_count': len(records),
            'open_count': len([r for r in records if r.status == 'open']),
            'exempted_count': len([r for r in records if r.status == 'exempted']),
        }, message=f'扫描完成，发现 {len(records)} 条冲突')


class ConflictRecordListView(APIView):
    """冲突记录列表：展示冲突来自哪些权限和业务关系"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied

        queryset = DutyConflictRecord.objects.select_related('rule', 'user', 'resolved_by')
        status = request.query_params.get('status')
        rule_id = request.query_params.get('rule')
        user_id = request.query_params.get('user')
        if status:
            queryset = queryset.filter(status=status)
        if rule_id:
            queryset = queryset.filter(rule_id=rule_id)
        if user_id:
            queryset = queryset.filter(user_id=user_id)

        total, records, page, page_size = _paginate(request, queryset)
        serializer = DutyConflictRecordSerializer(records, many=True)
        return success_response(data={
            'list': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size
        })


class ConflictRecordResolveView(APIView):
    """处置冲突记录（需说明处理依据）"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            record = DutyConflictRecord.objects.get(pk=pk)
        except DutyConflictRecord.DoesNotExist:
            return error_response(message='冲突记录不存在', code=404)

        note = request.data.get('resolution_note', '')
        if not note:
            return error_response(message='请填写处理说明')

        record.status = 'resolved'
        record.resolved_by = request.user
        record.resolved_at = timezone.now()
        record.resolution_note = note
        record.save(update_fields=[
            'status', 'resolved_by', 'resolved_at', 'resolution_note', 'last_seen_at'
        ])
        logger.info(
            f"User {request.user.username} resolved duty conflict record {record.id}: {note}"
        )
        return success_response(
            data=DutyConflictRecordSerializer(record).data, message='处理成功'
        )


# ==================== 临时代理 ====================

class DelegationListView(APIView):
    """临时代理列表"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied

        queryset = DutyDelegation.objects.select_related('delegator', 'delegate', 'created_by')
        total, delegations, page, page_size = _paginate(request, queryset)
        serializer = DutyDelegationSerializer(delegations, many=True)
        return success_response(data={
            'list': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size
        })

    def post(self, request):
        """
        创建临时代理。创建前模拟代理人获得该权限后的组合冲突，
        命中已发布规则且无有效豁免时拒绝建立代理。
        """
        denied = _admin_required(request)
        if denied:
            return denied

        serializer = DutyDelegationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        delegator = data['delegator_obj']
        delegate = data['delegate_obj']
        permission = data['permission']

        # 只能转授自己角色持有的权限
        if permission not in services.get_effective_permissions(delegator)[0] \
                and not delegator.is_super_admin:
            return error_response(message='委托人未持有该权限，无法转授')

        conflicts = services.check_delegation_conflicts(delegator, delegate, permission)
        if conflicts:
            return error_response(
                message='该代理将使代理人同时持有冲突权限，且存在已发布规则，请调整代理或先登记紧急豁免',
                data={'conflicts': [
                    {
                        'rule_id': c['rule'].id,
                        'rule_name': c['rule'].name,
                        'sources': c['sources'],
                    } for c in conflicts
                ]}
            )

        delegation = DutyDelegation.objects.create(
            delegator=delegator,
            delegate=delegate,
            permission=permission,
            reason=data['reason'],
            start_at=data['start_at'],
            end_at=data['end_at'],
            created_by=request.user,
        )
        logger.info(
            f"User {request.user.username} created delegation {delegation.id}: "
            f"{delegator.username} -> {delegate.username} ({permission})"
        )
        return success_response(
            data=DutyDelegationSerializer(delegation).data, message='创建成功'
        )


class DelegationDetailView(APIView):
    """临时代理详情"""
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        """撤销代理（保留记录作为依据，仅置为停用）"""
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            delegation = DutyDelegation.objects.get(pk=pk)
        except DutyDelegation.DoesNotExist:
            return error_response(message='代理记录不存在', code=404)
        if not delegation.is_active:
            return error_response(message='该代理已撤销')

        delegation.is_active = False
        delegation.save(update_fields=['is_active'])
        logger.info(f"User {request.user.username} revoked delegation {delegation.id}")
        return success_response(message='撤销成功')


# ==================== 紧急豁免 ====================

class ExemptionListView(APIView):
    """紧急豁免列表"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied

        queryset = DutyExemption.objects.select_related('user', 'rule', 'created_by')
        total, exemptions, page, page_size = _paginate(request, queryset)
        serializer = DutyExemptionSerializer(exemptions, many=True)
        return success_response(data={
            'list': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size
        })

    def post(self, request):
        """创建紧急豁免（必须填写依据，到期自动失效）"""
        denied = _admin_required(request)
        if denied:
            return denied

        serializer = DutyExemptionCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        exemption = DutyExemption.objects.create(
            user_id=data['user'],
            rule_id=data['rule'],
            reason=data['reason'],
            expires_at=data['expires_at'],
            created_by=request.user,
        )
        logger.info(
            f"User {request.user.username} created exemption {exemption.id}: "
            f"user={exemption.user_id} rule={exemption.rule_id}"
        )
        return success_response(
            data=DutyExemptionSerializer(exemption).data, message='创建成功'
        )


class ExemptionDetailView(APIView):
    """紧急豁免详情"""
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        """撤销豁免（保留记录作为依据，仅置为停用）"""
        denied = _admin_required(request)
        if denied:
            return denied
        try:
            exemption = DutyExemption.objects.get(pk=pk)
        except DutyExemption.DoesNotExist:
            return error_response(message='豁免记录不存在', code=404)
        if not exemption.is_active:
            return error_response(message='该豁免已撤销')

        exemption.is_active = False
        exemption.save(update_fields=['is_active'])
        logger.info(f"User {request.user.username} revoked exemption {exemption.id}")
        return success_response(message='撤销成功')


# ==================== 判断日志 ====================

class CheckLogListView(APIView):
    """职责冲突判断日志：业务阻断/豁免放行的依据"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = _admin_required(request)
        if denied:
            return denied

        queryset = DutyCheckLog.objects.select_related('user', 'rule', 'exemption')
        decision = request.query_params.get('decision')
        user_id = request.query_params.get('user')
        if decision:
            queryset = queryset.filter(decision=decision)
        if user_id:
            queryset = queryset.filter(user_id=user_id)

        total, logs, page, page_size = _paginate(request, queryset)
        serializer = DutyCheckLogSerializer(logs, many=True)
        return success_response(data={
            'list': serializer.data,
            'total': total,
            'page': page,
            'page_size': page_size
        })
