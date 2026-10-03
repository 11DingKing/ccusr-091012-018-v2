"""
职责冲突管理视图
"""
import logging
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from apps.core.response import success_response, error_response
from .engine import get_object_registry, scan_rule_impact, scan_standing_conflicts
from .models import ConflictCheckRecord, Delegation, DutyConflictRule, EmergencyExemption
from .permissions import PERMISSIONS, ROLE_PERMISSIONS
from .serializers import (
    ConflictCheckRecordSerializer,
    DelegationCreateSerializer, DelegationSerializer,
    DutyConflictRuleCreateSerializer, DutyConflictRuleSerializer,
    EmergencyExemptionCreateSerializer, EmergencyExemptionSerializer,
)

logger = logging.getLogger('apps')


def _paginate(request, queryset, serializer_class):
    """按项目既有风格手动分页"""
    page = int(request.query_params.get('page', 1))
    page_size = int(request.query_params.get('page_size', 10))
    start = (page - 1) * page_size
    end = start + page_size
    total = queryset.count()
    serializer = serializer_class(queryset[start:end], many=True)
    return success_response(data={
        'list': serializer.data,
        'total': total,
        'page': page,
        'page_size': page_size,
    })


def _first_error(errors):
    first = list(errors.values())[0]
    if isinstance(first, list):
        return str(first[0])
    return str(first)


class SodAdminRequiredMixin:
    """职责冲突管理仅对管理员开放"""

    def check_admin(self, request):
        if not request.user.is_admin:
            return error_response(message='无权限访问', code=403)
        return None


# ==================== 权限目录 ====================

class PermissionCatalogView(SodAdminRequiredMixin, APIView):
    """权限目录：全部权限代码及角色映射，供规则配置与冲突溯源使用"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        return success_response(data={
            'permissions': [
                {'code': code, 'label': label} for code, label in PERMISSIONS.items()
            ],
            'role_permissions': [
                {'role': role, 'permissions': permissions}
                for role, permissions in ROLE_PERMISSIONS.items()
            ],
            'object_types': [
                {
                    'object_type': object_type,
                    'label': config['label'],
                    'creator_paths': [
                        {'path': path, 'label': label}
                        for path, label in config['creator_paths'].items()
                    ],
                }
                for object_type, config in get_object_registry().items()
            ],
        })


# ==================== 冲突规则 ====================

class DutyConflictRuleListView(SodAdminRequiredMixin, APIView):
    """职责冲突规则列表与创建"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        queryset = DutyConflictRule.objects.all().order_by('-created_at')
        status_param = request.query_params.get('status')
        if status_param:
            queryset = queryset.filter(status=status_param)
        return _paginate(request, queryset, DutyConflictRuleSerializer)

    def post(self, request):
        """创建规则（草稿状态，发布前必须预览影响）"""
        denied = self.check_admin(request)
        if denied:
            return denied
        serializer = DutyConflictRuleCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        rule = DutyConflictRule.objects.create(
            name=data['name'],
            rule_type=data['rule_type'],
            permissions=data.get('permissions') or [],
            object_type=data.get('object_type', ''),
            action=data.get('action', ''),
            creator_path=data.get('creator_path', ''),
            severity=data['severity'],
            description=data.get('description', ''),
            created_by=request.user,
        )
        logger.info(f"User {request.user.username} created sod rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='创建成功，发布前请先预览影响')


class DutyConflictRuleDetailView(SodAdminRequiredMixin, APIView):
    """职责冲突规则详情、更新与删除"""
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        return DutyConflictRule.objects.filter(pk=pk).first()

    def get(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = self.get_object(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        return success_response(data=DutyConflictRuleSerializer(rule).data)

    def put(self, request, pk):
        """更新规则，仅草稿可修改"""
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = self.get_object(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'draft':
            return error_response(message='仅草稿状态的规则可以修改')

        serializer = DutyConflictRuleCreateSerializer(data=request.data, context={'instance': rule})
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        rule.name = data['name']
        rule.rule_type = data['rule_type']
        rule.permissions = data.get('permissions') or []
        rule.object_type = data.get('object_type', '')
        rule.action = data.get('action', '')
        rule.creator_path = data.get('creator_path', '')
        rule.severity = data['severity']
        rule.description = data.get('description', '')
        rule.save()
        logger.info(f"User {request.user.username} updated sod rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='更新成功')

    def delete(self, request, pk):
        """删除规则，仅草稿可删除"""
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = self.get_object(pk)
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'draft':
            return error_response(message='仅草稿状态的规则可以删除，已发布规则请停用')
        name = rule.name
        rule.delete()
        logger.info(f"User {request.user.username} deleted sod rule {name}")
        return success_response(message='删除成功')


class DutyConflictRulePreviewView(SodAdminRequiredMixin, APIView):
    """规则影响预览

    发布前评估规则影响范围：哪些现有用户将构成冲突、冲突来自哪些
    权限和业务关系。预览只读，不修改任何数据。
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = DutyConflictRule.objects.filter(pk=pk).first()
        if not rule:
            return error_response(message='规则不存在', code=404)
        impact = scan_rule_impact(rule)
        logger.info(
            f"User {request.user.username} previewed sod rule {rule.name}: "
            f"{impact['affected_user_count']} users affected"
        )
        return success_response(data=impact)


class DutyConflictRulePublishView(SodAdminRequiredMixin, APIView):
    """发布规则

    发布时自动执行一次影响评估并存入 publish_impact 快照留痕。
    发布不会改写任何已有用户的角色或权限，冲突用户以存量冲突形式
    呈现给管理员处置。
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = DutyConflictRule.objects.filter(pk=pk).first()
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'draft':
            return error_response(message='仅草稿状态的规则可以发布')

        impact = scan_rule_impact(rule)
        rule.status = 'published'
        rule.published_by = request.user
        rule.published_at = timezone.now()
        rule.publish_impact = {
            **impact,
            'evaluated_at': rule.published_at.isoformat(),
            'evaluated_by': request.user.username,
        }
        rule.save()
        logger.warning(
            f"User {request.user.username} published sod rule {rule.name}: "
            f"{impact['affected_user_count']} existing users in conflict (kept unchanged)"
        )
        return success_response(
            data=DutyConflictRuleSerializer(rule).data,
            message=f'发布成功，{impact["affected_user_count"]} 个现有用户存在冲突，其权限保持不变，请前往冲突列表处置'
        )


class DutyConflictRuleDisableView(SodAdminRequiredMixin, APIView):
    """停用规则"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        rule = DutyConflictRule.objects.filter(pk=pk).first()
        if not rule:
            return error_response(message='规则不存在', code=404)
        if rule.status != 'published':
            return error_response(message='仅已发布的规则可以停用')
        rule.status = 'disabled'
        rule.save(update_fields=['status', 'updated_at'])
        logger.info(f"User {request.user.username} disabled sod rule {rule.name}")
        return success_response(data=DutyConflictRuleSerializer(rule).data, message='停用成功')


# ==================== 冲突总览与判定记录 ====================

class ConflictOverviewView(SodAdminRequiredMixin, APIView):
    """冲突总览

    管理员在此看到当前全部职责冲突及其来源：
    - standing_conflicts：已发布权限组合规则下的存量冲突，
      每个冲突都列出命中的权限及其来源（角色/临时代理）；
    - recent_records：最近的业务自审判定记录（阻止/豁免放行），
      basis 中包含业务关系、权限来源与豁免依据。
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        standing = scan_standing_conflicts()
        records = ConflictCheckRecord.objects.all().order_by('-created_at')[:50]
        return success_response(data={
            'standing_conflicts': standing,
            'standing_conflict_count': len(standing),
            'recent_records': ConflictCheckRecordSerializer(records, many=True).data,
        })


class ConflictCheckRecordListView(SodAdminRequiredMixin, APIView):
    """冲突判定记录列表（留痕查询）"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        queryset = ConflictCheckRecord.objects.all().order_by('-created_at')
        result = request.query_params.get('result')
        if result:
            queryset = queryset.filter(result=result)
        user_id = request.query_params.get('user')
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        rule_id = request.query_params.get('rule')
        if rule_id:
            queryset = queryset.filter(rule_id=rule_id)
        return _paginate(request, queryset, ConflictCheckRecordSerializer)


# ==================== 临时代理 ====================

class DelegationListView(SodAdminRequiredMixin, APIView):
    """临时代理列表与登记"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        queryset = Delegation.objects.all().order_by('-created_at')
        return _paginate(request, queryset, DelegationSerializer)

    def post(self, request):
        """登记临时代理（必须填写代理依据）"""
        denied = self.check_admin(request)
        if denied:
            return denied
        serializer = DelegationCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        delegation = Delegation.objects.create(
            delegator_id=data['delegator'],
            delegate_id=data['delegate'],
            permissions=data['permissions'],
            reason=data['reason'],
            start_at=data['start_at'],
            end_at=data['end_at'],
            created_by=request.user,
        )
        logger.info(
            f"User {request.user.username} created delegation "
            f"{delegation.delegator_id}->{delegation.delegate_id} perms={delegation.permissions}"
        )
        return success_response(data=DelegationSerializer(delegation).data, message='代理登记成功')


class DelegationRevokeView(SodAdminRequiredMixin, APIView):
    """撤销临时代理"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        delegation = Delegation.objects.filter(pk=pk).first()
        if not delegation:
            return error_response(message='代理记录不存在', code=404)
        if not delegation.is_active:
            return error_response(message='该代理已撤销')
        delegation.is_active = False
        delegation.save(update_fields=['is_active'])
        logger.info(f"User {request.user.username} revoked delegation {delegation.id}")
        return success_response(data=DelegationSerializer(delegation).data, message='代理已撤销')


# ==================== 紧急豁免 ====================

class EmergencyExemptionListView(SodAdminRequiredMixin, APIView):
    """紧急豁免列表与登记"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        denied = self.check_admin(request)
        if denied:
            return denied
        queryset = EmergencyExemption.objects.all().order_by('-created_at')
        return _paginate(request, queryset, EmergencyExemptionSerializer)

    def post(self, request):
        """登记紧急豁免（必须填写豁免依据，不能为本人批准）"""
        denied = self.check_admin(request)
        if denied:
            return denied
        serializer = EmergencyExemptionCreateSerializer(
            data=request.data, context={'request_user': request.user}
        )
        if not serializer.is_valid():
            return error_response(message=_first_error(serializer.errors))

        data = serializer.validated_data
        exemption = EmergencyExemption.objects.create(
            user_id=data['user'],
            rule=data['rule_obj'],
            reason=data['reason'],
            approved_by=request.user,
            start_at=data['start_at'],
            end_at=data['end_at'],
        )
        logger.warning(
            f"User {request.user.username} granted exemption {exemption.id} "
            f"to user {exemption.user_id} on rule {exemption.rule_id}"
        )
        return success_response(data=EmergencyExemptionSerializer(exemption).data, message='豁免登记成功')


class EmergencyExemptionRevokeView(SodAdminRequiredMixin, APIView):
    """撤销紧急豁免"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        denied = self.check_admin(request)
        if denied:
            return denied
        exemption = EmergencyExemption.objects.filter(pk=pk).first()
        if not exemption:
            return error_response(message='豁免记录不存在', code=404)
        if not exemption.is_active:
            return error_response(message='该豁免已撤销')
        exemption.is_active = False
        exemption.save(update_fields=['is_active'])
        logger.info(f"User {request.user.username} revoked exemption {exemption.id}")
        return success_response(data=EmergencyExemptionSerializer(exemption).data, message='豁免已撤销')
