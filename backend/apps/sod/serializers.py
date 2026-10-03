"""
职责冲突序列化器
"""
from rest_framework import serializers
from django.utils import timezone
from apps.authentication.models import User
from .models import (
    DutyConflictRule, DutyDelegation, DutyExemption,
    DutyConflictRecord, DutyCheckLog,
)
from .permissions import PERMISSION_CATALOG


class DutyConflictRuleSerializer(serializers.ModelSerializer):
    """职责冲突规则序列化器"""
    rule_type_display = serializers.CharField(source='get_rule_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    object_type_display = serializers.CharField(source='get_object_type_display', read_only=True)
    permission_a_name = serializers.SerializerMethodField()
    permission_b_name = serializers.SerializerMethodField()
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    published_by_name = serializers.CharField(source='published_by.username', read_only=True)

    class Meta:
        model = DutyConflictRule
        fields = [
            'id', 'name', 'description', 'rule_type', 'rule_type_display',
            'permission_a', 'permission_a_name', 'permission_b', 'permission_b_name',
            'object_type', 'object_type_display', 'severity', 'severity_display',
            'status', 'status_display', 'published_by', 'published_by_name',
            'published_at', 'created_by', 'created_by_name', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'status', 'published_by', 'published_at', 'created_at', 'updated_at']

    def get_permission_a_name(self, obj):
        return PERMISSION_CATALOG.get(obj.permission_a, obj.permission_a) if obj.permission_a else ''

    def get_permission_b_name(self, obj):
        return PERMISSION_CATALOG.get(obj.permission_b, obj.permission_b) if obj.permission_b else ''


class DutyConflictRuleCreateSerializer(serializers.Serializer):
    """职责冲突规则创建/更新序列化器"""
    name = serializers.CharField(min_length=1, max_length=50, required=True, error_messages={
        'required': '请输入规则名称',
        'blank': '规则名称不能为空',
        'max_length': '规则名称最多50个字',
    })
    description = serializers.CharField(max_length=200, required=False, allow_blank=True, default='')
    rule_type = serializers.ChoiceField(
        choices=DutyConflictRule.RULE_TYPE_CHOICES, required=True,
        error_messages={'required': '请选择规则类型', 'invalid_choice': '无效的规则类型'}
    )
    permission_a = serializers.CharField(max_length=50, required=False, allow_blank=True, default='')
    permission_b = serializers.CharField(max_length=50, required=False, allow_blank=True, default='')
    object_type = serializers.ChoiceField(
        choices=DutyConflictRule.OBJECT_TYPE_CHOICES, required=False, allow_blank=True, default='',
        error_messages={'invalid_choice': '无效的业务对象类型'}
    )
    severity = serializers.ChoiceField(
        choices=DutyConflictRule.SEVERITY_CHOICES, required=False, default='medium',
        error_messages={'invalid_choice': '无效的严重级别'}
    )

    def validate_name(self, value):
        instance = self.context.get('instance')
        queryset = DutyConflictRule.objects.filter(name=value)
        if instance:
            queryset = queryset.exclude(pk=instance.pk)
        if queryset.exists():
            raise serializers.ValidationError('规则名称已存在')
        return value

    def validate(self, data):
        instance = self.context.get('instance')
        rule_type = data['rule_type']

        if rule_type == 'role_combo':
            permission_a = data.get('permission_a')
            permission_b = data.get('permission_b')
            if not permission_a or not permission_b:
                raise serializers.ValidationError('组合冲突规则必须选择两个冲突权限')
            for perm in (permission_a, permission_b):
                if perm not in PERMISSION_CATALOG:
                    raise serializers.ValidationError(f'权限"{perm}"不在权限目录中')
            if permission_a == permission_b:
                raise serializers.ValidationError('两个冲突权限不能相同')
            pair = {permission_a, permission_b}
            queryset = DutyConflictRule.objects.filter(rule_type='role_combo')
            if instance:
                queryset = queryset.exclude(pk=instance.pk)
            for existing in queryset:
                if {existing.permission_a, existing.permission_b} == pair:
                    raise serializers.ValidationError('相同的权限组合冲突规则已存在')
            data['object_type'] = ''
        else:
            if not data.get('object_type'):
                raise serializers.ValidationError('创建人自审规则必须选择业务对象类型')
            queryset = DutyConflictRule.objects.filter(
                rule_type='self_approval', object_type=data['object_type']
            )
            if instance:
                queryset = queryset.exclude(pk=instance.pk)
            if queryset.exists():
                raise serializers.ValidationError('该业务对象已存在创建人自审规则')
            data['permission_a'] = ''
            data['permission_b'] = ''
        return data


class DutyDelegationSerializer(serializers.ModelSerializer):
    """临时代理序列化器"""
    delegator_name = serializers.CharField(source='delegator.username', read_only=True)
    delegate_name = serializers.CharField(source='delegate.username', read_only=True)
    permission_name = serializers.SerializerMethodField()
    is_currently_active = serializers.SerializerMethodField()
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = DutyDelegation
        fields = [
            'id', 'delegator', 'delegator_name', 'delegate', 'delegate_name',
            'permission', 'permission_name', 'reason', 'start_at', 'end_at',
            'is_active', 'is_currently_active', 'created_by', 'created_by_name', 'created_at'
        ]

    def get_permission_name(self, obj):
        return PERMISSION_CATALOG.get(obj.permission, obj.permission)

    def get_is_currently_active(self, obj):
        return obj.is_currently_active()


class DutyDelegationCreateSerializer(serializers.Serializer):
    """临时代理创建序列化器"""
    delegator = serializers.IntegerField(required=True, error_messages={'required': '请选择委托人'})
    delegate = serializers.IntegerField(required=True, error_messages={'required': '请选择代理人'})
    permission = serializers.CharField(max_length=50, required=True, error_messages={
        'required': '请选择代理权限',
        'blank': '代理权限不能为空',
    })
    reason = serializers.CharField(min_length=1, max_length=200, required=True, error_messages={
        'required': '请填写代理依据',
        'blank': '代理依据不能为空',
        'max_length': '代理依据最多200个字',
    })
    start_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择生效时间'})
    end_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择失效时间'})

    def validate_permission(self, value):
        if value not in PERMISSION_CATALOG:
            raise serializers.ValidationError('代理权限不在权限目录中')
        return value

    def validate(self, data):
        if data['delegator'] == data['delegate']:
            raise serializers.ValidationError('委托人与代理人不能是同一人')

        try:
            delegator = User.objects.get(pk=data['delegator'], is_active=True)
        except User.DoesNotExist:
            raise serializers.ValidationError('委托人不存在或已停用')
        try:
            delegate = User.objects.get(pk=data['delegate'], is_active=True)
        except User.DoesNotExist:
            raise serializers.ValidationError('代理人不存在或已停用')

        if data['end_at'] <= data['start_at']:
            raise serializers.ValidationError('失效时间必须晚于生效时间')
        if data['end_at'] <= timezone.now():
            raise serializers.ValidationError('失效时间必须晚于当前时间')

        data['delegator_obj'] = delegator
        data['delegate_obj'] = delegate
        return data


class DutyExemptionSerializer(serializers.ModelSerializer):
    """紧急豁免序列化器"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    is_currently_active = serializers.SerializerMethodField()
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = DutyExemption
        fields = [
            'id', 'user', 'user_name', 'rule', 'rule_name', 'reason',
            'expires_at', 'is_active', 'is_currently_active',
            'created_by', 'created_by_name', 'created_at'
        ]

    def get_is_currently_active(self, obj):
        return obj.is_currently_active()


class DutyExemptionCreateSerializer(serializers.Serializer):
    """紧急豁免创建序列化器"""
    user = serializers.IntegerField(required=True, error_messages={'required': '请选择豁免用户'})
    rule = serializers.IntegerField(required=True, error_messages={'required': '请选择豁免规则'})
    reason = serializers.CharField(min_length=1, max_length=200, required=True, error_messages={
        'required': '请填写豁免依据',
        'blank': '豁免依据不能为空',
        'max_length': '豁免依据最多200个字',
    })
    expires_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择失效时间'})

    def validate(self, data):
        if not User.objects.filter(pk=data['user'], is_active=True).exists():
            raise serializers.ValidationError('豁免用户不存在或已停用')
        if not DutyConflictRule.objects.filter(pk=data['rule']).exists():
            raise serializers.ValidationError('豁免规则不存在')
        if data['expires_at'] <= timezone.now():
            raise serializers.ValidationError('失效时间必须晚于当前时间')
        return data


class DutyConflictRecordSerializer(serializers.ModelSerializer):
    """职责冲突记录序列化器"""
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    rule_type = serializers.CharField(source='rule.rule_type', read_only=True)
    user_name = serializers.CharField(source='user.username', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    resolved_by_name = serializers.CharField(source='resolved_by.username', read_only=True)

    class Meta:
        model = DutyConflictRecord
        fields = [
            'id', 'rule', 'rule_name', 'rule_type', 'user', 'user_name',
            'sources', 'status', 'status_display', 'first_seen_at', 'last_seen_at',
            'resolved_by', 'resolved_by_name', 'resolved_at', 'resolution_note'
        ]


class DutyCheckLogSerializer(serializers.ModelSerializer):
    """职责冲突判断日志序列化器"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    check_type_display = serializers.CharField(source='get_check_type_display', read_only=True)
    decision_display = serializers.CharField(source='get_decision_display', read_only=True)

    class Meta:
        model = DutyCheckLog
        fields = [
            'id', 'user', 'user_name', 'rule', 'rule_name',
            'check_type', 'check_type_display', 'object_type', 'object_id',
            'decision', 'decision_display', 'basis', 'exemption', 'created_at'
        ]
