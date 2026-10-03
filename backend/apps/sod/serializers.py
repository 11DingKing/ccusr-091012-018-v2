"""
职责冲突序列化器
"""
from rest_framework import serializers
from apps.authentication.models import User
from .engine import get_effective_permissions, get_object_registry
from .models import ConflictCheckRecord, Delegation, DutyConflictRule, EmergencyExemption
from .permissions import PERMISSIONS, permission_label


class DutyConflictRuleSerializer(serializers.ModelSerializer):
    """职责冲突规则序列化器"""
    rule_type_display = serializers.CharField(source='get_rule_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    published_by_name = serializers.CharField(source='published_by.username', read_only=True)
    permission_items = serializers.SerializerMethodField()
    object_type_label = serializers.SerializerMethodField()
    creator_path_label = serializers.SerializerMethodField()

    class Meta:
        model = DutyConflictRule
        fields = [
            'id', 'name', 'rule_type', 'rule_type_display',
            'permissions', 'permission_items',
            'object_type', 'object_type_label', 'action', 'creator_path', 'creator_path_label',
            'severity', 'severity_display', 'description', 'status', 'status_display',
            'publish_impact', 'created_by', 'created_by_name',
            'published_by', 'published_by_name', 'published_at',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'status', 'publish_impact', 'published_by', 'published_at', 'created_at', 'updated_at']

    def get_permission_items(self, obj):
        """冲突权限集合（含中文说明）"""
        return [{'code': code, 'label': permission_label(code)} for code in obj.permissions or []]

    def get_object_type_label(self, obj):
        config = get_object_registry().get(obj.object_type)
        return config['label'] if config else obj.object_type

    def get_creator_path_label(self, obj):
        config = get_object_registry().get(obj.object_type)
        if config:
            return config['creator_paths'].get(obj.creator_path, obj.creator_path)
        return obj.creator_path


class DutyConflictRuleCreateSerializer(serializers.Serializer):
    """职责冲突规则创建/更新序列化器"""
    name = serializers.CharField(max_length=100, required=True, error_messages={
        'required': '请输入规则名称',
        'blank': '规则名称不能为空',
    })
    rule_type = serializers.ChoiceField(choices=['role_combo', 'self_approval'], required=True)
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=100), required=False, default=list
    )
    object_type = serializers.CharField(max_length=50, required=False, allow_blank=True, default='')
    action = serializers.CharField(max_length=100, required=False, allow_blank=True, default='')
    creator_path = serializers.CharField(max_length=200, required=False, allow_blank=True, default='')
    severity = serializers.ChoiceField(choices=['high', 'medium', 'low'], default='medium')
    description = serializers.CharField(required=False, allow_blank=True, default='')

    def validate_name(self, value):
        instance = self.context.get('instance')
        queryset = DutyConflictRule.objects.filter(name=value)
        if instance:
            queryset = queryset.exclude(pk=instance.pk)
        if queryset.exists():
            raise serializers.ValidationError('规则名称已存在')
        return value

    def validate(self, data):
        rule_type = data['rule_type']
        if rule_type == 'role_combo':
            permissions = data.get('permissions') or []
            if len(permissions) < 2:
                raise serializers.ValidationError('权限组合冲突规则至少需要2个权限')
            unknown = [code for code in permissions if code not in PERMISSIONS]
            if unknown:
                labels = '、'.join(unknown)
                raise serializers.ValidationError(f'未知权限代码：{labels}')
        else:
            registry = get_object_registry()
            object_type = data.get('object_type')
            if object_type not in registry:
                raise serializers.ValidationError('业务对象类型无效')
            if not data.get('action'):
                raise serializers.ValidationError('请选择受控动作')
            if data['action'] not in PERMISSIONS:
                raise serializers.ValidationError('受控动作不是有效的权限代码')
            creator_path = data.get('creator_path')
            if creator_path not in registry[object_type]['creator_paths']:
                raise serializers.ValidationError('创建人定位路径无效')
        return data


class DelegationSerializer(serializers.ModelSerializer):
    """临时代理序列化器"""
    delegator_name = serializers.CharField(source='delegator.username', read_only=True)
    delegate_name = serializers.CharField(source='delegate.username', read_only=True)
    created_by_name = serializers.CharField(source='created_by.username', read_only=True)
    permission_items = serializers.SerializerMethodField()
    in_effect = serializers.SerializerMethodField()

    class Meta:
        model = Delegation
        fields = [
            'id', 'delegator', 'delegator_name', 'delegate', 'delegate_name',
            'permissions', 'permission_items', 'reason', 'start_at', 'end_at',
            'is_active', 'in_effect', 'created_by', 'created_by_name', 'created_at',
        ]
        read_only_fields = ['id', 'is_active', 'created_by', 'created_at']

    def get_permission_items(self, obj):
        return [{'code': code, 'label': permission_label(code)} for code in obj.permissions or []]

    def get_in_effect(self, obj):
        return obj.is_in_effect()


class DelegationCreateSerializer(serializers.Serializer):
    """临时代理创建序列化器"""
    delegator = serializers.IntegerField(required=True, error_messages={'required': '请选择委托人'})
    delegate = serializers.IntegerField(required=True, error_messages={'required': '请选择代理人'})
    permissions = serializers.ListField(
        child=serializers.CharField(max_length=100), required=True, allow_empty=False,
        error_messages={'required': '请选择代理权限', 'empty': '代理权限不能为空'}
    )
    reason = serializers.CharField(required=True, error_messages={
        'required': '请填写代理依据',
        'blank': '代理依据不能为空',
    })
    start_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择生效时间'})
    end_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择失效时间'})

    def validate_permissions(self, value):
        unknown = [code for code in value if code not in PERMISSIONS]
        if unknown:
            raise serializers.ValidationError(f'未知权限代码：{"、".join(unknown)}')
        return value

    def validate(self, data):
        if data['delegator'] == data['delegate']:
            raise serializers.ValidationError('委托人与代理人不能是同一人')
        try:
            delegator = User.objects.get(pk=data['delegator'], is_active=True)
        except User.DoesNotExist:
            raise serializers.ValidationError('委托人不存在或已停用')
        if not User.objects.filter(pk=data['delegate'], is_active=True).exists():
            raise serializers.ValidationError('代理人不存在或已停用')
        if data['end_at'] <= data['start_at']:
            raise serializers.ValidationError('失效时间必须晚于生效时间')
        # 只能代理委托人当前实际持有的权限
        held = get_effective_permissions(delegator)
        not_held = [code for code in data['permissions'] if code not in held]
        if not_held:
            labels = '、'.join(permission_label(code) for code in not_held)
            raise serializers.ValidationError(f'委托人不持有以下权限，无法代理：{labels}')
        return data


class EmergencyExemptionSerializer(serializers.ModelSerializer):
    """紧急豁免序列化器"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    approved_by_name = serializers.CharField(source='approved_by.username', read_only=True)
    in_effect = serializers.SerializerMethodField()

    class Meta:
        model = EmergencyExemption
        fields = [
            'id', 'user', 'user_name', 'rule', 'rule_name', 'reason',
            'approved_by', 'approved_by_name', 'start_at', 'end_at',
            'is_active', 'in_effect', 'created_at',
        ]
        read_only_fields = ['id', 'is_active', 'approved_by', 'created_at']

    def get_in_effect(self, obj):
        return obj.is_in_effect()


class EmergencyExemptionCreateSerializer(serializers.Serializer):
    """紧急豁免创建序列化器"""
    user = serializers.IntegerField(required=True, error_messages={'required': '请选择豁免用户'})
    rule = serializers.IntegerField(required=True, error_messages={'required': '请选择豁免规则'})
    reason = serializers.CharField(required=True, error_messages={
        'required': '请填写豁免依据',
        'blank': '豁免依据不能为空',
    })
    start_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择生效时间'})
    end_at = serializers.DateTimeField(required=True, error_messages={'required': '请选择失效时间'})

    def validate(self, data):
        request_user = self.context.get('request_user')
        if not User.objects.filter(pk=data['user'], is_active=True).exists():
            raise serializers.ValidationError('豁免用户不存在或已停用')
        rule = DutyConflictRule.objects.filter(pk=data['rule']).first()
        if not rule:
            raise serializers.ValidationError('豁免规则不存在')
        if rule.status != 'published':
            raise serializers.ValidationError('只能对已发布的规则设置豁免')
        if data['end_at'] <= data['start_at']:
            raise serializers.ValidationError('失效时间必须晚于生效时间')
        # 豁免批准人不能是豁免对象本人，避免自我豁免
        if request_user and request_user.id == data['user']:
            raise serializers.ValidationError('不能为本人批准紧急豁免')
        data['rule_obj'] = rule
        return data


class ConflictCheckRecordSerializer(serializers.ModelSerializer):
    """冲突判定记录序列化器"""
    user_name = serializers.CharField(source='user.username', read_only=True)
    rule_name = serializers.CharField(source='rule.name', read_only=True)
    result_display = serializers.CharField(source='get_result_display', read_only=True)
    action_label = serializers.SerializerMethodField()

    class Meta:
        model = ConflictCheckRecord
        fields = [
            'id', 'user', 'user_name', 'rule', 'rule_name', 'action', 'action_label',
            'object_type', 'object_id', 'object_label', 'result', 'result_display',
            'basis', 'created_at',
        ]

    def get_action_label(self, obj):
        return permission_label(obj.action)
