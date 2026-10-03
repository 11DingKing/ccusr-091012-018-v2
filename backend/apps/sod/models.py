"""
职责冲突（SoD）模型
"""
from django.db import models
from apps.authentication.models import User


class DutyConflictRule(models.Model):
    """职责冲突规则

    - role_combo：静态权限组合冲突，用户同时拥有 permissions 中全部权限即构成冲突；
      用于影响预览与存量冲突报告，不拦截具体操作。
    - self_approval：业务自审冲突，按 object_type + creator_path 定位业务对象的
      创建人，创建人（含其临时代理人）不得对该对象执行 action。
    """

    RULE_TYPE_CHOICES = [
        ('role_combo', '权限组合冲突'),
        ('self_approval', '自审冲突'),
    ]
    STATUS_CHOICES = [
        ('draft', '草稿'),
        ('published', '已发布'),
        ('disabled', '已停用'),
    ]
    SEVERITY_CHOICES = [
        ('high', '高'),
        ('medium', '中'),
        ('low', '低'),
    ]

    name = models.CharField('规则名称', max_length=100, unique=True)
    rule_type = models.CharField('规则类型', max_length=20, choices=RULE_TYPE_CHOICES)
    # role_combo：冲突权限集合（权限代码列表，至少2个）
    permissions = models.JSONField('冲突权限集合', default=list, blank=True)
    # self_approval：业务对象类型、受控动作（权限代码）、创建人定位路径
    object_type = models.CharField('业务对象类型', max_length=50, blank=True)
    action = models.CharField('受控动作', max_length=100, blank=True)
    creator_path = models.CharField('创建人定位路径', max_length=200, blank=True)
    severity = models.CharField('严重级别', max_length=10, choices=SEVERITY_CHOICES, default='medium')
    description = models.TextField('规则说明', blank=True)
    status = models.CharField('状态', max_length=20, choices=STATUS_CHOICES, default='draft')
    # 发布时的影响评估快照（留痕，证明发布前已评估影响）
    publish_impact = models.JSONField('发布影响快照', default=dict, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='created_sod_rules', verbose_name='创建人'
    )
    published_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='published_sod_rules', verbose_name='发布人'
    )
    published_at = models.DateTimeField('发布时间', null=True, blank=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'sod_duty_conflict_rule'
        verbose_name = '职责冲突规则'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name}（{self.get_status_display()}）"


class Delegation(models.Model):
    """临时代理

    代理生效期间，代理人视同持有被代理的权限：
    - 静态组合冲突检查把代理获得的权限计入代理人；
    - 自审检查把"代理人审批委托人的业务对象"视同委托人自审。
    """

    delegator = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='delegations_given', verbose_name='委托人'
    )
    delegate = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='delegations_received', verbose_name='代理人'
    )
    permissions = models.JSONField('代理权限集合', default=list)
    reason = models.TextField('代理依据')
    start_at = models.DateTimeField('生效时间')
    end_at = models.DateTimeField('失效时间')
    is_active = models.BooleanField('是否有效', default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='created_delegations', verbose_name='登记人'
    )
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_delegation'
        verbose_name = '临时代理'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.delegator} -> {self.delegate}"

    def is_in_effect(self, at=None):
        """指定时刻是否处于生效状态"""
        from django.utils import timezone
        at = at or timezone.now()
        return self.is_active and self.start_at <= at <= self.end_at


class EmergencyExemption(models.Model):
    """紧急豁免

    豁免生效期间，指定用户触发指定规则时放行，但每次放行都会写入
    冲突判定记录（含豁免依据），保证紧急操作可追溯。
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='sod_exemptions', verbose_name='豁免用户'
    )
    rule = models.ForeignKey(
        DutyConflictRule, on_delete=models.CASCADE,
        related_name='exemptions', verbose_name='豁免规则'
    )
    reason = models.TextField('豁免依据')
    approved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='approved_exemptions', verbose_name='批准人'
    )
    start_at = models.DateTimeField('生效时间')
    end_at = models.DateTimeField('失效时间')
    is_active = models.BooleanField('是否有效', default=True)
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_emergency_exemption'
        verbose_name = '紧急豁免'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user} - {self.rule}"

    def is_in_effect(self, at=None):
        """指定时刻是否处于生效状态"""
        from django.utils import timezone
        at = at or timezone.now()
        return self.is_active and self.start_at <= at <= self.end_at


class ConflictCheckRecord(models.Model):
    """冲突判定记录（留痕）

    每次职责冲突判定（阻止或豁免放行）都写入一条记录，
    basis 字段保存判定依据：命中的权限及其来源、临时代理链、
    业务关系（创建人路径）以及豁免信息。
    """

    RESULT_CHOICES = [
        ('blocked', '已阻止'),
        ('exempted', '豁免放行'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='sod_check_records', verbose_name='操作用户'
    )
    rule = models.ForeignKey(
        DutyConflictRule, on_delete=models.SET_NULL, null=True,
        related_name='check_records', verbose_name='命中规则'
    )
    action = models.CharField('尝试动作', max_length=100)
    object_type = models.CharField('业务对象类型', max_length=50, blank=True)
    object_id = models.IntegerField('业务对象ID', null=True, blank=True)
    object_label = models.CharField('业务对象描述', max_length=200, blank=True)
    result = models.CharField('判定结果', max_length=20, choices=RESULT_CHOICES)
    basis = models.JSONField('判定依据', default=dict)
    created_at = models.DateTimeField('判定时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_conflict_check_record'
        verbose_name = '冲突判定记录'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user} - {self.get_result_display()} - {self.action}"
