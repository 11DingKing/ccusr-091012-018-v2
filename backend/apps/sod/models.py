"""
职责冲突（职责分离）模型
"""
from django.db import models
from django.utils import timezone
from apps.authentication.models import User


class DutyConflictRule(models.Model):
    """职责冲突规则"""

    RULE_TYPE_CHOICES = [
        ('role_combo', '角色权限组合冲突'),
        ('self_approval', '创建人自审冲突'),
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
    OBJECT_TYPE_CHOICES = [
        ('stock_in', '收件（入库）'),
    ]

    name = models.CharField('规则名称', max_length=50, unique=True)
    description = models.CharField('规则说明', max_length=200, blank=True)
    rule_type = models.CharField('规则类型', max_length=20, choices=RULE_TYPE_CHOICES)
    # role_combo：同一账号不得同时持有的两个权限
    permission_a = models.CharField('冲突权限A', max_length=50, blank=True)
    permission_b = models.CharField('冲突权限B', max_length=50, blank=True)
    # self_approval：创建人不得审批自己创建的业务对象
    object_type = models.CharField('业务对象类型', max_length=20, choices=OBJECT_TYPE_CHOICES, blank=True)
    severity = models.CharField('严重级别', max_length=10, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField('状态', max_length=10, choices=STATUS_CHOICES, default='draft')
    published_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='published_duty_rules', verbose_name='发布人'
    )
    published_at = models.DateTimeField('发布时间', null=True, blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_duty_rules', verbose_name='创建人'
    )
    created_at = models.DateTimeField('创建时间', auto_now_add=True)
    updated_at = models.DateTimeField('更新时间', auto_now=True)

    class Meta:
        db_table = 'sod_duty_conflict_rule'
        verbose_name = '职责冲突规则'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class DutyDelegation(models.Model):
    """临时代理：在时间窗内把某项权限授予代理人，判断冲突时计入代理人权限"""

    delegator = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='given_duty_delegations', verbose_name='委托人'
    )
    delegate = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='received_duty_delegations', verbose_name='代理人'
    )
    permission = models.CharField('代理权限', max_length=50)
    reason = models.CharField('代理依据', max_length=200)
    start_at = models.DateTimeField('生效时间')
    end_at = models.DateTimeField('失效时间')
    is_active = models.BooleanField('是否启用', default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+', verbose_name='创建人'
    )
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_duty_delegation'
        verbose_name = '临时代理'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.delegator} -> {self.delegate} ({self.permission})"

    def is_currently_active(self, at=None):
        """指定时刻是否处于生效窗口内"""
        at = at or timezone.now()
        return self.is_active and self.start_at <= at <= self.end_at


class DutyExemption(models.Model):
    """紧急豁免：允许指定用户临时豁免某条冲突规则，必须留下依据"""

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='duty_exemptions', verbose_name='豁免用户'
    )
    rule = models.ForeignKey(
        DutyConflictRule, on_delete=models.CASCADE,
        related_name='exemptions', verbose_name='豁免规则'
    )
    reason = models.CharField('豁免依据', max_length=200)
    expires_at = models.DateTimeField('失效时间')
    is_active = models.BooleanField('是否启用', default=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_duty_exemptions', verbose_name='创建人'
    )
    created_at = models.DateTimeField('创建时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_duty_exemption'
        verbose_name = '紧急豁免'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user} 豁免 {self.rule}"

    def is_currently_active(self, at=None):
        at = at or timezone.now()
        return self.is_active and self.expires_at > at


class DutyConflictRecord(models.Model):
    """职责冲突记录：冲突来自哪些权限和业务关系，供管理员处置"""

    STATUS_CHOICES = [
        ('open', '待处理'),
        ('exempted', '已豁免'),
        ('resolved', '已解决'),
    ]

    rule = models.ForeignKey(
        DutyConflictRule, on_delete=models.CASCADE,
        related_name='conflict_records', verbose_name='冲突规则'
    )
    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='duty_conflict_records', verbose_name='冲突用户'
    )
    sources = models.JSONField('冲突来源', default=list)
    status = models.CharField('状态', max_length=10, choices=STATUS_CHOICES, default='open')
    first_seen_at = models.DateTimeField('首次发现时间', auto_now_add=True)
    last_seen_at = models.DateTimeField('最近发现时间', auto_now=True)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+', verbose_name='处理人'
    )
    resolved_at = models.DateTimeField('处理时间', null=True, blank=True)
    resolution_note = models.CharField('处理说明', max_length=200, blank=True)

    class Meta:
        db_table = 'sod_duty_conflict_record'
        verbose_name = '职责冲突记录'
        verbose_name_plural = verbose_name
        ordering = ['-last_seen_at']
        unique_together = ['rule', 'user']

    def __str__(self):
        return f"{self.user} 触发 {self.rule}"


class DutyCheckLog(models.Model):
    """职责冲突判断日志：每次业务阻断/放行都留下判断依据"""

    DECISION_CHOICES = [
        ('blocked', '已阻止'),
        ('allowed_exempted', '豁免放行'),
        ('bypassed', '超级管理员绕过'),
    ]
    CHECK_TYPE_CHOICES = [
        ('role_combo', '角色权限组合'),
        ('self_approval', '创建人自审'),
        ('delegation', '临时代理'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True,
        related_name='+', verbose_name='被判断用户'
    )
    rule = models.ForeignKey(
        DutyConflictRule, on_delete=models.SET_NULL, null=True,
        related_name='+', verbose_name='命中规则'
    )
    check_type = models.CharField('判断类型', max_length=20, choices=CHECK_TYPE_CHOICES)
    object_type = models.CharField('业务对象类型', max_length=50, blank=True)
    object_id = models.BigIntegerField('业务对象ID', null=True, blank=True)
    decision = models.CharField('判断结果', max_length=20, choices=DECISION_CHOICES)
    basis = models.TextField('判断依据', blank=True)
    exemption = models.ForeignKey(
        DutyExemption, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='+', verbose_name='使用豁免'
    )
    created_at = models.DateTimeField('判断时间', auto_now_add=True)

    class Meta:
        db_table = 'sod_duty_check_log'
        verbose_name = '职责冲突判断日志'
        verbose_name_plural = verbose_name
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user} - {self.get_decision_display()} - {self.check_type}"
