"""
职责冲突管理URL配置
"""
from django.urls import path
from .views import (
    ConflictCheckRecordListView, ConflictOverviewView,
    DelegationListView, DelegationRevokeView,
    DutyConflictRuleDetailView, DutyConflictRuleDisableView,
    DutyConflictRuleListView, DutyConflictRulePreviewView, DutyConflictRulePublishView,
    EmergencyExemptionListView, EmergencyExemptionRevokeView,
    PermissionCatalogView,
)

urlpatterns = [
    # 权限目录
    path('permissions/', PermissionCatalogView.as_view(), name='sod-permission-catalog'),

    # 冲突规则
    path('rules/', DutyConflictRuleListView.as_view(), name='sod-rule-list'),
    path('rules/<int:pk>/', DutyConflictRuleDetailView.as_view(), name='sod-rule-detail'),
    path('rules/<int:pk>/preview/', DutyConflictRulePreviewView.as_view(), name='sod-rule-preview'),
    path('rules/<int:pk>/publish/', DutyConflictRulePublishView.as_view(), name='sod-rule-publish'),
    path('rules/<int:pk>/disable/', DutyConflictRuleDisableView.as_view(), name='sod-rule-disable'),

    # 冲突总览与判定记录
    path('conflicts/', ConflictOverviewView.as_view(), name='sod-conflict-overview'),
    path('records/', ConflictCheckRecordListView.as_view(), name='sod-record-list'),

    # 临时代理
    path('delegations/', DelegationListView.as_view(), name='sod-delegation-list'),
    path('delegations/<int:pk>/revoke/', DelegationRevokeView.as_view(), name='sod-delegation-revoke'),

    # 紧急豁免
    path('exemptions/', EmergencyExemptionListView.as_view(), name='sod-exemption-list'),
    path('exemptions/<int:pk>/revoke/', EmergencyExemptionRevokeView.as_view(), name='sod-exemption-revoke'),
]
