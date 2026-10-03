"""
职责冲突管理URL配置
"""
from django.urls import path
from .views import (
    PermissionCatalogView,
    RuleListView, RuleDetailView, RulePreviewView, RulePublishView, RuleDisableView,
    ScanView, ConflictRecordListView, ConflictRecordResolveView,
    DelegationListView, DelegationDetailView,
    ExemptionListView, ExemptionDetailView,
    CheckLogListView,
)

urlpatterns = [
    # 权限目录
    path('permissions/', PermissionCatalogView.as_view(), name='sod-permission-catalog'),

    # 冲突规则
    path('rules/', RuleListView.as_view(), name='sod-rule-list'),
    path('rules/<int:pk>/', RuleDetailView.as_view(), name='sod-rule-detail'),
    path('rules/<int:pk>/preview/', RulePreviewView.as_view(), name='sod-rule-preview'),
    path('rules/<int:pk>/publish/', RulePublishView.as_view(), name='sod-rule-publish'),
    path('rules/<int:pk>/disable/', RuleDisableView.as_view(), name='sod-rule-disable'),

    # 静态扫描与冲突记录
    path('scan/', ScanView.as_view(), name='sod-scan'),
    path('conflicts/', ConflictRecordListView.as_view(), name='sod-conflict-list'),
    path('conflicts/<int:pk>/resolve/', ConflictRecordResolveView.as_view(), name='sod-conflict-resolve'),

    # 临时代理
    path('delegations/', DelegationListView.as_view(), name='sod-delegation-list'),
    path('delegations/<int:pk>/', DelegationDetailView.as_view(), name='sod-delegation-detail'),

    # 紧急豁免
    path('exemptions/', ExemptionListView.as_view(), name='sod-exemption-list'),
    path('exemptions/<int:pk>/', ExemptionDetailView.as_view(), name='sod-exemption-detail'),

    # 判断日志
    path('check-logs/', CheckLogListView.as_view(), name='sod-check-log-list'),
]
