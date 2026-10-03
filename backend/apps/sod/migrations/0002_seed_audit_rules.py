"""
根据内部审计发现预置两条职责冲突规则（草稿状态）

草稿状态不参与任何判定，需管理员预览影响并手动发布后才生效，
避免对现有用户造成静默的行为变更。
"""
from django.db import migrations


def seed_audit_rules(apps, schema_editor):
    DutyConflictRule = apps.get_model('sod', 'DutyConflictRule')

    DutyConflictRule.objects.get_or_create(
        name='移交单位创建与高风险收件审批权限互斥',
        defaults={
            'rule_type': 'role_combo',
            'permissions': ['unit:create', 'stock_in:approve_high_risk'],
            'severity': 'high',
            'description': (
                '内部审计发现：同一账号既能创建移交单位，又能批准该单位的高风险收件。'
                '同时拥有"创建移交单位"与"高风险收件审批"权限即构成权限组合冲突。'
            ),
            'status': 'draft',
        },
    )

    DutyConflictRule.objects.get_or_create(
        name='创建移交单位者不得审批该单位高风险收件',
        defaults={
            'rule_type': 'self_approval',
            'object_type': 'stock_in',
            'action': 'stock_in:approve_high_risk',
            'creator_path': 'goods.variety.category.unit.created_by',
            'severity': 'high',
            'description': (
                '高风险收件审批时，若审批人是该收件所属移交单位的创建人'
                '（或持有创建人的临时代理），判定为自审冲突并阻止；'
                '紧急情况下可通过登记豁免放行，全程留痕。'
            ),
            'status': 'draft',
        },
    )


def remove_audit_rules(apps, schema_editor):
    DutyConflictRule = apps.get_model('sod', 'DutyConflictRule')
    DutyConflictRule.objects.filter(
        name__in=[
            '移交单位创建与高风险收件审批权限互斥',
            '创建移交单位者不得审批该单位高风险收件',
        ]
    ).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('sod', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(seed_audit_rules, remove_audit_rules),
    ]
