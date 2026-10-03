"""
权限目录与角色权限映射

系统原有权限模型只有角色（superadmin/admin/user），角色列表本身无法表达
"同一账号既能创建移交单位、又能批准该单位高风险收件"这类组合风险。
本目录把角色展开为可枚举的权限代码，作为职责冲突规则的最小判断单元，
从而可以回答"冲突来自哪些权限"。
"""

# 权限代码 -> 中文说明
PERMISSIONS = {
    # 基础数据
    'unit:create': '创建移交单位',
    'unit:update': '修改移交单位',
    'unit:delete': '删除移交单位',
    'category:manage': '管理品类',
    'variety:manage': '管理品种',
    'goods:manage': '管理货物',
    # 收发业务
    'stock_in:create': '收件登记',
    'stock_in:approve_high_risk': '高风险收件审批',
    'stock_out:create': '出库申请',
    'stock_out:approve': '出库审批',
    # 系统管理
    'user:manage': '用户管理',
    'log:view': '日志查看',
    'sod:manage': '职责冲突规则管理',
}

# 普通用户权限（与现有视图行为一致：登录用户可维护基础数据、登记收发）
_USER_PERMISSIONS = [
    'unit:create',
    'unit:update',
    'unit:delete',
    'category:manage',
    'variety:manage',
    'goods:manage',
    'stock_in:create',
    'stock_out:create',
]

# 角色 -> 权限代码
ROLE_PERMISSIONS = {
    'user': list(_USER_PERMISSIONS),
    'admin': list(_USER_PERMISSIONS) + [
        'stock_in:approve_high_risk',
        'stock_out:approve',
        'user:manage',
        'log:view',
        'sod:manage',
    ],
    'superadmin': list(PERMISSIONS.keys()),
}


def permission_label(code):
    """权限代码的中文说明"""
    return PERMISSIONS.get(code, code)


def role_permissions(role):
    """角色对应的权限代码列表"""
    return list(ROLE_PERMISSIONS.get(role, []))
