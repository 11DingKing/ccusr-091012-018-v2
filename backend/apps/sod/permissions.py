"""
权限目录与角色权限映射

角色列表本身只能表达"某角色能做什么"，无法表达"同一账号同时持有
某些权限会形成职责冲突"。职责冲突规则建立在权限目录之上：
静态组合检查与业务自审阻断都以这里的权限编码为准。
"""

# 权限目录：编码 -> 中文说明
PERMISSION_CATALOG = {
    'unit:create': '创建移交单位',
    'receipt:create': '登记收件',
    'receipt:approve_high_risk': '批准高风险收件',
    'user:manage': '管理用户账号',
    'sod:manage': '管理职责冲突规则',
}

# 角色 -> 权限集合。超级管理员默认持有全部权限。
ROLE_PERMISSIONS = {
    'superadmin': set(PERMISSION_CATALOG.keys()),
    'admin': {
        'unit:create',
        'receipt:create',
        'receipt:approve_high_risk',
        'user:manage',
        'sod:manage',
    },
    'user': {
        'receipt:create',
    },
}

# 职责冲突规则可引用的业务对象类型
OBJECT_TYPE_CHOICES = {
    'stock_in': '收件（入库）',
}


def get_role_permissions(role):
    """角色自带的权限集合"""
    return set(ROLE_PERMISSIONS.get(role, set()))


def permission_name(code):
    """权限编码的中文说明"""
    return PERMISSION_CATALOG.get(code, code)
