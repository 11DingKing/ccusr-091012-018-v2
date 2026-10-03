# 监管物资保管服务

该项目为监管仓、证物室和受控物资保管点提供服务端 API，覆盖人员授权、物资分类、批次登记、收发记录、审批、预警、审计日志与统计报表。数据保存在 SQLite，所有测试和接口验收均可在单个 Linux 应用容器内离线完成。

## 职责冲突（SoD）

针对"同一账号既能创建移交单位、又能批准该单位高风险收件"的审计发现，系统提供职责冲突规则（`apps/sod`）：

- **权限目录**：`GET /api/sod/permissions/` 将角色展开为可枚举的权限代码，冲突可溯源到具体权限。
- **冲突规则**：`POST /api/sod/rules/` 创建草稿，支持两类规则——
  - `role_combo`：静态权限组合冲突（同时拥有规则中全部权限即冲突）；
  - `self_approval`：业务自审冲突（创建人及其临时代理人不得批准自己的对象）。
- **影响预览**：`POST /api/sod/rules/{id}/preview/` 发布前评估受影响用户及其冲突来源；`POST /api/sod/rules/{id}/publish/` 发布时自动留存影响快照，**不改写任何已有用户的角色或权限**，存量冲突在 `GET /api/sod/conflicts/` 中呈现。
- **临时代理**：`POST /api/sod/delegations/` 登记（必填代理依据与有效期），代理期间代理人继承权限，且视同委托人参与自审判断。
- **紧急豁免**：`POST /api/sod/exemptions/` 登记（必填豁免依据，不能为本人批准），豁免期内冲突操作放行但逐笔留痕。
- **判定留痕**：每次阻止或豁免放行均写入判定记录（`GET /api/sod/records/`），依据包含命中的权限来源、代理链、业务关系与豁免信息。
- **业务接入**：高风险收件（`POST /api/stock-in/` 传 `risk_level=high`）登记后进入待审批，`POST /api/stock-in/{id}/approve/` 审批时强制执行自审检查。

数据迁移预置了两条审计规则（草稿状态），需管理员预览影响并发布后生效。

## 运行环境

- Python 3.11
- Django REST Framework
- SQLite

## 安装与初始化

```bash
python -m pip install -r backend/requirements.txt
cd backend
python manage.py migrate --run-syncdb
```

## 测试

```bash
cd backend
pytest -q
```

## 编译检查

```bash
python -m compileall -q backend
```

## API 验收

```bash
cd backend
python manage.py migrate --run-syncdb
python manage.py shell -c "from rest_framework.test import APIClient; from apps.authentication.models import User; u=User.objects.create_user('smoke','safe-pass',role='admin'); c=APIClient(); r=c.post('/api/auth/login/',{'username':'smoke','password':'safe-pass'},format='json'); print(r.status_code, bool(r.json()['data']['token']))"
```

## 容器

```bash
docker build -t custody-service .
docker run --rm custody-service
```
