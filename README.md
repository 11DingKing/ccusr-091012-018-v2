# 监管物资保管服务

该项目为监管仓、证物室和受控物资保管点提供服务端 API，覆盖人员授权、物资分类、批次登记、收发记录、审批、预警、审计日志与统计报表。数据保存在 SQLite，所有测试和接口验收均可在单个 Linux 应用容器内离线完成。

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

## 职责冲突（职责分离）

`apps/sod` 提供职责冲突规则，弥补角色列表无法表达的组合风险：

- **静态角色组合检查**：`role_combo` 规则声明同一账号不得同时持有的两个权限，
  `POST /api/sod/scan/` 对全部既有用户扫描并登记冲突记录。
- **创建人自审阻断**：`self_approval` 规则在具体业务上阻止创建人审批自己的对象，
  高风险收件审批（`POST /api/stock-in/<id>/approve/`）会拦截登记人本人及移交单位创建人。
- **临时代理与紧急豁免**：代理在时间窗内授予权限并计入冲突判断；
  豁免到期自动失效，每次阻断/豁免放行都写入判断日志（`/api/sod/check-logs/`）作为依据。
- **发布前影响预览**：`GET /api/sod/rules/<id>/preview/` 只读评估受影响用户；
  发布需 `confirm=true` 确认，且只登记冲突记录，绝不改写既有用户的角色或权限。
- **冲突来源可见**：`/api/sod/conflicts/` 展示冲突来自哪些权限（角色/代理）和业务关系。
