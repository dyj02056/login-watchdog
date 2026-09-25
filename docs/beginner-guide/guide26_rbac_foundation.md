# 26단계 — RBAC 기본 구조 (Track B 1/3)

[◀ 25단계](guide25_scripts_merge_ai_report.md) · [전체 목차](beginner-guide.md) · [27단계 ▶](guide27_siem_correlation.md)

> SKT aleph 교육과정 Week3(RBAC/예외승인/감사추적)을 반영하는 Track B의 첫 단계입니다. 지금까지 관리자는 `admin_users`에 로그인만 되면 잠금 해제부터 회원 삭제, 회원가입 On/Off까지 전부 같은 권한으로 할 수 있었습니다 — "누가 어떤 권한을 왜 가졌는지"가 전혀 기록되지 않는 이진(로그인/비로그인) 구조였습니다. 이번 단계에서 역할 3개(`security_viewer`/`security_admin`/`super_admin`)와 역할별로 할 수 있는 액션을 DB 표로 나누고, `routes/admin.py`의 쓰기 API 6개를 액션 단위로 다시 잠갔습니다.

### 왜 역할을 3개로 나눴는가

`routes/admin.py`의 실제 API를 "되돌릴 수 있는가"와 "영향 범위가 어디까지인가" 기준으로 나눴습니다.

| 역할 | 할 수 있는 일 | 기준 |
|---|---|---|
| `security_viewer` | 대시보드 조회만 | 세 역할 모두 조회는 가능해서 별도 permissions 행을 두지 않음 |
| `security_admin` | `unlock_ip`, `resolve_security_event` | 매일 반복되는 가역적 SOAR 대응 |
| `super_admin` | 위 두 가지 + `toggle_signup`, `delete_user`, `delete_post`, `delete_comment` | 비가역이거나 사이트 전역에 영향을 주는 작업 |

## 1. DB 구조 — `roles`/`permissions` 표 + `admin_users.role` 컬럼

[docs/schema.sql](../schema.sql)에 세 부분을 추가했습니다.

```sql
create table roles (
  role text primary key check (role in ('security_viewer', 'security_admin', 'super_admin'))
);
create table permissions (
  role text not null references roles(role),
  action text not null check (action in (
    'unlock_ip', 'resolve_security_event', 'toggle_signup',
    'delete_user', 'delete_post', 'delete_comment', 'manage_admin_users'
  )),
  primary key (role, action)
);
alter table admin_users add column role text not null references roles(role) default 'security_admin';
update admin_users set role = 'super_admin' where username = 'sktmaster123';
```

`role`을 새 계정 표로 따로 만들지 않고 기존 `admin_users`에 컬럼 하나만 추가한 이유: 관리자 "역할"은 관리자 "계정"의 속성이지 별도 개체가 아닙니다. 이미 있던 최종 책임자 계정(`sktmaster123`)도 이 ALTER 한 번으로 새 계정이 생기는 게 아니라, 같은 행에 `role = 'super_admin'`이라는 값이 채워질 뿐입니다.

`permissions`은 역할→액션을 평평하게(포함 관계 없이) 전부 나열합니다 — `security_admin`이 할 수 있는 일도 `super_admin` 행에 다시 한 번 적어야 합니다. 스키마가 역할 계층을 표현하지 않기 때문인데, 역할이 3개뿐이고 액션도 6개뿐이라 지금은 이 편이 "어느 역할이 뭘 할 수 있는지 표 한 번 보면 다 보인다"는 장점이 더 큽니다.

## 2. 요청마다 실시간으로 역할/권한을 확인 — 세션에 캐싱하지 않음

[db/admin.py](../../db/admin.py)의 `get_admin_role()`과 [db/roles.py](../../db/roles.py)의 `has_permission()` 둘 다 로그인 시점에 세션에 저장해두지 않고, 매 요청마다 Supabase를 직접 조회합니다.

```python
# helpers.py — require_permission()
role = db.get_admin_role(session["admin_username"])
if role is None or not db.has_permission(role, action):
    return jsonify({"error": "이 작업을 수행할 권한이 없습니다."}), 403
```

`db/settings.py`의 `get_signup_enabled()`가 매번 Supabase를 조회하는 것과 같은 이유입니다 — 나중에 28단계(권한회수)에서 super_admin이 다른 관리자의 role을 낮추거나 회수해도, 그 관리자가 로그아웃하지 않은 채로도 바로 다음 요청부터 새 권한이 적용되어야 합니다. 로그인 시점에 세션에 역할을 캐싱했다면 재로그인 전까지 예전 권한이 계속 유효한 구멍이 생깁니다.

반면 `GET /admin/dashboard`, `GET /api/status`(2~3초마다 폴링되는 화면)는 여전히 `login_required`만 씁니다 — 세 역할 모두 조회 권한은 동일하므로 여기에 권한 검사를 추가해도 막아지는 사람이 없고, 폴링 API에 매번 DB 조회 2번을 더 얹는 손해만 생깁니다.

## 3. `routes/admin.py` 쓰기 API 6개를 `require_permission`으로 교체

```python
@admin_bp.route("/api/unlock", methods=["POST"])
@require_permission("unlock_ip")
def api_unlock(): ...

@admin_bp.route("/api/users/delete", methods=["POST"])
@require_permission("delete_user")
def api_users_delete(): ...
```

`login_required`와 똑같이 미로그인 시 `/api/*`는 401 JSON, 그 외는 로그인 화면으로 리다이렉트합니다. 로그인은 됐지만 역할에 그 액션이 없으면 403 JSON을 돌려줍니다.

## 4. 새 관리자 계정 생성 — 스크립트 + (super_admin 한정) 대시보드

`admin_users`는 원래도 회원가입 화면이 없는 표입니다(부트스트랩 계정 1개만 `.env`로 자동 생성). 처음엔 [scripts/create_admin.py](../../scripts/create_admin.py)를 터미널에서 직접 실행하는 방법만 있었습니다.

```bash
python scripts/create_admin.py --username sktviewer123 --password <비밀번호> --role security_viewer
python scripts/create_admin.py --username sktadmin123 --password <비밀번호> --role security_admin
```

이미 있는 아이디면 아무것도 만들지 않고 건너뜁니다(`unlock_account.py` 등 기존 스크립트와 동일한 "실수로 두 번 실행해도 안전" 원칙). 이 스크립트는 `--role`에 `super_admin`도 선택할 수 있습니다 — 터미널 접근 자체가 이미 신뢰된 사람만 할 수 있는 작업이라는 전제입니다.

## 5. 대시보드 "관리자 계정 관리" 카드 — super_admin만 보임 (guide26 후속)

터미널을 열어야만 관리자를 추가/제거할 수 있다는 게 guide26의 가장 어색한 지점이었습니다(발표·운영 중에 SSH나 로컬 셸이 필요함). 그래서 `super_admin` 전용으로 대시보드 안에 계정 생성/삭제 기능을 추가했습니다.

새 액션 `manage_admin_users`를 `permissions`에 추가하고(`super_admin`만 보유), 관련 함수를 `db/admin.py`에 더했습니다: `list_admin_users()`, `get_admin_role_by_id()`(id로 role 확인 — 삭제 전에 super_admin인지 확인할 때 씀), `create_admin_user()`(스크립트와 이 화면이 공유), `delete_admin_user()`.

`GET /api/status`는 요청자 role이 `manage_admin_users`를 가졌을 때만 응답에 `admin_users` 키를 실어 보냅니다 — 다른 role로 로그인하면 이 키 자체가 없어서, `render.js`가 카드를 통째로 숨깁니다. role 조회는 다른 8개 쿼리와 같은 `ThreadPoolExecutor` 배치에 병렬로 넣어서, 이 검사 때문에 폴링이 느려지지 않게 했습니다.

```python
# routes/admin.py — api_status()
if role is not None and db.has_permission(role, "manage_admin_users"):
    response_data["admin_users"] = db.list_admin_users()
```

**"super_admin은 1명만 둔다"는 정책을 화면과 서버 양쪽에서 강제**합니다 — 생성 폼의 `<select>`에는 `security_viewer`/`security_admin` 옵션만 있고(`super_admin` 자체가 없음), 목록 표에서도 `super_admin` 행에는 삭제 버튼을 그리지 않습니다. 다만 화면만 막으면 fetch()를 직접 조작하는 우회가 가능하므로, 서버(`POST /api/admin-users/create`, `POST /api/admin-users/delete`)에서도 각각 role 값 검증과 삭제 대상 role 확인을 한 번 더 합니다.

## 실제로 확인한 것

`pytest tests/` 전체 253개 통과(guide26 원래 238개 + 이번 추가 15개: `db` 계층 6개, `routes/admin.py` API 9개 — 권한 없음 403, `role=super_admin` 생성 거부 400, `super_admin` 대상 삭제 거부 400, `/api/status`의 `admin_users` 필드 유무 포함).

실제 로컬 서버 + 실제 Supabase로도 검증했습니다: `sktmaster123`으로 로그인해 대시보드에서 직접 계정을 생성하고 화면에 뜨는 것까지 확인했고(브라우저 자동화 환경이라 `confirm()` 팝업만 API 직접 호출로 대체), `security_admin`으로는 `admin_users` 필드 자체가 안 보이고 두 API 모두 403인 것, `super_admin`으로 `role: "super_admin"` 생성과 `sktmaster123` 자기 자신 삭제를 시도해도 둘 다 400으로 막히고 실제로 DB에 반영되지 않는 것까지 확인했습니다. 테스트로 만든 계정은 확인 후 삭제해 DB에 남기지 않았습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [docs/schema.sql](../schema.sql)
- [config.py](../../config.py) — `USERNAME_PATTERN`/`MIN_PASSWORD_LENGTH` 공용 상수로 이동
- [db/admin.py](../../db/admin.py) — `get_admin_role()`, `list_admin_users()`, `get_admin_role_by_id()`, `create_admin_user()`, `delete_admin_user()`
- [db/roles.py](../../db/roles.py) — 신규, `has_permission()`
- [db/__init__.py](../../db/__init__.py)
- [helpers.py](../../helpers.py) — `require_permission()` 추가
- [routes/admin.py](../../routes/admin.py) — `/api/admin-users/create`, `/api/admin-users/delete` 신규 + `/api/status` 조건부 `admin_users` 필드
- [routes/auth.py](../../routes/auth.py) — 아이디/비밀번호 규칙을 `config.py`에서 가져오도록 변경
- [scripts/create_admin.py](../../scripts/create_admin.py) — 신규, 이후 `db.create_admin_user()` 재사용하도록 리팩터링
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) — "관리자 계정 관리" 카드
- [public/js/dashboard/render.js](../../public/js/dashboard/render.js), [api.js](../../public/js/dashboard/api.js), [events.js](../../public/js/dashboard/events.js)
- [public/css/dashboard.css](../../public/css/dashboard.css)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_app.py](../../tests/test_app.py)
