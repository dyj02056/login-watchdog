# 21단계 — 이상행위 탐지 보완 (캡스톤 검토 문서 후속 조치)

[◀ 20단계](guide20_board.md) · [전체 목차](beginner-guide.md)

> 캡스톤 프로젝트 검토 문서(`attack_response_state.md`)에서 "구현 가능성 있는 항목"으로 정리했던 6가지를, 리스크가 낮은 것부터(기존 결함 보완 → 기존 패턴 재사용 → 새 설계가 필요한 것 순으로) 하나씩 구현합니다. 항목이 늘어날 때마다 이 문서에 절을 추가합니다.

### 우리가 한 일 (진행 순서)

| # | 문제 | 난이도 | 성격 |
|---|---|---|---|
| 1 | 게시글 수정(`board_edit_submit`)에 빈도 제한이 빠져있음 | 매우 낮음 | 20단계(게시판) 보완 |
| 2 | Brute Force와 Password Spraying이 Slack 알림에서 구분되지 않음 | 낮음 | 4단계(soar/alert) 보완 |
| 3 | 존재하지 않는 경로(404) 반복 요청(Web Scanning)을 전혀 기록/탐지하지 않음 | 낮음 | 신규 탐지 |
| 4 | 관리자 API에 세션 없이 반복 접근(401)해도 기록/알림이 없음 | 낮음~중간 | 신규 탐지 |
| 5 | 같은 페이지를 반복 요청하는 패턴을 전혀 관찰하지 않음 | 중간 | 신규 탐지 |

---

## 1. 게시글 수정(`board_edit_submit`)에는 빈도 제한이 빠져 있었다

### 무엇이 문제였는가
20단계에서 게시판 기능을 만들 때, 새 글 작성(`board_new_submit()`)에는 `detector.is_post_rate_limited()`로 도배(스팸) 방지를 걸어뒀지만, 같은 화면(`board_form.html`)을 재사용하는 글 수정(`board_edit_submit()`)에는 이 검사를 빼먹었습니다. 소유권 확인(`_is_post_owner`)만 있고, "얼마나 자주 수정을 시도했는가"는 전혀 세지 않는 상태였습니다.

### 왜 위험한가
새 글 작성은 막혀 있어도, 이미 있는 자기 글 하나를 짧은 시간에 수백 번 수정 요청으로 두드리는 건 그대로 가능했습니다. 매번 `posts` 표에 UPDATE가 발생하므로 DB 부하를 유발할 수 있고, "게시글 반복 작성(Spam)"을 완전히 구현했다고 문서(`attack_response_state.md` 1절)에 적어뒀던 것과 실제 코드 사이에 괴리가 있었습니다.

### 어떻게 고쳤는가
`board_new_submit()`과 완전히 동일한 판정 순서(먼저 판정 → 통과하면 시도 자체를 기록 → 그다음 실제 처리)를 `board_edit_submit()`에도 그대로 적용했습니다. 새 표를 만들지 않고 기존 `post_attempts`(및 `POST_RATE_LIMIT`)를 그대로 공유합니다 — 글 작성이든 수정이든 "이 IP가 게시글 관련 POST를 얼마나 자주 보내는가"라는 같은 성격의 남용이기 때문입니다.

```python
# app.py — board_edit_submit()
post = db.get_post(post_id)
if post is None:
    flash("존재하지 않는 게시글입니다.")
    return redirect(url_for("board_list"))
if not _is_post_owner(post):
    flash("본인이 작성한 글만 수정할 수 있습니다.")
    return redirect(url_for("board_detail", post_id=post_id))

form_action = url_for("board_edit_submit", post_id=post_id)

# board_new_submit()과 동일한 빈도 제한 — 글 수정도 도배 대상이 될 수 있으므로
# 새 글 작성과 같은 post_attempts 카운트를 공유한다.
ip = get_request_ip()
if detector.is_post_rate_limited(ip):
    flash("너무 많은 게시글 작성 시도가 감지되었습니다. 잠시 후 다시 시도해주세요.")
    return render_template("board_form.html", form_action=form_action, post=post)
db.log_post_attempt(ip)

title = request.form.get("title", "").strip()
body = request.form.get("body", "").strip()
```

새 함수나 새 표는 필요 없었습니다 — `detector.is_post_rate_limited()`, `db.log_post_attempt()` 모두 20단계에서 이미 만들어둔 것을 그대로 재사용했습니다.

### 실제로 확인한 것
`tests/test_app.py`에 두 개의 테스트를 추가했습니다.
1. `test_board_edit_submit_rejects_when_rate_limited` — 빈도 제한에 걸리면 `db.update_post`가 아예 호출되지 않고 안내 메시지만 뜨는지
2. `test_board_edit_submit_updates_post_and_redirects` — 정상적인 수정 요청은 여전히 통과해서 상세 화면으로 리다이렉트되는지

`pytest tests/ -v` 전체(96개)를 돌려 전부 통과하는 것도 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [app.py](../../app.py) (`board_edit_submit()`에 빈도 제한 체크 추가)
- [tests/test_app.py](../../tests/test_app.py) (관련 테스트 2개 추가)

---

## 2. Brute Force와 Password Spraying이 Slack 알림에서 구분되지 않았다

### 무엇이 문제였는가
`detector.is_suspicious()`가 세는 `count_recent_failures(ip)`는 아이디와 무관하게 "이 IP가 실패한 총 횟수"만 셌습니다. 그래서 `admin` 계정 하나를 6번 노린 공격과, `admin1`~`admin6`처럼 서로 다른 계정을 한 번씩 돌아가며 시도한 공격(Password Spraying)이 완전히 똑같은 Slack 메시지("실패 횟수: 6회")로 나갔습니다. `attack_response_state.md` 1절에도 "Password Spraying은 부수적으로만 커버되고, 별도로 구분해 로그/알림하지는 않는다"고 정확히 지적돼 있었습니다.

### 왜 필요한가
관리자 입장에서 이 둘은 대응이 달라야 합니다 — 계정 하나 집중 공격은 "그 계정의 비밀번호가 약한가"를 의심하면 되지만, 여러 계정을 순회하는 공격은 "이 서비스의 계정 목록 자체가 어디선가 유출됐거나 흔한 아이디 목록으로 훑이고 있다"는, 훨씬 넓은 범위의 문제를 의심해야 하기 때문입니다. 지금까지는 알림만 봐서는 이 둘을 구분할 방법이 없었습니다.

### 어떻게 고쳤는가
새 표는 만들지 않고, 이미 있는 `login_attempts`/`admin_login_log`의 `username` 칸을 활용해 "최근 실패에 쓰인 서로 다른 아이디 개수"를 세는 함수를 4단계(`db.py`/`detector.py`) 계층에 대칭으로 추가했습니다.

```python
# db.py — login_attempts용. admin_login_log를 보는 count_recent_distinct_admin_usernames도 동일한 구조.
def count_recent_distinct_usernames(ip: str, window_seconds=config.DETECTION_WINDOW_SECONDS) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
    res = (
        get_client().table("login_attempts").select("username")
        .eq("ip_address", ip).eq("success", False).gte("attempted_at", cutoff)
        .execute()
    )
    return len({row["username"] for row in res.data})
```

`detector.py`에는 판정 없이 그대로 전달만 하는 얇은 함수 2개(`count_distinct_usernames`, `count_distinct_admin_usernames`)를 추가했고, `soar.enforce_lockout(ip, failure_count, distinct_usernames)`처럼 이 값을 받는 매개변수를 하나 더 받게 해서 `alert.send_lockout_alert()`까지 그대로 흘려보냅니다.

```python
# alert.py — Slack 메시지에 공격 유형 한 줄 추가
if distinct_usernames > 1:
    pattern_line = f"공격 유형: Password Spraying 의심 (서로 다른 아이디 {distinct_usernames}개 시도)"
else:
    pattern_line = "공격 유형: Brute Force (단일 계정 집중 시도)"
```

`enforce_lockout`의 매개변수가 하나 늘었으므로, 이 함수를 호출하는 `login_submit()`/`admin_login_submit()`(app.py) 두 곳 모두에서 잠그기 직전에 아이디 개수를 먼저 센 뒤 넘겨주도록 고쳤습니다.

### 실제로 확인한 것
`tests/test_db.py`(dedup 로직: 같은 아이디 2번 + 다른 아이디 1번 → 결과 2), `tests/test_detector.py`(단순 전달 확인), `tests/test_soar.py`/`tests/test_app.py`(세 번째 인자가 `enforce_lockout`까지 정확히 전달되는지, 회원 로그인은 3개 아이디, 관리자 로그인은 1개 아이디 시나리오로 각각)에 테스트를 추가했습니다. 매개변수가 늘어나며 기존 잠금 테스트 4개도 함께 손봐야 했습니다(19단계에서 `SIGNUP_RATE_LIMIT` 추가 때 겪었던 것과 같은 종류의 작업). `pytest tests/ -v` 전체(100개) 통과를 확인했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [db.py](../../db.py) (`count_recent_distinct_usernames`, `count_recent_distinct_admin_usernames` 신규 추가)
- [detector.py](../../detector.py) (`count_distinct_usernames`, `count_distinct_admin_usernames` 신규 추가)
- [soar.py](../../soar.py) (`enforce_lockout`에 `distinct_usernames` 매개변수 추가)
- [alert.py](../../alert.py) (`send_lockout_alert`에 공격 유형 구분 줄 추가)
- [app.py](../../app.py) (`login_submit()`, `admin_login_submit()` 두 호출부 모두 수정)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_soar.py](../../tests/test_soar.py), [tests/test_app.py](../../tests/test_app.py)

---

## 3. 존재하지 않는 경로(404) 반복 요청을 전혀 기록/탐지하지 않았다

### 무엇이 문제였는가
지금까지 이 프로젝트는 Flask의 기본 404 처리에만 의존했습니다 — 존재하지 않는 주소로 요청이 오면 그냥 기본 404 화면을 보여주고 끝이었고, "누가, 얼마나 자주, 어떤 경로를 두드렸는지"는 어디에도 기록되지 않았습니다.

### 왜 필요한가
공격자가 자동화 스크립트로 `/admin.php`, `/wp-login.php`, `/.env`, `/config.bak`처럼 흔히 있을 법한 관리 경로·설정 파일 이름을 순서대로 훑어보는 것(Web Scanning)은 실제 침투의 첫 단계로 매우 흔합니다. 이 프로젝트는 지금까지 이런 행위가 벌어져도 서버 로그를 직접 뒤지지 않는 한 전혀 알 방법이 없었습니다.

### 어떻게 고쳤는가
로그인 브루트포스 탐지와 같은 "카운트 → 임계값 초과 시에만 대응" 구조를 그대로 재사용했습니다. 다만 대응 방식은 다릅니다 — 로그인 실패는 그 IP를 잠그면 되지만(공격 대상인 계정이 명확), 404는 애초에 존재하지 않는 경로를 두드린 것이라 "잠글" 대상이 없습니다. 그래서 잠금 없이 Slack 알림만 보냅니다.

```python
# app.py
@app.errorhandler(404)
def handle_not_found(error):
    ip = get_request_ip()
    db.log_not_found_attempt(ip, request.path)

    suspicious, count = detector.is_web_scanning(ip)
    if suspicious and count == config.WEB_SCANNING_ALERT_THRESHOLD + 1:
        soar.notify_web_scanning(ip, count, request.path)

    return error.get_response()  # 화면은 Flask 기본 404 그대로 유지
```

`enforce_lockout()`은 "잠긴 상태"라는 별도 표시(`lockouts.active`)가 있어서 알림을 딱 한 번만 보내지만, 404에는 그런 상태가 없습니다. 대신 "카운트가 정확히 `임계값+1`이 되는 바로 그 요청"에서만 알리도록 해서 같은 효과(임계값을 넘는 매 요청마다 알림이 반복되는 "알림 피로"를 방지)를 냈습니다.

새 표(`not_found_attempts`)와 새 설정값(`WEB_SCANNING_ALERT_THRESHOLD`, 기본 10)을 추가했고, `soar.py`에는 잠금 없이 알림만 보내는 `notify_web_scanning()`을 추가해 `app.py`가 여전히 `alert.py`를 직접 부르지 않고 `soar.py`를 통해서만 알림을 보내는 기존 구조를 유지했습니다.

### 실제로 확인한 것
`tests/test_db.py`(기록·카운트 함수), `tests/test_detector.py`(경계값: 정확히 10회는 아직 아님, 11회부터 수상), `tests/test_app.py`(404가 여전히 404로 응답하는지, 임계값을 막 넘긴 순간에만 정확히 1번 알리는지, 이미 넘긴 뒤 후속 요청에서는 다시 알리지 않는지, 임계값 미만에서는 알리지 않는지 4가지 시나리오)에 테스트를 추가했습니다. `pytest tests/ -v` 전체(108개) 통과를 확인했습니다.

**Supabase 반영 필요**: 19단계·20단계와 마찬가지로, `docs/schema.sql`에 SQL을 적어두는 것과 실제 운영 중인 Supabase 프로젝트에 그 표가 존재하는 것은 별개입니다. 실제 배포 환경에서 이 기능이 동작하려면, Supabase SQL Editor에서 아래 SQL을 직접 실행해 `not_found_attempts` 표를 만들어야 합니다 (docs/schema.sql 맨 아래 새로 추가된 부분).

```sql
create table not_found_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_not_found_attempts_ip_time on not_found_attempts (ip_address, attempted_at);
```

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`not_found_attempts` 표 추가 — Supabase 프로젝트에는 아직 미반영, 위 SQL을 직접 실행 필요)
- [config.py](../../config.py) (`WEB_SCANNING_ALERT_THRESHOLD` 추가)
- [db.py](../../db.py) (`log_not_found_attempt`, `count_recent_not_found_attempts` 추가)
- [detector.py](../../detector.py) (`is_web_scanning` 추가)
- [alert.py](../../alert.py) (`send_web_scanning_alert` 추가, 웹훅 전송 로직을 `_send_slack_message`로 공통화)
- [soar.py](../../soar.py) (`notify_web_scanning` 추가)
- [app.py](../../app.py) (`@app.errorhandler(404)` 신규 추가)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py)

---

## 4. 관리자 API에 세션 없이 반복 접근(401)해도 기록/알림이 없었다

### 무엇이 문제였는가
`login_required()`의 `/api/*` 분기는 세션이 없으면 401 JSON을 돌려주기는 했지만, "누가 얼마나 자주 이 401을 유발했는지"는 어디에도 남기지 않았습니다. 3번(Web Scanning)과 함께 `attack_response_state.md` 1절에서 "🟡 절반만 구현"으로 표시됐던 항목입니다 — 차단은 되지만 반복 시도를 관찰할 방법이 없었습니다.

### 왜 필요한가
공격자가 관리자 세션 쿠키나 토큰을 무작위로 대입하며 `/api/users/delete`, `/api/unlock` 같은 관리자 전용 API를 직접 두드려보는 것도 흔한 정찰 패턴입니다. 3번(존재하지 않는 경로)과 다른 점은, 여기서 두드리는 경로는 **실제로 존재하는** 민감한 API라는 것 — 그만큼 더 눈여겨봐야 할 신호입니다.

### 어떻게 고쳤는가
3번과 거의 동일한 구조(새 표 `unauthorized_attempts` + "카운트 → 임계값 초과 시에만 알림")를 재사용했습니다. 다만 이번엔 계획 문서에 "잠금 여부는 별도 결정"이라고 열려 있던 부분을 직접 판단해야 했습니다 — **잠그지 않기로 결정**했습니다. 이유는 관리자 대시보드 화면(`admin_dashboard.html`)이 열려있는 동안 `ADMIN_DASHBOARD_POLL_MS`(기본 10초)마다 `/api/*`를 자동으로 계속 호출한다는 점입니다. 만약 관리자의 세션이 만료된 뒤에도 그 탭을 닫지 않았다면, 이 폴링이 그대로 401을 반복 유발하게 되고, 만약 이 상황에서 IP를 잠갔다면 정작 그 관리자 본인이 재로그인조차 못 하게 되는 자충수가 될 뻔했습니다. 그래서 이 항목도 3번처럼 관찰(Slack 알림)까지만 자동화합니다.

```python
# app.py — login_required()의 401 분기
if "admin_username" not in session:
    if request.path.startswith("/api/"):
        ip = get_request_ip()
        db.log_unauthorized_attempt(ip, request.path)
        suspicious, count = detector.is_unauthorized_access_suspicious(ip)
        if suspicious and count == config.UNAUTHORIZED_ACCESS_ALERT_THRESHOLD + 1:
            soar.notify_unauthorized_access(ip, count, request.path)
        return jsonify({"error": "로그인이 필요합니다."}), 401
    return redirect(url_for("admin_login"))
```

`member_login_required()`(회원용)는 `/api/` 특례 자체가 없어(항상 로그인 화면으로 리다이렉트) 이번 대상에서 제외했습니다 — 계획 문서도 "login_required의 401 분기"로 관리자 쪽만 명시하고 있었습니다.

### 실제로 확인한 것
새 db/detector 함수 각각에 대한 단위 테스트에 더해, `tests/test_app.py`에 3번과 동일한 4가지 시나리오(기록되는지, 임계값을 막 넘긴 순간에만 정확히 1번 알리는지, 이후 요청에서는 다시 알리지 않는지, 임계값 미만에서는 알리지 않는지)를 추가했습니다. 기존에 있던 `/api/status`, `/api/board/posts/delete` 관련 미인증 테스트 2개도 새로 추가된 db 호출을 가짜로 채워넣도록 손봐야 했습니다(19단계에서 겪은 것과 같은 종류의 작업). `pytest tests/ -v` 전체(116개) 통과를 확인했습니다.

**Supabase 반영 필요**: `docs/schema.sql`에 추가된 아래 SQL을 Supabase SQL Editor에서 직접 실행해야 실제 배포 환경에서 동작합니다.

```sql
create table unauthorized_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_unauthorized_attempts_ip_time on unauthorized_attempts (ip_address, attempted_at);
```

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`unauthorized_attempts` 표 추가 — Supabase 프로젝트에는 아직 미반영)
- [config.py](../../config.py) (`UNAUTHORIZED_ACCESS_ALERT_THRESHOLD` 추가)
- [db.py](../../db.py) (`log_unauthorized_attempt`, `count_recent_unauthorized_attempts` 추가)
- [detector.py](../../detector.py) (`is_unauthorized_access_suspicious` 추가)
- [alert.py](../../alert.py) (`send_unauthorized_access_alert` 추가)
- [soar.py](../../soar.py) (`notify_unauthorized_access` 추가)
- [app.py](../../app.py) (`login_required()`의 401 분기에 기록·알림 로직 추가)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py)

---

## 5. 같은 페이지를 반복 요청하는 패턴을 전혀 관찰하지 않았다

### 무엇이 문제였는가
3번(Web Scanning)과 4번(Unauthorized Access)은 각각 "존재하지 않는 경로"와 "세션 없는 관리자 API 401"이라는 **좁고 명확한** 신호만 관찰했습니다. 이 프로젝트에는 그것 말고도 "정상적으로 존재하고, 로그인도 필요 없는 페이지 하나를 스크립트가 반복 요청하는" 패턴(예: 특정 게시글 상세 화면을 자동화 도구로 계속 새로고침)을 관찰할 방법이 전혀 없었습니다.

### 왜 필요한가
이 프로젝트에는 "상품 목록/상세" 같은 스크래핑 대상 도메인 자체가 없어서 `attack_response_state.md`도 Automated Scraping은 "범위 밖"으로 분류했습니다. 하지만 그 축소판이라 할 수 있는 "같은 URL을 비정상적으로 자주 두드리는 행동" 자체는 게시판(`/board/1` 등) 같은 기존 화면에도 똑같이 적용될 수 있는 신호이므로, 별도로 관찰할 가치가 있습니다.

### 어떻게 고쳤는가 — 그리고 무엇을 먼저 판단해야 했는가
3번/4번과 똑같은 "카운트 → 임계값 초과 시에만 알림" 구조를 재사용하되, 이번엔 **어디에 훅을 걸지**부터 결정해야 했습니다. 특정 라우트 하나가 아니라 "이 애플리케이션의 거의 모든 GET 페이지"가 감시 대상이므로, 개별 라우트마다 코드를 추가하는 대신 Flask의 `@app.before_request`(라우팅이 끝난 직후, 실제 뷰 함수를 부르기 직전에 항상 실행되는 훅)를 하나만 등록했습니다.

문제는 이 훅이 **정말로 모든 요청**에서 실행된다는 점이었습니다. 이 프로젝트는 이미 스스로 자동 폴링을 두 군데 만들어뒀습니다.
- `dashboard.js` → `/api/status`를 10초마다 자동 호출
- `board.js` → `/api/board/<id>/comments/latest`를 5초마다 자동 호출

이걸 빼놓지 않으면, 브라우저 탭 하나만 열어놔도 이 폴링 자체가 임계값을 계속 넘겨서 "정상적으로 화면을 켜둔 사용자"가 항상 수상한 사람으로 잘못 판정됩니다. 그래서 이 두 엔드포인트(그리고 정적 파일을 서빙하는 Flask 내장 `static` 엔드포인트)를 명시적으로 제외 목록에 넣었고, 존재하지 않는 경로(404, 이미 3번이 별도로 기록)와 GET이 아닌 요청도 제외했습니다.

```python
# app.py
_PAGE_ACCESS_EXCLUDED_ENDPOINTS = {"static", "api_status", "api_board_comments_latest"}


@app.before_request
def track_page_access():
    if request.method != "GET" or request.url_rule is None:
        return
    if request.endpoint in _PAGE_ACCESS_EXCLUDED_ENDPOINTS:
        return

    ip = get_request_ip()
    db.log_page_access_attempt(ip, request.path)

    suspicious, count = detector.is_page_access_suspicious(ip, request.path)
    if suspicious and count == config.PAGE_ACCESS_ALERT_THRESHOLD + 1:
        soar.notify_page_access(ip, count, request.path)
```

또 하나 결정할 부분은 "무엇을 세는가"였습니다 — "이 IP의 전체 요청 수"를 셀지, "이 IP가 이 특정 경로를 요청한 횟수"를 셀지. 후자를 선택했습니다. 여러 페이지를 정상적으로 둘러보는 사람(예: `/board` → `/board/1` → `/board/2`)과, 같은 페이지 하나를 스크립트로 반복 요청하는 사람을 구분하려면 "경로별"로 세야 하기 때문입니다. 그래서 `page_access_attempts` 표는 `ip_address`뿐 아니라 `path`도 함께 저장하고, `count_recent_page_access_attempts(ip, path)`처럼 두 값을 모두 필터링합니다.

### 실제로 확인한 것
이 훅은 사실상 이 프로젝트의 **거의 모든 기존 테스트**(어떤 페이지든 GET으로 접근하는 테스트라면 전부)에 영향을 줬습니다 — 미리 막아두지 않으면 30개 테스트가 한꺼번에 진짜 Supabase로 네트워크 요청을 시도해 실패했습니다. 그래서 다른 항목들과 달리, `tests/conftest.py`의 공용 `flask_app` fixture에 "기본값은 항상 수상하지 않음"으로 미리 막아두는 코드를 추가해, 이 훅과 무관한 기존 테스트들은 손대지 않고도 계속 통과하게 했습니다. 이 항목 자체를 검증하는 새 테스트 7개(정상 기록, 임계값을 막 넘긴 순간에만 알림, 반복 알림 방지, 임계값 미만 무알림, 정적 파일 제외, 폴링 API 제외, 존재하지 않는 경로 제외)는 각자 필요한 값으로 다시 monkeypatch해서 실제 동작을 확인했습니다. `pytest tests/ -v` 전체(127개) 통과를 확인했습니다.

**Supabase 반영 필요**: `docs/schema.sql`에 추가된 아래 SQL을 Supabase SQL Editor에서 직접 실행해야 실제 배포 환경에서 동작합니다.

```sql
create table page_access_attempts (
  id bigint generated always as identity primary key,
  ip_address text not null,
  path text not null,
  attempted_at timestamptz not null default now()
);
create index idx_page_access_attempts_ip_path_time on page_access_attempts (ip_address, path, attempted_at);
```

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`page_access_attempts` 표 추가 — Supabase 프로젝트에는 아직 미반영)
- [config.py](../../config.py) (`PAGE_ACCESS_ALERT_THRESHOLD` 추가)
- [db.py](../../db.py) (`log_page_access_attempt`, `count_recent_page_access_attempts` 추가)
- [detector.py](../../detector.py) (`is_page_access_suspicious` 추가)
- [alert.py](../../alert.py) (`send_page_access_alert` 추가)
- [soar.py](../../soar.py) (`notify_page_access` 추가)
- [app.py](../../app.py) (`@app.before_request track_page_access()` 신규 추가)
- [tests/conftest.py](../../tests/conftest.py) (`flask_app` fixture에 새 훅 기본 무력화 추가)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py)
