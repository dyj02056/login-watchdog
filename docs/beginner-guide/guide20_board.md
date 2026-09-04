# 20단계 — 게시판·댓글 기능 추가

[◀ 19단계](guide19_security_hardening.md) · [전체 목차](beginner-guide.md) · [21단계 ▶](guide21_anomaly_detection.md)

> 회원 전용 영역에 게시판·댓글 기능을 새로 추가했습니다. 이번엔 코드를 바로 짜지 않고, 먼저 "지금 코드가 어떻게 생겼는지"를 분석하고, 모호한 부분 11가지를 질문으로 정리해서 하나씩 답을 정한 뒤, 그 결정을 바탕으로 계획서를 쓰고 나서야 실제 코드를 만들었습니다. 이 순서를 기록해둔 문서가 [docs/board-comment/](../board-comment)에 그대로 남아있습니다 — 이번 단계는 그 문서들의 내용을 이 해설서 스타일로 풀어 쓴 것입니다.

### 우리가 한 일
1. [docs/board-comment/research_board.md](../board-comment/research_board.md) — 기존 코드의 구조·관례·위험요소를 먼저 분석
2. [docs/board-comment/02-design-decisions.md](../board-comment/02-design-decisions.md) — 접근 범위, 삭제 권한, 대댓글 여부 등 모호한 질문 11개에 대한 답을 확정
3. [docs/board-comment/plan_board.md](../board-comment/plan_board.md) — 스키마·라우트·함수 설계를 담은 구현 계획 수립
4. [docs/schema.sql](../schema.sql)에 `posts`, `comments`, `post_attempts`, `comment_attempts` 표 4개 추가
5. [db.py](../../db.py)에 게시글/댓글 CRUD + 빈도 제한 함수 17개, [detector.py](../../detector.py)에 판정 함수 2개, [app.py](../../app.py)에 라우트 12개 추가
6. 게시글 목록(`board_list.html`), 상세(`board_detail.html`), 작성/수정 폼(`board_form.html`) 화면과 전용 스타일(`board.css`) 신규 제작
7. 관리자 대시보드에 "게시판 관리" 섹션(임의 게시글·댓글 삭제) 추가
8. `pytest` 94개 + 실제 브라우저 검증까지 마친 뒤, 검증 중 발견한 버그 2건 수정
9. 사용자 피드백을 받아 새 댓글 알림 주기를 5초로 조정하고, 이 값을 `config.py`로 이관

---

## 왜 이렇게 설계했는가 (쉬운 설명)

**왜 "판정→조치" 구조(`detector.py`/`soar.py`)를 게시판에는 안 썼는가**
4단계에서 만든 `detector.py`(판사)와 `soar.py`(집행관)는 "임계값을 넘으면 자동으로 잠근다"는 브루트포스 탐지 전용 개념입니다. 게시글을 쓰고 지우는 데는 이런 "자동 판정 후 조치" 흐름이 없습니다. 그래서 게시판은 `member_profile_submit()`처럼 `db.py` 함수를 `app.py`에서 바로 부르는 더 단순한 패턴을 따랐습니다. 판사·집행관 비유를 억지로 가져다 쓰면 "판사가 게시글 검열도 한다"는 이상한 개념이 생기기 때문입니다.

**작성자를 `users` 표와 연결(FK)하지 않고 문자열로만 저장한 이유**
3단계에서 만든 `login_attempts`(로그인 기록)는 `username`을 문자열로만 저장하고 `users` 표와 연결하지 않습니다 — "회원이 탈퇴해도 로그인 기록은 감사 로그로 남아야 한다"는 이유였습니다. `posts`/`comments`의 `author_username`도 똑같은 이유로 FK를 걸지 않았습니다. 만약 FK를 걸고 회원 삭제 시 `on delete cascade`로 묶었다면, 관리자가 회원 하나를 지울 때 그 사람이 쓴 글·댓글이 전부 같이 사라지는데, 이건 게시판 성격상 다른 사람들이 보던 글이 갑자기 없어지는 부작용이 있어 "흔적은 남기고 유지"하는 쪽을 선택했습니다.

**댓글에 대댓글(답글)을 안 만든 이유**
대댓글을 넣으려면 `comments` 표에 `parent_comment_id`라는 "자기 자신을 가리키는" 칸을 추가하고, 화면에서도 들여쓰기·펼치기 같은 로직이 필요해집니다. 이번 요구사항에는 그 정도 복잡도가 필요 없다고 판단해 단순한 1단(depth) 구조로 정했습니다.

**본문에 `<script>` 같은 태그를 입력해도 안전한 이유 — `|safe` 없이 줄바꿈만 살리기**
회원가입의 아이디처럼 "영문자/숫자만 허용"하는 화이트리스트 정규식은 게시글 본문에는 쓸 수 없습니다(한글, 문장부호를 다 막아버리게 됩니다). 그렇다고 본문에 실제 HTML 서식을 허용하면 XSS(Stored XSS, 6단계에서 실제로 한 번 겪은 문제 유형) 위험이 생깁니다. 그래서 **입력은 그대로 저장**하고, **출력할 때 이스케이프를 절대 끄지 않는** 방법을 택했습니다. Jinja2는 기본적으로 `{{ post.body }}`처럼 값을 출력할 때 `<`, `>` 같은 문자를 자동으로 안전한 문자(HTML 엔티티)로 바꿔줍니다. 문제는 이 상태로는 사용자가 입력한 줄바꿈(Enter)도 그냥 사라져 보인다는 것인데, 이걸 살리려고 보통 쓰는 `nl2br` 필터나 `|safe`는 "이 문자열은 진짜 HTML이니 이스케이프하지 마"라는 뜻이라 다시 위험이 열립니다. 대신 CSS `white-space: pre-wrap;` 속성 하나로 "글자는 그대로 안전하게 이스케이프하되, 줄바꿈만 화면에 그대로 보여달라"고 브라우저에게 지시했습니다 — 코드(이스케이프 로직)는 하나도 안 건드리고 스타일만으로 문제를 풀었습니다.

**"새 댓글 알림"을 웹소켓이 아니라 폴링으로 만든 이유**
관리자 대시보드(`dashboard.js`)가 이미 "몇 초마다 서버에 다시 물어본다"는 폴링 방식을 검증된 패턴으로 쓰고 있습니다. 게시글 상세 화면도 실시간성이 꼭 필요하진 않아서(댓글이 몇 초 늦게 반영돼도 괜찮음), 같은 패턴을 재사용했습니다. 다만 관리자 대시보드처럼 표 전체를 다시 그리지는 않고, "최신 댓글 개수/시각"만 가볍게 물어봐서 값이 바뀌었을 때만 "새로운 댓글이 추가되었습니다"라는 배너를 띄우는 더 단순한 방식을 썼습니다. 배너를 누르면 그냥 페이지를 새로고침합니다 — 댓글 하나만 화면에 끼워넣는 정교한 로직 없이 가장 단순하게 만들었습니다.

**관리자 삭제를 회원 삭제 API와 별도로 만든 이유**
`/api/board/posts/delete`, `/api/board/comments/delete`는 `/api/users/delete`와 똑같은 패턴입니다 — `login_required`(관리자 문지기)를 이미 통과했으므로, "이 사람이 관리자인가"는 다시 확인하지 않고 삭제 실행에만 집중합니다. 반면 회원이 자기 글을 지우는 `/board/<id>/delete`는 `member_login_required`(로그인 여부만 확인)를 통과한 뒤에도, 라우트 함수 안에서 **"이 글의 작성자가 정말 나인가"**를 한 번 더 직접 검사합니다. 문지기가 확인하는 것과 코드가 추가로 확인해야 하는 것이 서로 다르다는 걸 보여주는 부분입니다.

---

## 실제 코드 함께 보기

**`docs/schema.sql` — 작성자는 FK 없이 텍스트로, 댓글은 글이 지워지면 함께 지워지게**
```sql
create table posts (
  id bigint generated always as identity primary key,
  author_username text not null,
  title text not null,
  body text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table comments (
  id bigint generated always as identity primary key,
  post_id bigint not null references posts(id) on delete cascade,
  author_username text not null,
  body text not null,
  created_at timestamptz not null default now()
);
```
`comments.post_id`는 `posts(id)`를 참조하며 `on delete cascade`가 붙어 있습니다 — "글이 지워지면 그 글의 댓글도 자동으로 같이 지워진다"는 뜻으로, 회원 탈퇴 때와는 다른 이유의 cascade입니다(글 하나가 사라지면 그 밑의 댓글은 당연히 의미가 없어지므로).

**`db.py` — 페이지네이션은 `.range()` 한 줄로**
```python
def list_posts(page: int, page_size: int) -> list[dict]:
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        get_client()
        .table("posts")
        .select("*")
        .order("created_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data
```
`.range(start, end)`는 Supabase가 기본으로 제공하는 "몇 번째 행부터 몇 번째 행까지만 줘"라는 기능입니다. 2페이지, 페이지당 10개면 `range(10, 19)`가 되어 11~20번째 글만 가져옵니다 — 별도 페이지네이션 라이브러리 없이 이 한 줄로 "페이지 번호 방식"을 구현했습니다.

**`app.py` — 회원은 본인 글만, 관리자는 전부 지울 수 있게**
```python
def _is_post_owner(post: dict) -> bool:
    return post["author_username"] == session.get("username")


@app.route("/board/<int:post_id>/delete", methods=["POST"])
@member_login_required
def board_delete(post_id):
    post = db.get_post(post_id)
    if post is None:
        flash("존재하지 않는 게시글입니다.")
        return redirect(url_for("board_list"))
    if not _is_post_owner(post):
        flash("본인이 작성한 글만 삭제할 수 있습니다.")
        return redirect(url_for("board_detail", post_id=post_id))
    db.delete_post(post_id)
    flash("게시글이 삭제되었습니다.")
    return redirect(url_for("board_list"))


@app.route("/api/board/posts/delete", methods=["POST"])
@login_required
def api_board_posts_delete():
    data = request.get_json(silent=True) or {}
    post_id = data.get("post_id")
    deleted = db.delete_post(post_id)
    return jsonify({"success": deleted})
```
회원용 라우트(`board_delete`)는 소유권을 직접 검사하지만, 관리자용 API(`api_board_posts_delete`)는 이미 `login_required`가 "로그인된 관리자"임을 보장해줬기 때문에 별도 검사 없이 바로 삭제를 실행합니다.

**`public/js/board.js` — 새 댓글을 가볍게 확인하는 폴링**
```javascript
async function checkForNewComments() {
    const response = await fetch(`/api/board/${boardPostId}/comments/latest`);
    if (!response.ok) return;
    const data = await response.json();
    const latestAt = data.latest_at || "";

    if (data.count !== knownCommentCount || latestAt !== knownLatestAt) {
        document.getElementById("new-comment-banner").hidden = false;
    }
}

setInterval(checkForNewComments, boardPollIntervalMs);
```
`data.latest_at || ""` 부분이 왜 필요한지는 아래 "검증 중 발견한 버그" 절에서 설명합니다. `boardPollIntervalMs`는 숫자가 이 파일에 직접 적혀있지 않고, 화면의 `data-poll-interval-ms` 속성에서 읽어옵니다 — 이 부분도 아래에서 따로 설명합니다.

---

## 실제로 확인한 것

1. `pytest tests/` — 게시판 관련 단위/통합 테스트를 추가해 **94개 전부 통과** (회원 전용 접근 제어, 본인 글/댓글 소유권 검사, 빈도 제한 시 요청 단락 처리, 관리자 API의 인증/CSRF 검증 포함)
2. 실제 로컬 서버 + 실 Supabase에 연결해 브라우저로 직접 확인
   - 회원가입 → 로그인 → 회원 대시보드의 "게시판 바로가기" → 글쓰기 → 목록/상세 반영
   - 본문에 `<script>alert(1)</script>`를 입력해도 화면에는 `&lt;script&gt;`라는 글자 그대로만 보이고, 개발자 도구로 확인해도 진짜 `<script>` 태그가 만들어지지 않는 것을 직접 확인
   - 줄바꿈이 있는 본문을 저장해도 그대로 줄바꿈이 유지되는 것 확인
   - 댓글 작성 → 새로고침 없이 "새로운 댓글이 추가되었습니다" 배너 노출 확인
   - 글 수정, 댓글 삭제(본인), 글 삭제(본인 — 딸린 댓글도 함께 삭제됨) 확인
   - 관리자 대시보드 "게시판 관리" 섹션에서 임의 글/댓글 삭제 확인
3. 검증에 사용한 테스트 계정·게시글은 확인 후 정리

**Supabase 반영 — 이번에도 코드만으로는 끝나지 않았습니다**: 2단계, 19단계에서 이미 겪었던 것과 똑같은 이유로, `docs/schema.sql`에 SQL을 적어두는 것과 실제 운영 중인 Supabase 프로젝트 안에 그 표가 존재하는 것은 별개의 일입니다. 사용자가 직접 Supabase SQL Editor에서 새 테이블 4개(`posts`, `comments`, `post_attempts`, `comment_attempts`) 생성 SQL을 실행한 뒤에야 `/board`가 정상 동작했습니다 — 반영 전에는 `"Could not find the table 'public.posts' in the schema cache"`라는 오류로 500 에러가 났고, 이 오류 메시지를 실제로 보고 나서 무엇을 해야 하는지 안내했습니다.

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`posts`, `comments`, `post_attempts`, `comment_attempts` 4개 표 추가, Supabase에도 SQL Editor로 직접 반영 완료)
- [config.py](../../config.py) (`BOARD_PAGE_SIZE`, `POST_RATE_LIMIT`, `COMMENT_RATE_LIMIT` 추가)
- [db.py](../../db.py) (게시글/댓글/빈도제한 함수 17개 추가)
- [detector.py](../../detector.py) (`is_post_rate_limited`, `is_comment_rate_limited` 추가)
- [app.py](../../app.py) (게시판 라우트 10개 + 관리자용 게시글/댓글 관리 API 2개 추가, `api_status()` 확장)
- [templates/board_list.html](../../templates/board_list.html), [templates/board_detail.html](../../templates/board_detail.html), [templates/board_form.html](../../templates/board_form.html) (신규)
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) ("게시판 관리" 섹션 추가), [templates/member_dashboard.html](../../templates/member_dashboard.html) ("게시판 바로가기" 링크 추가)
- [public/css/board.css](../../public/css/board.css) (신규), [public/js/board.js](../../public/js/board.js) (신규)
- [public/js/dashboard.js](../../public/js/dashboard.js) (게시글/댓글 관리용 렌더링·삭제 함수 추가)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py) (게시판 관련 테스트 추가, 총 94개 통과)
- [docs/board-comment/](../board-comment) (구현 전 분석 → 설계 결정 → 구현 계획 → 결과 정리, 문서 4종 신규)

---

## 검증 중 발견한 버그 2개 수정

바로 위 내용을 실제 브라우저로 검증하다가 두 가지 문제를 발견해서 그 자리에서 바로 고쳤습니다.

### 문제 1 — 댓글이 하나도 없는데도 "새 댓글" 배너가 뜸

서버가 돌려주는 API 응답을 보면, 댓글이 0개인 글은 `latest_at`이 파이썬의 `None`(자바스크립트에서는 `null`)으로 내려옵니다. 그런데 페이지가 처음 그려질 때 화면에 심어두는 기준값은 빈 문자열(`""`)이었습니다. 자바스크립트에서 `null !== ""`은 참(true)입니다 — 즉 "값이 바뀌었다"고 항상 착각하게 되어, 댓글이 하나도 안 달렸는데도 배너가 잘못 떴습니다.

**고친 방법**: API에서 받은 값을 비교하기 직전에 `data.latest_at || ""`로 한 번 정리해서, `null`이든 실제 문자열이든 항상 문자열끼리만 비교하게 만들었습니다.
```javascript
const latestAt = data.latest_at || "";
if (data.count !== knownCommentCount || latestAt !== knownLatestAt) { ... }
```

### 문제 2 — "수정" 링크와 "삭제" 버튼의 생김새가 서로 다름

사용자가 실제 화면 스크린샷을 보내주면서 발견됐습니다. `board.css`에 `.board-post-actions button`이라는 규칙을 만들어뒀는데도, `member.css`에 이미 있던 `.member-card button[type="submit"]`이라는 더 강한 규칙에 밀려서 `<button>`(삭제)에는 원치 않는 스타일(전체 폭 + accent 배경)이 적용되고, `<a>` 태그인 "수정"에는 이 규칙이 아예 적용되지 않아 서로 다른 모양이 됐습니다.

CSS는 여러 규칙이 같은 요소를 동시에 겨냥할 때, "더 구체적으로 지정한 규칙"이 이깁니다(이를 **상세도, specificity**라고 부릅니다). `.member-card button[type="submit"]`은 클래스 하나 + 태그 + 속성 조건까지 걸려있어서, 클래스 두 개만 쓴 제 규칙보다 더 "구체적"이라고 브라우저가 판단한 것입니다.

**고친 방법**: 제 규칙도 똑같은 수준으로 구체적이게(`.board-card .board-post-actions button`) 다시 적었습니다. 상세도가 같아지면 "나중에 불러온 CSS 파일이 이긴다"는 규칙이 적용되는데, `board.css`가 `member.css`보다 항상 나중에 `<link>`로 걸려있으므로 `!important` 없이도 제 규칙이 최종 적용되게 만들 수 있었습니다.

---

## 사용자 피드백으로 추가한 개선

기능이 완성된 뒤 실제로 써보면서 세 가지를 더 조정했습니다.

**① 새 댓글 배너 주기를 15초 → 5초로**: 관리자 대시보드(10초)는 한 번에 쿼리 7개가 나가는 무거운 폴링이지만, 게시글 상세의 배너는 쿼리 1개짜리 가벼운 확인이고 사용자가 그 글을 보고 있는 동안에만 도는 것이라 여유가 있다고 판단해 5초로 줄였습니다. 서버 로그에 실제로 5초 간격(`12:04:46 → 51 → 56`)으로 요청이 찍히는 것까지 확인했습니다.

**② 폴링 주기 값을 `config.py`로 이관**: `board.js`(5000)와 `dashboard.js`(10000)에 숫자로 직접 적혀있던 값을 각 파일에서 빼내어 `config.py`에 상수로 모았습니다(1단계에서 "숫자를 한 곳에 모아두면 나중에 하나만 고치면 된다"고 설명했던 것과 같은 원리). 값을 화면까지 전달하는 방식은 화면마다 이미 있던 관례를 그대로 따랐습니다 — `board_detail.html`은 `data-poll-interval-ms` 속성으로, `admin_dashboard.html`은 CSRF 토큰과 똑같이 `<meta name="poll-interval-ms">` 태그로 값을 심어두고 각 JS 파일이 읽어갑니다.

```python
# config.py
BOARD_COMMENT_POLL_MS = int(os.environ.get("BOARD_COMMENT_POLL_MS", 5000))
ADMIN_DASHBOARD_POLL_MS = int(os.environ.get("ADMIN_DASHBOARD_POLL_MS", 10000))
```

이 값을 서버 밖(브라우저)으로 내보내도 안전한지도 짚고 넘어갔습니다. 폴링 주기는 "내 브라우저가 몇 초마다 다시 확인할지"를 정하는 UX용 숫자일 뿐, 서버가 이 숫자를 믿고 뭔가를 허용해주는 게 아닙니다. 게다가 `public/js/*.js`는 애초에 로그인 없이도 누구나 열람 가능한 정적 파일이라, 지금까지도 이 숫자는 이미 완전히 공개돼 있었습니다 — `config.py`로 옮겨도 노출 범위가 늘어나지 않습니다. 진짜 남용 방지는 이 값과 무관하게 서버 쪽의 `POST_RATE_LIMIT`/`COMMENT_RATE_LIMIT`, 그리고 `login_required`/`member_login_required` 문지기가 계속 담당합니다.

**③ 관리자 대시보드 삭제 버튼 스타일 통일**: 게시글/댓글 삭제 버튼(`delete-post-btn`/`delete-comment-btn`)에 클래스는 붙여뒀지만, 정작 `dashboard.css`에는 이 클래스를 위한 스타일 규칙 자체가 없었습니다 — 회원 목록의 삭제 버튼(`delete-user-btn`)만 스타일이 있고, 게시판 관리 섹션을 추가할 때 새 버튼들을 그 규칙에 합치는 걸 빠뜨린 것입니다. 그래서 회원 목록 삭제 버튼이 위험한 조치(빨간 배경)임을 알려주는 것과 달리, 게시글/댓글 삭제 버튼은 브라우저 기본 모양 그대로 밋밋하게 보였습니다.

```css
/* dashboard.css */
.delete-user-btn,
.delete-post-btn,
.delete-comment-btn {
    background: var(--danger);
    color: white;
    border: none;
    border-radius: var(--radius-s);
    padding: 5px 10px;
    cursor: pointer;
    font-family: var(--font-body);
    font-size: 12px;
}
```
CSS 선택자를 콤마로 나열하면 "이 중 아무 클래스나 가진 요소에는 전부 같은 스타일을 적용해라"는 뜻이 됩니다 — 세 버튼이 항상 같은 모양을 유지하도록, 규칙 자체를 하나로 묶었습니다. 실제 글/댓글을 만들어보고 관리자 대시보드에서 세 버튼의 배경색·글자색·패딩·폰트 크기가 완전히 똑같은지(`getComputedStyle`로) 확인했습니다.

### 이 개선으로 추가·변경된 파일
- [config.py](../../config.py) (`BOARD_COMMENT_POLL_MS`, `ADMIN_DASHBOARD_POLL_MS` 추가)
- [app.py](../../app.py) (`board_detail()`, `admin_dashboard()`가 폴링 주기 값을 템플릿에 전달)
- [templates/board_detail.html](../../templates/board_detail.html) (`data-poll-interval-ms` 속성 추가)
- [templates/admin_dashboard.html](../../templates/admin_dashboard.html) (`poll-interval-ms` meta 태그 추가)
- [public/js/board.js](../../public/js/board.js), [public/js/dashboard.js](../../public/js/dashboard.js) (하드코딩된 숫자 제거, 화면에서 값을 읽어오도록 변경)
- [public/css/dashboard.css](../../public/css/dashboard.css) (`.delete-user-btn` 규칙에 `.delete-post-btn`/`.delete-comment-btn` 통합)

---

## 이번 단계에서 얻은 교훈

이번엔 코드를 먼저 짜지 않고 "분석 → 질문 확정 → 계획 → 구현"이라는 순서를 지킨 게 가장 큰 차이였습니다. 특히 "회원 탈퇴 시 게시글은 어떻게 되는가", "비로그인 사용자도 볼 수 있는가" 같은 질문은 코드를 짜기 시작한 뒤에 알게 됐다면 이미 만든 스키마나 라우트를 다시 뜯어고쳐야 했을 결정들이었습니다. 미리 답을 정해두니 구현 자체는 오히려 단순하게 끝났습니다.

또한 실사용 검증(브라우저로 직접 눌러보기)이 자동화 테스트만으로는 못 잡는 문제를 잡아낸다는 걸 다시 확인했습니다 — `null`과 `""`을 다르게 취급하는 버그도, CSS 상세도 충돌 버그도 `pytest`로는 절대 걸리지 않는 종류의 문제였습니다(전자는 브라우저의 JS 실행이, 후자는 실제 렌더링된 화면을 봐야만 드러납니다). 13단계에서도 똑같은 패턴(실사용 중 버그 2개 발견)이 있었는데, 이번에도 같은 교훈이 반복됐습니다.

### 이 단계 전체에서 바뀐 파일 모음
- [app.py](../../app.py), [config.py](../../config.py), [db.py](../../db.py), [detector.py](../../detector.py)
- [docs/schema.sql](../schema.sql)
- [templates/board_list.html](../../templates/board_list.html), [templates/board_detail.html](../../templates/board_detail.html), [templates/board_form.html](../../templates/board_form.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html), [templates/member_dashboard.html](../../templates/member_dashboard.html)
- [public/css/board.css](../../public/css/board.css), [public/css/dashboard.css](../../public/css/dashboard.css), [public/js/board.js](../../public/js/board.js), [public/js/dashboard.js](../../public/js/dashboard.js)
- [tests/test_db.py](../../tests/test_db.py), [tests/test_detector.py](../../tests/test_detector.py), [tests/test_app.py](../../tests/test_app.py)
- [docs/board-comment/](../board-comment) (문서 4종)
