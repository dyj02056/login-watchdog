# ============================================================================
# db/users.py — users 표 관련 함수 (회원가입 기능)
# — 감시 대상이 되는 가짜 로그인 화면(/login)에 실제로 가입해서 로그인하는
#   "일반 사용자" 계정을 관리하는 기능. 관리자(admin_users)와는 완전히 별개 개념.
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

from postgrest.exceptions import APIError
from werkzeug.security import check_password_hash, generate_password_hash

import db

# 타이밍 사이드채널 방지용 더미 해시 (L7 공격 보강 계획 Tier 3) — verify_user_credentials
# 참고. 모듈이 처음 로드될 때 딱 한 번만 계산해서 고정해둔다 — 요청마다 새로
# generate_password_hash를 부르면 그 계산 자체가 또 다른 시간차를 만들어버린다.
_DUMMY_PASSWORD_HASH = generate_password_hash("dummy-password-for-timing-safety")


def get_user_by_username(username: str) -> dict | None:
    """아이디로 사용자 한 명을 찾는다. 없으면 None을 돌려준다."""
    res = (
        db.get_client()
        .table("users")
        .select("*")
        .eq("username", username)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None


def get_user_by_id(user_id: int) -> dict | None:
    """회원 번호(id)로 사용자 한 명을 찾는다.

    로그인 세션에는 아이디(username) 문자열뿐 아니라 이 id도 함께 저장해둔다
    (routes/auth.py의 login_submit() 참고) — 프로필을 수정할 때 "어느 행을 고칠지"를
    아이디가 아니라 변하지 않는 id로 정확히 짚어내기 위해서다.
    """
    res = db.get_client().table("users").select("*").eq("id", user_id).limit(1).execute()
    return res.data[0] if res.data else None


def create_user(username: str, email: str, password: str) -> dict | None:
    """새 사용자 계정을 만든다 (회원가입).

    같은 아이디나 같은 이메일로 이미 가입한 사람이 있으면 실패(None)를 돌려주고
    아무것도 저장하지 않는다. 문제없으면 비밀번호를 암호화해서 저장하고 새 회원 행을 돌려준다.

    반환값:
        새로 만든 회원 행(dict) - 회원가입 성공 (가입 인증 메일을 보낼 때 id·email이 필요하다, guide40)
        None                    - 아이디 또는 이메일이 이미 사용 중이라 가입 실패
    """
    # 1) 아이디 중복 확인
    existing_username = (
        db.get_client().table("users").select("id").eq("username", username).limit(1).execute()
    )
    if existing_username.data:
        return None
    # 2) 이메일 중복 확인
    existing_email = (
        db.get_client().table("users").select("id").eq("email", email).limit(1).execute()
    )
    if existing_email.data:
        return None
    # 3) 문제 없으면 비밀번호를 암호화해서 새 계정 저장
    res = db.get_client().table("users").insert(
        {"username": username, "email": email, "password_hash": generate_password_hash(password)}
    ).execute()
    return res.data[0] if res.data else None


def verify_user_credentials(username: str, password: str) -> bool:
    """사용자가 로그인 화면에 입력한 아이디/비밀번호가 맞는지 확인한다.

    동작 원리는 verify_admin_credentials와 동일 — 저장된 암호문과
    "지금 입력한 비밀번호를 암호화한 결과"가 일치하는지만 비교한다.

    타이밍 사이드채널 방지 (L7 공격 보강 계획 Tier 3): 예전에는 아이디가 없으면
    check_password_hash()를 아예 건너뛰고 바로 False를 돌려줬다. 이 해시 비교는
    일부러 느리게 설계된 연산이라, "즉시 반환(아이디 없음)"과 "해시 비교 후
    반환(비밀번호만 틀림)" 사이에 응답 시간 차이가 생겨 공격자가 그 차이만으로
    "이 아이디가 존재하는가"를 추측할 수 있었다(화면 메시지는 이미 통일돼
    있었지만 타이밍까지는 못 가렸다). 아이디가 없을 때도 미리 만들어둔 더미
    해시로 항상 같은 비교 연산을 거치게 해서 응답 시간을 균일화한다.
    """
    user = get_user_by_username(username)
    password_hash = user["password_hash"] if user else _DUMMY_PASSWORD_HASH
    result = check_password_hash(password_hash, password)
    return result if user else False


def update_user_name(user_id: int, name: str) -> None:
    """회원 본인이 프로필 화면에서 "표시 이름"을 바꿀 때 쓰인다.

    예전 update_user_profile()은 이메일도 함께 바로 바꿨다 — 세션만 있으면 비밀번호 확인도
    메일 확인도 없이 이메일을 바꿀 수 있어서, 세션을 탈취한 사람이 이메일을 자기 주소로 바꿔
    계정을 가져갈 수 있었다(guide40). 이메일 변경은 이제 현재 비밀번호 + 새 주소로 보낸 확인
    링크를 거쳐 change_user_email()로만 일어난다.
    """
    db.get_client().table("users").update({"name": name}).eq("id", user_id).execute()


def is_email_taken(email: str, exclude_user_id: int | None = None) -> bool:
    """이 이메일을 (exclude_user_id가 아닌) 다른 회원이 이미 쓰고 있는지."""
    query = db.get_client().table("users").select("id").eq("email", email)
    if exclude_user_id is not None:
        query = query.neq("id", exclude_user_id)
    return bool(query.limit(1).execute().data)


def change_user_email(user_id: int, new_email: str) -> bool:
    """새 주소로 보낸 확인 링크를 누른 뒤에만 불린다(guide40) — 이메일을 바꾸고, 링크를 눌렀다는
    것 자체가 메일함 주인이라는 증거이므로 VERIFIED로 표시한다.

    링크를 누르기 전에 다른 사람이 그 주소로 가입했을 수 있으므로 여기서 다시 확인하고, 그래도
    두 요청이 겹쳐 unique 제약에 걸리면(23505) False를 돌려준다.
    """
    if is_email_taken(new_email, exclude_user_id=user_id):
        return False
    try:
        db.get_client().table("users").update(
            {"email": new_email, "email_status": "VERIFIED", "email_status_checked_at": db._now_iso()}
        ).eq("id", user_id).execute()
    except APIError as e:
        if e.code != "23505":
            raise
        return False
    return True


def mark_user_email_verified(user_id: int, email: str) -> bool:
    """이 회원의 이메일이 아직 `email`일 때만 VERIFIED로 표시한다(guide40). 실제로 바뀌었으면 True.

    조건에 email을 넣는 이유: 인증 메일을 보낸 뒤 회원이 이메일을 바꿨다면, 옛 주소로 간
    인증 링크가 새 주소를 "인증됨"으로 만들면 안 되기 때문이다.
    """
    res = (
        db.get_client()
        .table("users")
        .update({"email_status": "VERIFIED", "email_status_checked_at": db._now_iso()})
        .eq("id", user_id)
        .eq("email", email)
        .execute()
    )
    return bool(res.data)


def list_users(page: int = 1, page_size: int = 100) -> tuple[list[dict], int]:
    """가입된 회원 목록을 최신 가입순으로 `page`번째 페이지만 가져오고, 전체 회원 수도
    함께 돌려준다 (1부터 시작). select(..., count="exact") + range()를 한 번에 써서
    목록 조회와 전체 개수 조회를 별도 쿼리 두 번이 아니라 한 번의 왕복으로 끝낸다
    (list_recent_attempts() 참고 — 관리자 대시보드 응답 속도 개선).

    password_hash 칸은 일부러 요청하지 않는다 — 암호화된 값이라 그 자체로는
    안전하지만, 화면에 굳이 내보낼 이유가 없는 값은 애초에 조회 단계에서부터
    빼두는 게 "혹시 모를 실수로 노출되는 사고"를 막는 가장 확실한 방법이다.
    """
    start = (page - 1) * page_size
    end = start + page_size - 1
    res = (
        db.get_client()
        .table("users")
        .select("id, username, email, email_status, created_at", count="exact")
        .order("created_at", desc=True)
        .range(start, end)
        .execute()
    )
    return res.data, res.count or 0


def delete_user(user_id: int) -> bool:
    """회원 계정을 하나 삭제한다 (관리자 전용 기능).

    삭제된 사람의 과거 로그인 시도 기록(login_attempts)은 그대로 남는다 —
    그 표는 username을 문자열로만 저장하고 users 표와 연결(FK)되어 있지 않기
    때문이다(3단계 설명 참고). 즉 계정을 지워도 "이 아이디가 예전에 시도했던
    기록" 자체는 감사 로그로 계속 남는다.

    반환값: 실제로 삭제된 행이 있었으면 True, 애초에 그런 id가 없었으면 False.
    """
    res = db.get_client().table("users").delete().eq("id", user_id).execute()
    return len(res.data) > 0


# ============================================================================
# 비밀번호 변경 + 세션 무효화 (guide35)
#
# users.session_version은 "이 계정의 로그인 세션 세대 번호"다. 로그인할 때 그 번호를 세션에
# 같이 넣어두고, 회원 화면에 들어올 때마다(helpers.member_login_required) DB의 번호와
# 비교한다. 비밀번호를 바꾸면 번호를 1 올리므로, 바꾸기 전에 만들어진 다른 기기의 세션은
# 번호가 맞지 않아 자동으로 로그아웃된다(탈취된 세션도 함께 끊긴다).
# ============================================================================

def get_user_session_version(user_id: int) -> int | None:
    """이 회원의 현재 세션 세대 번호. 회원이 없으면(삭제됨) None."""
    res = db.get_client().table("users").select("session_version").eq("id", user_id).limit(1).execute()
    if not res.data:
        return None
    return res.data[0].get("session_version") or 0


def update_user_password(user_id: int, new_password: str) -> int:
    """비밀번호를 바꾸고 세션 세대 번호를 1 올린 뒤, 새 번호를 돌려준다.

    번호는 "읽은 값 그대로일 때만" 올린다(조건부 UPDATE) — 두 기기에서 거의 동시에 바꾸는
    드문 경우에도 번호가 한 번 덜 올라가 이전 세션이 살아남는 일이 없게, 경쟁에서 지면
    다시 읽어서 한 번 더 시도한다.
    """
    password_hash = generate_password_hash(new_password)
    for _ in range(3):
        current = get_user_session_version(user_id) or 0
        res = (
            db.get_client()
            .table("users")
            .update({"password_hash": password_hash, "session_version": current + 1})
            .eq("id", user_id)
            .eq("session_version", current)
            .execute()
        )
        if res.data:
            return current + 1
    raise RuntimeError("비밀번호 변경 중 세션 번호 갱신 경쟁이 반복되었습니다.")
