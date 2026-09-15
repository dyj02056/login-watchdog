# ============================================================================
# db/_client.py — Supabase 연결과 공용 시각 헬퍼
#
# 원래 db.py 최상단에 있던 부분을 그대로 옮겨왔다. db 패키지의 다른 모든
# 모듈(attempts.py, users.py 등)이 이 파일의 get_client()/_now_iso()를 쓴다.
# ============================================================================

import os
from datetime import datetime, timezone

from supabase import Client, create_client

# 프로그램 전체에서 Supabase 연결을 딱 하나만 만들어서 재사용하기 위한 변수.
# 처음엔 비어있다가(None), 처음 필요할 때 한 번만 실제 연결을 만듭니다.
_client: Client | None = None


def get_client() -> Client:
    """Supabase(데이터베이스)에 접속하는 연결 객체를 돌려준다.

    이미 한 번 접속해뒀다면 새로 접속하지 않고 기존 연결을 재사용한다
    (전화를 걸 때마다 새로 다이얼하지 않고, 이미 연결된 통화선을 계속 쓰는 것과 비슷함).
    """
    global _client
    if _client is None:
        # .env 파일에 적어둔 주소(URL)와 비밀 열쇠(KEY)를 읽어와서 접속을 시도한다.
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_KEY"]
        _client = create_client(url, key)
    return _client


def _now_iso() -> str:
    """지금 이 순간의 시각을 데이터베이스가 알아듣는 표준 문자열 형식으로 돌려준다.

    이름 앞의 밑줄(_)은 "이 함수는 이 파일 안에서만 쓰는 내부용 도구"라는 표시.
    """
    return datetime.now(timezone.utc).isoformat()
