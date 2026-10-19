# AGENTS.md — login-watchdog 작업 규칙 (Codex용)

## 프로젝트
- Flask 로그인 보안 모니터링 앱. DB는 Supabase(REST), 관리자 화면은 Next.js 정적 빌드(web/ → spa/, public/_next/).
- 지금 진행 중인 확장은 Track D(네트워크 계층 탐지·차단). 기준 문서:
  - docs/track-d/contracts.md  ← 함수 이름·인자·JSON 모양의 기준. 여기와 다르게 만들지 말 것.
- 요청문과 함께 plan-excerpt.md(상위 계획서 발췌)가 첨부되면, 그 파일 맨 위 "이 발췌보다 우선하는 것" 표를 본문보다 먼저 따른다. 이 파일을 저장소 안에 저장하지 않는다.

## 반드시 지킬 것
1. 요청문에 "고칠 파일"로 적힌 파일만 수정한다. 다른 파일을 고쳐야 할 것 같으면 고치지 말고 마지막 보고에 적는다.
2. 다음 파일은 절대 수정하지 않는다: app.py, helpers/hooks.py, db/__init__.py, routes/internal/__init__.py, tests/track_d/conftest.py, spa/**, public/_next/**, docs/migrations/에 이미 있는 파일.
3. config.py와 .env.example은 맨 아래 "# === Track D ===" 구역 안의, 요청문이 지정한 소구역만 수정한다.
4. 새 DB 함수는 기존 db/*.py가 아니라 역할별 새 모듈(B: db/network_events.py·db/playbook_runs.py, C: db/network_blocks.py·db/agent_heartbeats.py)에 넣고, 그 파일의 __all__에 이름을 추가한다. db/__init__.py는 건드리지 않는다. 기존 db 함수에 기본값 있는 선택 인자를 더하는 것은 요청문이 허락할 때만 한다.
5. 기존 함수의 이름·인자·반환값을 바꾸지 않는다. 기존 테스트를 삭제하거나 기대값을 바꾸지 않는다.
6. 테스트는 tests/track_d/test_<역할>_*.py에 새로 만든다. 실제 DB·네트워크에 접속하지 않게 monkeypatch로 db.* 함수를 가짜로 바꾼다. 아직 없는 함수를 바꿀 때는 monkeypatch.setattr(..., raising=False)를 쓴다.
7. netwatch/ 아래 프로그램은 다른 컨테이너에서 돈다. 앱 코드(db, config, routes 등)를 import하지 않고, 컨테이너 전용 라이브러리는 netwatch/<이름>/requirements.txt에 둔다. 루트 requirements.txt는 고치지 않는다.
8. 주석과 docstring은 한국어로, 기존 파일처럼 "왜 이렇게 하는지"를 적는다.
9. 비밀값(키·토큰·비밀번호)을 코드나 테스트에 실제 값으로 넣지 않는다. 테스트에는 "test-ingest-secret" 같은 가짜 값을 쓴다. .env 파일은 열어 보지도 출력하지도 않는다.
10. Supabase REST는 트랜잭션이 없다. 동시성은 조건부 UPDATE(.eq("status", 이전값))와 유니크 인덱스로 처리한다(기존 db/*.py 방식).
11. 커밋·푸시·브랜치 변경은 하지 않는다. 작업이 끝나면 아래 형식으로 보고한다.

## 끝났을 때 보고 형식
- 바꾼 파일 목록
- 실행한 명령과 결과 (pytest tests/ -q 마지막 줄)
- 요청문 중 하지 못한 것 / 계약서와 다르게 한 것 (없으면 "없음")
- 담당 밖 파일을 고쳐야 할 것 같은 곳 (없으면 "없음")

#dfsdfdsfsd

## 자주 쓰는 명령
- 테스트: pytest tests/ -q
- 특정 테스트: pytest tests/track_d/test_b_ingest.py -q
