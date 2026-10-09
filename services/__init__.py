# ============================================================================
# services/ — 외부 서비스 연동과 계정 부가 흐름
#
#   services/email_verification.py — 이메일 인증·변경 확인·비밀번호 재설정 토큰 흐름 (guide40/41)
#   services/llm_client.py         — Groq LLM 호출, 조기 경보 판정 (guide31)
#   services/geoip.py              — IP 위치 조회(ip-api) + 캐시
#   services/ip_utils.py           — IP 정규화(IPv6 /64 대역), 역방향 조회
#
# 이 파일은 일부러 비워둔다(재내보내기 없음) — 호출부는 `from services import geoip`처럼
# 모듈 단위로 가져다 쓴다. 배경은 docs/refactor/2026-10-09-module-plan.md 참고.
# ============================================================================
