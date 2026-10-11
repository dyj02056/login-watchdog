# 32. 부록

<aside>
🎯 **한 줄 요약**
앞의 31개 단원이 "기능이 어떻게 동작하나"였다면, 부록은 **"프로젝트 전체에서 무엇이 어디에 있나"** 를 찾아보는 **지도**입니다. 계층별 파일 · 기능별 테스트 · 공격별 시뮬레이터 · DB 표를 한곳에서 찾을 수 있습니다.
</aside>

> 🗺️ **클릭해서 코드를 볼 수 있는 파일 지도**: [32-appendix.html](32-appendix.html) — 다른 단원과 달리 **실행 순서가 아니라 "분야별 지도"** 입니다. 카드를 누르면 그 분야의 대표 코드가 열립니다.
> 📚 **계층**: Layer 6. 부록

---

## 🧱 32.1 이 계층 구조가 의미하는 것

| 계층 | 한 줄 설명 | 단원 |
|---|---|---|
| **Layer 1. 기반 기능** | 사용자가 직접 쓰는 화면 (감시 대상) | 1~4 |
| **Layer 2. 탐지** — "판사" | "이거 수상한가?"를 **판단만** 함 (`security/detector.py`) | 5~7 |
| **Layer 3. 대응** — "집행관"·"형사" | 실제로 **잠그고·알리고·엮고**, 필요하면 AI에게 물음 | 8~11 |
| **Layer 4. 관리** — 사람의 최종 판단 | 자동 대응을 사람이 **보고 되돌림** | 12~14 |
| **Layer 5. 방어 강화·확장** | 개별 취약점 보강, 영구 잠금·복구·이메일 인증·화면 어댑터 등 | 15~31 |

<aside>
⚖️ **이 프로젝트의 설계 원칙 한 줄**
**"판단(Layer 2)"과 "실행(Layer 3)"을 분리**하고, 그 위에 **"사람의 최종 확인(Layer 4)"** 을 얹는다.

`security/detector.py`는 **절대 아무것도 바꾸지 않고**, `security/soar/`만 실제로 잠급니다. 덕분에 "판단 기준만 바꾸고 싶다"거나 "이 조치는 사람 승인을 거치게 하고 싶다"(11단원 AI 조기 경보) 같은 변경이 **기존 코드를 건드리지 않고** 가능합니다. 영구 잠금(16단원)도 같은 구조입니다 — 판정은 `detector.py`에 "잠금 종류"만 추가했고, 승격·해제라는 새 실행은 `soar`의 확장인 `lockdown.py`가 맡았습니다.
</aside>

---

## 🧪 32.2 테스트 커버리지 — 기능 ↔ 테스트 파일

```bash
pytest        # 현재 718개, 몇 초 안에 끝남
```

| 테스트 파일 | 대상 기능 |
|---|---|
| `tests/test_app.py` | 라우트 전반 + `app.py`·`helpers/hooks.py` (보안 헤더, 에러 핸들러, 훅) |
| `tests/test_detector.py` | `security/detector.py` 판정 함수 전체 |
| `tests/test_soar.py` | `security/soar/` 조치 함수 전체 |
| `tests/test_db.py` | `db/*.py` 데이터 계층 |
| `tests/test_geoip.py` | `services/geoip.py` 위치 조회/캐싱 (4단원) |
| `tests/test_correlate.py` | `security/correlate.py` 상관분석 (9단원) |
| `tests/test_early_warning.py` | LLM 조기 경보 (11단원) |
| `tests/test_password_spraying_sim.py` | Password Spraying 시나리오 (5단원) |
| `tests/test_tune_thresholds.py` | 임계값 튜닝 리포트 (14단원) |
| `tests/test_unlock_ip.py` | `scripts/management/unlock_ip.py` |
| `tests/test_helpers.py` | `helpers/` 공용 함수 |
| `tests/test_config.py` | `config.py` 값 로딩 |
| `tests/test_permanent_lock.py` · `test_permanent_admin_api.py` | 영구 잠금 승격·해제·관리자 API (16단원) |
| `tests/test_recovery.py` | 이메일 복구·메일 발송·로그인 예외 (17단원) |
| `tests/test_unlock_permanent.py` | unlock 스크립트 `--permanent` (16단원) |
| `tests/test_send_test_mail.py` | 메일 설정 점검 스크립트 (17단원) |
| `tests/test_password_change.py` | 비밀번호 변경·세션 해제 (18단원) |
| `tests/test_db_client.py` | DB 연결 재시도 (19단원) |
| `tests/test_admin_session.py` | 관리자 세션 검증 (20단원) |
| `tests/test_admin_account_lockout.py` | 관리자 계정 단위 잠금 (21단원) |
| `tests/test_email_verification.py` | 이메일 인증·이메일 변경 보호 (23단원) |
| `tests/test_password_reset.py` | 비밀번호 찾기 (24단원) |
| `tests/test_log_retention.py` · `test_daily_log_summary.py` | 로그 자동 정리·일별 요약 SQL (26단원) |
| `tests/test_polling.py` | 보이지 않는 탭 폴링 중지 (27단원) |
| `tests/test_dashboard_speed.py` | 대시보드 즉시 반응 (28단원) |
| `tests/test_ipv6_prefix.py` | IPv6 /64 대역 정규화 (29단원) |
| `tests/test_spa.py` | Next.js 껍데기 서빙·CSP 해시·JSON 변환·폴백 (30단원) |
| `tests/test_stats.py` | 관제 화면 집계 `db/stats.py` (30단원) |
| `tests/test_demo_logs.py` | 샘플 로그 도구 (31단원) |

---

## 💥 32.3 시뮬레이션 스크립트 — 공격 ↔ 시뮬레이터

> 모두 **내 컴퓨터(로컬) 서버에만** 실행되도록 안전장치가 걸려 있습니다. 31단원의 점검기가 전부 한 번에 돌립니다.

### 🔴 critical — 잠금까지 일어나는 공격
| 스크립트 | 대상 |
|---|---|
| `critical/bruteforce_sim.py` | 브루트포스 (5단원) |
| `critical/password_spraying_sim.py` | Password Spraying (5단원) |
| `critical/distributed_bruteforce_sim.py` | 분산 브루트포스 — 계정 단위 잠금 |
| `critical/admin_bruteforce_sim.py` | 관리자 로그인 무차별 대입 — IP 잠금 |
| `critical/admin_distributed_bruteforce_sim.py` | 관리자 분산 브루트포스 (21단원) |
| `critical/permanent_lock_sim.py` | 영구 잠금 승격 (16단원) |
| `critical/incident_correlation_sim.py` | 다단계 공격 사건화·영구 차단 (9단원) |

### 🟠 high — 요청 거부가 일어나는 공격
| 스크립트 | 대상 |
|---|---|
| `high/signup_abuse_sim.py` | 가입 도배 (6단원) |
| `high/spam_sim.py` | 게시글/댓글 도배 (6·3단원) |
| `high/comment_spam_sim.py` | 댓글 도배 |
| `high/http_flood_sim.py` | HTTP 플러딩 — 전역 요청 한도 (15단원) |
| `high/recovery_flood_sim.py` | 복구·비밀번호 찾기·이메일 확인 폭주 (25단원) |

### 🟡 medium — 알림·기록만 하는 공격
| 스크립트 | 대상 |
|---|---|
| `medium/web_scanning_sim.py` | Web Scanning (6단원) |
| `medium/unauthorized_access_sim.py` | Unauthorized Access (6단원) |
| `medium/repeated_access_sim.py` | 반복 페이지 접근 (6단원) |
| `medium/macro_bot_sim.py` | API 매크로/봇 (7단원) |
| `medium/honeypot_bot_sim.py` | 허니팟 봇 차단 (15단원) |

### 🛠️ 운영·점검 도구 (`scripts/management/`, `scripts/demo/`)
| 스크립트 | 하는 일 |
|---|---|
| `management/tune_thresholds.py` | 임계값 튜닝 리포트 (14단원) |
| `management/daily_report.py` | 일일 리포트 (AI 요약 포함) |
| `management/unlock_ip.py` · `unlock_account.py` | 터미널에서 수동 잠금 해제 (영구 잠금은 `--permanent --note "사유"`) |
| `management/send_test_mail.py` | 메일 발송 설정 점검 (17단원) |
| `management/create_admin.py` | 관리자 계정 생성 |
| `management/delete_security_events.py` | 보안 이벤트 정리 |
| `demo/check_simulations.py` | 시뮬레이터 전부를 메모리 DB 서버에서 한 번에 점검 (31단원) |
| `demo/generate_demo_logs.py` · `demo_server.py` · `load_demo_to_supabase.py` · `demo_data.py` | 7일치 샘플 로그와 데모 서버 (30·31단원) |

---

## 🗄️ 32.4 DB 스키마 — 표 30개

전체 정의는 `docs/schema.sql`, 표별 설명은 `docs/feature-reference/db-schema-guide.md`입니다. 처음 19개 표에서 시작해 지금은 **30개**입니다. 기존 DB에 추가로 실행할 SQL은 `docs/migrations/`에 있습니다.

| 분야 | 표 |
|---|---|
| 회원·관리자·권한 | `users`, `admin_users`, `roles`, `permissions` |
| 로그인·접근 기록 | `login_attempts`, `admin_login_log`, `signup_attempts`, `not_found_attempts`, `unauthorized_attempts`, `page_access_attempts`, `api_access_log` |
| 잠금 | `lockouts`, `account_lockouts`, `admin_account_lockouts`, `lock_history` |
| 이벤트·사건·승인 | `security_events`, `security_incidents`, `access_requests` |
| 복구·이메일 | `recovery_requests`, `ip_lock_exemptions`, `email_tokens` |
| 게시판·설정·캐시 | `posts`, `comments`, `post_attempts`, `comment_attempts`, `app_settings`, `ip_locations` |
| 로그 요약 | `log_daily_summary`, `log_daily_breakdown`, `log_summary_state` |

---

## 🚧 32.5 알려진 제한사항 (의도된 미구현 범위)

전체 목록은 `README.md`의 "알려진 제한사항"을 참고하세요. 이 문서들과 관련된 주요 항목:

| 제한 | 이유·설명 | 단원 |
|---|---|---|
| **Automated Scraping(게시글 번호 순차 조회) 미차단** | 게시판이 "회원 전체 공개" 설계라 버그가 아니라 **의도된 범위** | 3, 6 |
| **영구 잠금은 이미 로그인된 세션을 끊지 않음** | 세션은 비밀번호를 바꿀 때만 끊김 | 16, 18 |
| **비밀번호 찾기는 인증된 이메일에만** | 이메일을 인증하지 않은 회원은 관리자가 처리. 관리자 계정의 재설정은 제공하지 않음 | 24 |
| **회원가입 응답은 아직 가입 여부를 알려줌** | "이미 사용 중인 아이디 또는 이메일입니다" | 22 |
| **지운 로그는 되돌릴 수 없음** | 30·90일 지난 원본은 매일 새벽 지워지고 요약표에는 건수만 남음 | 26 |
| **DB 기록 요청은 연결 끊김 시 재시도하지 않음** | 두 번 기록되는 것을 막기 위한 선택이라 드물게 오류가 날 수 있음 | 19 |
| **네트워크(L3)/전송(L4) 계층 공격 미구현** | SYN Flood, 포트 스캐닝 등. 현재는 **애플리케이션 계층(L7)** 공격 대응에 집중 | 15 |

---

⬅️ 이전: 31. 시뮬레이션 일괄 점검 · ➡️ 다음: 없음(마지막 단원)
