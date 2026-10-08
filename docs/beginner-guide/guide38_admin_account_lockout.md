# 38단계 — 관리자 계정 단위 잠금 (분산 브루트포스 대응)

[◀ 37단계](guide37_session_and_code_hardening.md) · [전체 목차](beginner-guide.md)

> 관리자 로그인(`/admin/login`)은 지금까지 **IP 단위**로만 잠겼습니다. 공격자가 IP를 여러 개 돌려 쓰면 IP마다 실패가 4회 이하로 유지되어, 관리자 계정은 사실상 무제한으로 비밀번호를 시도당할 수 있었습니다. 회원 로그인에는 이미 있던 **계정 단위 잠금**을 관리자에게도 적용했습니다.

> ⚠️ **배포 전에** Supabase SQL Editor에서 [docs/migrations/guide38_admin_account_lockout.sql](../migrations/guide38_admin_account_lockout.sql)을 먼저 실행해야 합니다. 새 표가 없으면 `/admin/login`과 대시보드가 오류를 냅니다.

## 무엇이 문제였나

| 공격 방식 | IP 잠금 (기존) | 결과 |
|---|---|---|
| 한 IP에서 계속 시도 | 60초에 5회 초과 → 잠금 | ✅ 막힘 |
| IP 100개로 나눠서 IP당 4회씩 | 어느 IP도 기준을 넘지 않음 | ❌ 400번 시도 가능 |

회원 로그인은 이 빈틈을 [계정 단위 잠금](guide24_l7_attack_hardening.md)(`account_lockouts`)으로 막고 있었지만, 관리자 로그인에는 없었습니다. 관리자 계정이 뚫리면 회원 삭제·잠금 해제·권한 관리까지 전부 넘어가므로 더 위험한 곳이 오히려 비어 있던 셈입니다.

## 설계 결정 4가지

### ① 회원 표를 같이 쓰지 않고 `admin_account_lockouts`를 따로 만든다

`account_lockouts`는 `username`이 기본키입니다. 회원 `alice`와 관리자 `alice`가 동시에 있을 수 있으니, 같은 표를 쓰면 **관리자 계정을 공격하면 같은 이름의 회원까지 잠깁니다**(반대도 마찬가지). 또 회원 잠금에는 이메일 복구·보호관찰·영구 승격이 얽혀 있어서 관리자에게는 맞지 않습니다.

같은 이유로 보안 이벤트 정리도 나눴습니다. `security_events.username`은 회원과 관리자가 같은 칸을 쓰므로:

| 잠금 해제 | 정리하는 이벤트 |
|---|---|
| 회원 계정 | `ADMIN_DISTRIBUTED_BRUTE_FORCE`를 **뺀** CRITICAL 이벤트 |
| 관리자 계정 | `ADMIN_DISTRIBUTED_BRUTE_FORCE`**만** |

### ② 잠금이 공격 수단이 되지 않게 — 허용 목록 IP는 계정 잠금을 건너뛴다

계정 단위 잠금에는 부작용이 있습니다. 공격자가 **일부러 틀린 비밀번호를 넣어 관리자를 못 들어오게** 만들 수 있다는 점입니다(서비스 거부). super_admin이 한 명뿐이면 특히 위험합니다. 그래서:

- **허용 목록**(`PERMANENT_LOCK_IP_ALLOWLIST`, [33단계](guide33_permanent_lock.md)에서 만든 "관리자 PC" 목록) IP에서의 로그인은 계정 잠금을 건너뜁니다. IP 잠금은 그대로 적용됩니다. 배포에서는 `TRUST_FORWARDED_FOR=false`라 공격자가 IP를 위조할 수 없습니다.
- 잠금은 회원과 같은 **5분 임시 잠금**뿐이고, **영구 잠금으로 올리지 않습니다** — 관리자를 영구히 못 들어오게 만드는 것 자체가 공격자가 원하는 결과이기 때문입니다. 대신 감사용으로 잠금 이력(`lock_history`, `target_kind='admin_account'`)은 남깁니다.
- 허용 목록 IP에서 이미 잠긴 계정으로 또 틀려도 **다시 잠그지 않습니다**(Slack 알림이 실패마다 반복되지 않게).

### ③ 회원보다 긴 창: 15분 안에 8회 초과

회원 기준(60초에 8회 초과)을 그대로 쓰면 분당 7회씩 천천히 시도하는 공격(하루 약 1만 회)이 통과합니다. 관리자는 몇 명뿐이라 정상적인 오탐이 거의 없으므로 **15분**으로 늘렸습니다.

| 설정 | 기본값 | 뜻 |
|---|---|---|
| `ADMIN_ACCOUNT_FAILURE_THRESHOLD` | 8 | 이 횟수를 **초과**하면 잠금 |
| `ADMIN_ACCOUNT_DETECTION_WINDOW_SECONDS` | 900 | 실패를 세는 창(15분), IP 무관 |

### ④ 관리자 아이디가 있는지 드러나지 않게

로그인 화면은 회원과 관리자가 같은 모양이라, "잠겼다"는 응답으로 관리자 아이디를 알아낼 수 있으면 안 됩니다. 그래서 **아이디가 실제로 있든 없든** `admin_login_log`의 실패 기록만으로 똑같이 잠그고, 문구도 IP 잠금과 같은 "잠긴 계정입니다. 잠시 후 다시 시도해주세요."를 씁니다.

## 바뀐 로그인 순서

```
1. 만료된 IP 잠금 + 관리자 계정 잠금 정리
2. 허니팟 검사                                   (기존)
3. IP 잠금이면 거절                               (기존)
4. 관리자 계정 잠금이면 거절 — 허용 목록 IP는 건너뜀   ← 신규, 비밀번호 확인 전
5. 비밀번호 확인 + admin_login_log 기록            (기존)
6. 실패 시: IP 기준 초과 → IP 잠금                  (기존)
           아니면 계정 기준 초과 → 관리자 계정 잠금    ← 신규
```

잠긴 계정은 4번에서 끝나므로 **맞는 비밀번호를 넣어도 확인 자체를 하지 않습니다** — 잠금 중에 비밀번호를 맞춰볼 기회가 없습니다.

## 잠기면 무엇이 일어나나

| 항목 | 내용 |
|---|---|
| 잠금 | `admin_account_lockouts`에 5분 |
| Slack | CRITICAL 알림, "관리자 계정: <아이디>"와 관련 IP 개수 |
| 보안 이벤트 | `ADMIN_DISTRIBUTED_BRUTE_FORCE` (CRITICAL, username 포함) → 상관분석(27단계)으로도 이어짐 |
| 잠금 이력 | `lock_history`에 `admin_account` 한 줄 (영구 승격 없음) |
| 대시보드 | "현재 잠긴 IP / 계정" 카드에 **"관리자 계정 잠금"** 카드 |

## 푸는 방법

| 방법 | 누가 |
|---|---|
| 5분 뒤 자동 해제 | — |
| 대시보드 카드의 "즉시 해제" (`POST /api/unlock-admin-account`) | **super_admin만** (`unlock_admin_account` 권한). 다른 역할에는 "해제는 super_admin만 가능" 안내만 보임 |
| 허용 목록 IP에서 그냥 로그인 | 잠긴 본인 |
| `python scripts/unlock_account.py --admin --username <아이디>` | 서버 접근 권한이 있는 사람 (super_admin 본인이 잠겼는데 허용 목록 밖일 때의 비상 수단). `--admin`만 주면 목록 조회만 함 |

회원 계정 해제(`/api/unlock-account`)는 `unlock_ip` 권한(security_admin도 보유)인데, 관리자 계정 해제는 위험도가 더 높아서 권한을 따로 나눴습니다.

## 시연 방법 (로컬)

`.env`에 `TRUST_FORWARDED_FOR=true`를 켜고, IP를 바꿔가며 **IP당 4회씩**(IP 잠금 기준 5회 초과에 걸리지 않게) 보냅니다.

```bash
python scripts/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.21
python scripts/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.22
python scripts/bruteforce_sim.py --admin --username demo_admin --attempts 4 --ip 203.0.113.23
```

앞의 두 번은 `[FAIL]`(잠금 문구 없음)로 끝나는 게 정상입니다 — IP 잠금이 걸리지 않았다는 뜻입니다. 세 번째 실행의 첫 시도에서 총 9회가 되어 계정이 잠기고, 이후 시도는 "이미 잠김"으로 표시됩니다. 허용 목록 기본값에 `127.0.0.1`이 있지만, 가짜 IP(`--ip`)로 보낸 요청에는 적용되지 않습니다.

## 이번에 하지 않은 것

- **LLM 조기 경보 연동** — 임계값 코앞(6~8회)에서 LLM에게 묻는 기능([31단계](guide31_llm_judgment_agent.md))은 관리자 계정에는 아직 없습니다. 승인 대기 표에 새 조치(`LOCK_ADMIN_ACCOUNT`)를 추가해야 해서 다음 단계로 미뤘습니다.
- **2단계 인증(TOTP)** — 근본적인 대책이지만 비밀 저장·등록 QR·복구 코드·2단계 로그인 화면이 필요해서 별도 단계로 분리합니다. 계정 잠금은 TOTP를 도입한 뒤에도 유효한 방어선입니다.

## 확인한 결과

자동 테스트 524개 → **552개**, 전부 통과 (`tests/test_admin_account_lockout.py` 28개 신규).

| 묶음 | 확인한 것 |
|---|---|
| db/detector | `admin_login_log`를 아이디·15분 창으로 셈 / 8회는 통과, 9회는 수상 / 잠금은 관리자 전용 표에 / 해제 결과 True·False / 이벤트 정리가 회원·관리자 유형으로 나뉨 |
| 로그인 흐름 | 여러 IP의 실패 누적 → 잠금 / 잠긴 계정은 맞는 비밀번호도 확인 없이 거절 / 없는 아이디도 같은 문구 / 허용 목록 IP는 로그인 가능 / 이미 잠긴 계정 재잠금 안 함 / IP 잠금이 먼저 / IP 기준이 계정 기준보다 우선 / 회원 잠금이 관리자 로그인에 영향 없음 |
| soar | 잠금 → Slack(관리자 표시) → 이벤트 → 이력 순서, 영구 승격 호출 안 함 / 자동 해제 시 관리자 이벤트만 정리 |
| API·CLI | super_admin 해제 성공, 권한 없으면 403, 아이디 없으면 400 / `/api/status`에 목록 포함·만료 정리 / `--admin` 해제·조회, `--permanent`와 함께 쓰면 거부 |

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [db/admin_lockouts.py](../../db/admin_lockouts.py), [docs/migrations/guide38_admin_account_lockout.sql](../migrations/guide38_admin_account_lockout.sql), [tests/test_admin_account_lockout.py](../../tests/test_admin_account_lockout.py)
- 수정: [routes/admin.py](../../routes/admin.py), [soar.py](../../soar.py), [detector.py](../../detector.py), [alert.py](../../alert.py), [config.py](../../config.py), [db/security_events.py](../../db/security_events.py), [db/\_\_init\_\_.py](../../db/__init__.py), `db/lock_history.py`(설명), [docs/schema.sql](../schema.sql), `public/js/dashboard/{render,api,events}.js`, [scripts/unlock_account.py](../../scripts/unlock_account.py), [scripts/bruteforce_sim.py](../../scripts/bruteforce_sim.py), `tests/conftest.py`
