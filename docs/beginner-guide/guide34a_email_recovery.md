# 34단계 — 이메일 인증으로 영구 잠금 해제

[◀ 33단계](guide33_permanent_lock.md) · [전체 목차](beginner-guide.md) · [35단계 ▶](guide35_password_change.md)

> [33단계](guide33_permanent_lock.md)의 영구 잠금은 관리자만 풀 수 있으면 억울하게 잠긴 사용자가 기다려야 합니다. 이 단계에서는 **본인 이메일로 인증하면 스스로 풀 수 있는** `/recovery` 화면을 만들었습니다. 다만 IP와 계정은 성격이 달라서 풀리는 방식이 다릅니다.

## 누구를 보호하는 잠금인가 — 풀리는 방식이 다른 이유

| 대상 | 의미 | 이메일 인증을 하면 |
|---|---|---|
| **계정** 영구 잠금 | 피해 계정을 지키려는 조치 | 계정 주인에게 메일을 보내 **완전히 해제** (이후 24시간 보호관찰) |
| **IP** 영구 잠금 | 같은 IP를 여러 명이 쓸 수 있다(학교·회사 NAT) | IP는 계속 잠긴 채, 인증한 **"본인 + 본인 기기"에게만 예외(출입증)** 발급 |
| **관리자 로그인 IP**, 이메일을 신뢰할 수 없는 계정, 보호관찰 중 재잠금 | 위험도가 높음 | 이메일로 풀 수 없음 — 관리자만 |

IP를 이메일로 통째로 풀어버리면 같은 와이파이의 공격자도 함께 풀리고, 공격자가 자기 계정을 만들어 자기 IP를 풀 수도 있습니다. 그래서 예외를 **"회원 + 기기 쿠키(`lw_dev`)"** 둘 다에 묶었습니다. 쿠키는 무작위 값으로 HttpOnly(자바스크립트가 못 읽음)이고, DB에는 해시만 저장됩니다.

## 사용자가 보는 흐름

```
1. /login → 잠금 안내 + [본인 인증으로 잠금 해제] 링크 (39단계부터 임시·영구 잠금 문구가 같음)
2. /recovery → 아이디 입력 → 항상 같은 안내 "등록된 이메일이 있다면 안내 메일을 보냈습니다"
3. 메일함: 인증 링크(15분, 1회용) + 6자리 코드
4. 링크 클릭 → 확인 화면(가린 아이디·요청 IP·시각) → [해제] 버튼
5. 완료 화면 + "해제되었습니다" 확인 메일 + Slack 알림
```

## 보안 디테일

| 위험 | 대응 |
|---|---|
| 메일 보안 스캐너가 링크를 **GET으로 미리 열어** 토큰이 닳음 | GET은 확인 화면만, 토큰은 **POST에서만 소비** |
| Host 헤더를 조작해 링크를 공격자 주소로 바꿈 | 링크는 `request.host_url`이 아니라 환경변수 **`PUBLIC_BASE_URL`**로만 생성 |
| DB 유출 시 토큰 유출 | 토큰·6자리 코드는 **SHA-256 해시만 저장**, 비교는 `hmac.compare_digest` |
| 같은 토큰이 동시에 두 번 들어옴 | **조건부 UPDATE**(`WHERE status='PENDING' AND expires_at > now()`)로 한 번만 소비 |
| 6자리 코드 무차별 대입 | 5번 틀리면 요청 취소(`RECOVERY_MAX_CODE_ATTEMPTS`) |
| 계정 존재 여부 탐색(enumeration) | 없는 아이디·잠기지 않은 계정·복구 불가 계정 모두 **같은 문구·같은 쿠키·고정 응답 시간**(`RECOVERY_MIN_RESPONSE_SECONDS`, 기본 8초 → [43단계](guide43_recovery_request_limit.md)에서 실측 후 5초 — 처리가 빨리 끝나도 이 시간까지 기다린 뒤 응답) |
| 메일 폭탄 | IP당 시간당 5회, 계정당 하루 3회, 요청 간 60초 쿨다운, 같은 대상 진행 중 요청 1건 |
| **공격자가 피해자 아이디로 복구를 요청**해 공격자 기기에 예외를 받으려 함 | IP 복구는 **요청한 기기에서만 완료** — 다른 기기에서 링크를 누르면 거부(토큰은 소비되지 않음), 요청한 기기에서 6자리 코드를 입력해야 함. 다른 기기에서의 코드 입력은 맞았는지 알려주지도, 시도 횟수를 올리지도 않음. [39단계](guide39_account_enumeration.md)부터는 **계정 복구 코드도** 요청한 기기에서만 받고, 다른 기기에는 "요청한 기기" 대신 공통 실패 문구만 보여줌(메일 링크는 어느 기기에서나 동작) |
| 복구 직후 같은 공격 재개 | **보호관찰 24시간**(`RECOVERY_PROBATION_HOURS`) — 그 안에 다시 잠기면 횟수와 무관하게 관리자 전용 영구 잠금 |
| console 메일 백엔드가 운영 로그에 토큰을 남김 | `FLASK_ENV=production`에서는 `MAIL_BACKEND=console`을 거부 |

## 존재하지 않는 이메일 → 계정 위험 상향

가입 때 이메일 소유 확인은 하지 않습니다. 대신 복구 메일을 보내는 순간 메일 서버가 **수신자를 영구 거부(SMTP 5xx)** 하면:

1. `users.email_status`를 `UNDELIVERABLE`로 표시하고
2. `EMAIL_UNDELIVERABLE`(MEDIUM) 보안 이벤트를 기록하고(요청 IP가 HIGH 사건에 묶이는 부작용을 피하려고 MEDIUM, 상관분석에는 보내지 않음)
3. 그 계정의 영구 잠금을 **관리자 전용(`ADMIN_ONLY`)** 으로 올립니다. 이후 영구 잠금되는 경우에도 마찬가지입니다.

사용자에게 보이는 응답은 그대로입니다. 한계: 일시 장애(4xx, 연결 실패)는 이메일 문제로 보지 않으며, Gmail처럼 일단 받고 나중에 반송하는 경우는 SMTP 응답만으로 알 수 없습니다.

## 개발 환경에서 메일 확인하기 — Mailpit

실제로 보내지 않고 모든 메일을 가로채 웹 화면에 보여주는 개발용 가짜 메일 서버입니다.

```bash
docker compose -f docker-compose.mailpit.yml up -d
```

`.env`:

```
MAIL_BACKEND=smtp
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_STARTTLS=false
PUBLIC_BASE_URL=http://127.0.0.1:5000
```

받은 메일은 http://127.0.0.1:8025 에서 봅니다. Mailpit은 모든 수신자를 받아주므로 "존재하지 않는 이메일" 경로는 확인할 수 없고, 그 경로는 단위 테스트(가짜 SMTP)로 검증합니다. 실제 발송이 필요하면 Gmail SMTP(`smtp.gmail.com:587`, 2단계 인증 + 앱 비밀번호)나 Brevo 무료 플랜의 접속 정보로 `SMTP_*`만 바꾸면 됩니다.

## 배포(Vercel)에서 복구 메일 보내기

Mailpit은 개발용이라 실제 주소로는 메일이 가지 않습니다. 배포 사이트(https://login-watchdog.vercel.app)에서 실제 이메일로 보내려면 **Gmail SMTP**를 쓰고 Vercel 환경변수를 등록합니다.

### 1. Gmail 준비 (한 번만)

1. 메일을 **보낼** 전용 Gmail 계정을 하나 정합니다(사용자 개인 계정이 아니라 팀용 계정을 권장).
2. 그 계정에서 **2단계 인증**을 켭니다.
3. Google 계정 → 보안 → **앱 비밀번호**를 만들어 16자리 값을 복사합니다. 일반 비밀번호는 SMTP 인증에 쓸 수 없습니다.

### 2. Vercel 환경변수 (Settings → Environment Variables → Production)

| 변수 | 값 | 설명 |
|---|---|---|
| `MAIL_BACKEND` | `smtp` | 필수 |
| `SMTP_HOST` | `smtp.gmail.com` | 필수 |
| `SMTP_PORT` | `587` | 기본값과 같음 |
| `SMTP_STARTTLS` | `true` | 기본값과 같음 |
| `SMTP_USER` | 보내는 Gmail 주소 | 필수 |
| `SMTP_PASSWORD` | 앱 비밀번호 16자리 | 필수. Sensitive로 등록 |
| `MAIL_FROM` | `로그인 워치독 <보내는Gmail주소>` | **Gmail은 `SMTP_USER`와 같은 주소여야** 합니다 |
| `PUBLIC_BASE_URL` | `https://login-watchdog.vercel.app` | 필수. 없으면 운영에서는 메일을 보내지 않습니다 |
| `FLASK_ENV` | `production` | 이미 설정돼 있어야 함(console 백엔드 차단·쿠키 Secure에 필요) |
| `PERMANENT_LOCK_IP_ALLOWLIST` | `127.0.0.1,::1,관리자IP` | 관리자 PC의 공인 IP 추가 권장 |

선택 값(기본값으로 충분): `SMTP_USE_SSL`(포트 465를 쓸 때만 `true`), `SMTP_TIMEOUT_SECONDS`(6), `RECOVERY_MIN_RESPONSE_SECONDS`(8), `MAIL_FAILURE_ALERT_COOLDOWN_SECONDS`(3600). `RECOVERY_BACKGROUND_WORK`는 **`false`(기본)로 두세요** — Vercel은 응답을 보내는 순간 함수를 멈추므로, 메일 발송을 응답 뒤로 미루면 끊길 수 있습니다. 등록 후에는 **재배포**해야 적용됩니다.

### 3. 배포 전·후 점검

```bash
# .env(또는 환경변수)에 위 값을 넣고, 내 메일로 테스트 메일 한 통 보내기
python scripts/management/send_test_mail.py --to 내이메일@gmail.com
```

- 성공하면 수신함(스팸함 포함)에 "메일 발송 테스트"가 옵니다. 실패하면 원인(`CONFIG`/`AUTH`/`CONNECT`/`OTHER`)과 고칠 곳을 알려줍니다.
- 배포 후에는 서버 시작 로그에 `[mailer] 경고:`가 없는지 확인합니다(운영에서 설정이 비어 있으면 경고가 찍힙니다).
- 실제 흐름은 테스트 계정 하나를 대시보드 "영구 잠금" 카드의 수동 승격으로 영구 잠금한 뒤 `/recovery`에서 요청해 메일을 받아 보면 됩니다.

### 4. 메일이 안 갈 때 — 관리자가 알 수 있게 했습니다

사용자 화면은 계정 존재 여부가 드러나지 않게 **항상 "메일을 보냈습니다"** 라고만 나옵니다. 그래서 메일 설정이 틀려도 사용자는 모릅니다. 대신 발송에 실패하면 원인을 분류해 **Slack으로 알립니다**(같은 원인은 1시간에 한 번만).

| 분류 | 의미 | 고칠 곳 |
|---|---|---|
| `CONFIG` | 설정 누락 (`MAIL_BACKEND`, `SMTP_HOST`, `PUBLIC_BASE_URL`, 운영에서 console 사용) | 환경변수 |
| `AUTH` | SMTP 인증 실패 | `SMTP_USER`, 앱 비밀번호 |
| `CONNECT` | 서버에 접속 못 함(포트·시간 초과) | `SMTP_HOST`/`SMTP_PORT`, STARTTLS/SSL 조합 |
| `OTHER` | 발신자 거부, 일시 거부 등 | `MAIL_FROM`이 `SMTP_USER`와 같은지 |

알림과 서버 로그에는 비밀번호·토큰·메일 본문이 남지 않습니다.

### 5. 알아두세요

- **응답이 항상 약 8초 걸립니다.** 메일을 보낸 경우와 안 보낸 경우의 응답 시간이 같아야 계정 존재 여부가 새지 않기 때문입니다. 한 번 요청하면 8초쯤 기다리는 게 정상입니다. 실제 처리(DB 조회 + 메일 발송)가 8초를 넘으면 시간 차이가 드러날 수 있어서, 서로 무관한 조회는 동시에 보내도록 줄였습니다(로컬 실측: 실제 대상 8.00초, 없는 아이디 8.00초).
- **Vercel 무료(Hobby) 플랜의 함수 시간 제한을 확인하세요.** 요청 하나가 8초 가까이 걸리므로 함수 최대 실행 시간이 그보다 길어야 합니다(Project Settings → Functions). 10초 제한이라면 여유가 적어 `SMTP_TIMEOUT_SECONDS`를 더 줄이거나 `RECOVERY_MIN_RESPONSE_SECONDS`를 낮추세요(낮추면 시간 차이 위험이 커집니다).
- **Gmail 한도·스팸함.** 개인 Gmail 계정은 하루 발송 한도(수백 통)가 있고, 새 발신 계정의 메일은 수신자의 스팸함으로 갈 수 있습니다. 스팸 문제가 계속되면 Brevo 무료 플랜(SMTP, 하루 300통)으로 `SMTP_*` 값만 바꾸면 됩니다.
- **포트 25는 클라우드에서 막혀 있습니다.** 587(STARTTLS)과 465(SSL)만 쓰세요. 그래도 접속이 안 되면(`CONNECT` 알림) HTTP API 방식 백엔드를 추가하는 것을 검토합니다(아직 구현하지 않음).
- **가입 이메일 확인은 없습니다.** 오타가 있는 주소로 가입했다면 그 주소로 메일이 가므로, 본인은 받지 못하고 관리자 해제가 필요합니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [scripts/management/send_test_mail.py](../../scripts/management/send_test_mail.py)(메일 설정 점검), [mailer.py](../../notify/mailer.py)(`SENT`/`REFUSED`/`FAILED` 반환, 실패 원인 분류·Slack 알림), [routes/recovery.py](../../routes/recovery.py), [db/recovery.py](../../db/recovery.py), [templates/recovery_request.html](../../templates/recovery_request.html), [recovery_verify.html](../../templates/recovery_verify.html), [recovery_done.html](../../templates/recovery_done.html), [docker-compose.mailpit.yml](../../docker-compose.mailpit.yml), [tests/test_recovery.py](../../tests/test_recovery.py)
- 수정: [lockdown.py](../../security/lockdown.py)(`apply_recovery`), [helpers.py](../../helpers/)(기기 쿠키·해시 헬퍼), [routes/auth.py](../../routes/auth.py)(예외 통과·회수·가입 거부), [routes/admin.py](../../routes/admin/), [templates/login_form.html](../../templates/login_form.html), [config.py](../../config.py), [.env.example](../../.env.example), [app.py](../../app.py)(Blueprint 등록)
