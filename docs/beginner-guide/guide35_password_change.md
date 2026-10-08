# 35단계 — 비밀번호 변경 + 다른 기기 로그인 해제

[◀ 34단계](guide34a_email_recovery.md) · [전체 목차](beginner-guide.md) · [36단계 ▶](guide36_db_connection.md)

> [34단계](guide34a_email_recovery.md)의 복구 완료 메일은 "본인이 아니라면 비밀번호를 바꾸세요"라고 안내했지만, 정작 사이트에는 비밀번호를 바꾸는 화면이 없었습니다. 이 단계에서는 **로그인한 회원이 '내 프로필'에서 비밀번호를 바꿀 수 있게** 하고, 바꾸면 **다른 기기의 로그인을 모두 끊도록** 했습니다.

## 왜 "다른 기기 로그인 해제"까지 필요한가

누군가 내 로그인 세션(쿠키)을 훔쳤다고 해봅시다. 비밀번호만 바꾸고 이미 로그인된 세션을 그대로 두면, 훔친 사람은 계속 로그인 상태로 남습니다. 그래서 비밀번호를 바꾸는 순간 **지금 이 기기를 제외한 모든 로그인 세션을 무효로** 만듭니다.

## 원리 — 세션 "세대 번호"

| 단계 | 일어나는 일 |
|---|---|
| 로그인 | `users.session_version`(처음엔 0)을 세션에도 함께 저장 |
| 회원 화면에 들어올 때마다 | 세션의 번호와 DB의 번호를 비교 — 다르면 자동 로그아웃 |
| 비밀번호 변경 | DB 번호를 1 올리고, **지금 기기의 세션에만** 새 번호를 넣어줌 |
| 결과 | 다른 기기의 세션은 번호가 맞지 않아 다음 요청에서 로그아웃 |

- 회원 화면(`/dashboard/*`)과 게시판(`/board/*`) 모두 같은 문지기(`member_login_required`)를 쓰므로 함께 적용됩니다.
- 이 기능 이전에 로그인한 세션은 번호가 없어서 0으로 보고 그대로 유지됩니다.
- 회원 화면 요청마다 DB 조회가 한 번 늘어납니다.
- 번호는 "읽은 값 그대로일 때만" 올립니다(조건부 UPDATE). 두 기기에서 거의 동시에 바꿔도 번호가 덜 올라가 이전 세션이 살아남는 일이 없습니다.

## 비밀번호 변경 화면의 보안 규칙

| 규칙 | 이유 |
|---|---|
| **현재 비밀번호를 확인** | 세션만 훔친 사람이 비밀번호를 바꿔 계정을 빼앗지 못하게 |
| 현재 비밀번호를 틀리면 **로그인 실패와 똑같이 기록하고 같은 기준으로 잠금** | 이 화면이 "잠금 없이 비밀번호를 무한히 맞춰보는" 우회로가 되지 않게 |
| 이번 실패로 잠기면 **즉시 로그아웃** | 잠긴 계정이 계속 시도하지 못하게 |
| 이미 잠긴 계정은 변경 불가 | 같은 이유 |
| 새 비밀번호 형식(8자 이상, 확인 일치, 현재와 다름)은 **먼저** 확인 | 본인 확인과 무관한 입력 실수가 실패 횟수에 쌓이지 않게 |
| CSRF 토큰 + 허니팟(봇 차단) | 다른 폼과 같은 기본 방어 |
| 변경 후 **이메일 알림** | 본인이 한 일이 아니라면 바로 알 수 있게(메일이 실패해도 변경은 유지) |
| 이미 영구 잠금된 IP(예외로 들어온 회원)는 다시 잠그지 않음 | 5분 잠금 알림이 중복으로 나가지 않게 |

## 함께 바뀐 것

- 복구 완료 메일 문구: "비밀번호를 변경하세요"만 있던 안내를, 로그인 후 '내 프로필'(`PUBLIC_BASE_URL/dashboard/profile`)에서 바꾸라는 구체적인 안내로 바꿨습니다.
- 회원 로그아웃은 회원 세션 값(`username`, `user_id`, `session_version`)만 지우고, 같은 브라우저의 관리자 세션은 그대로 둡니다.

## 하지 않은 것

- **비밀번호를 잊었을 때 메일로 재설정**하는 기능은 만들지 않았습니다. 잊은 경우는 관리자가 처리합니다. 필요해지면 34단계와 같은 토큰 방식으로 추가할 수 있습니다. → [40단계](guide40_email_verification.md)에서 그 토대(이메일 인증, 이메일 변경 보호)를 만들고 [41단계](guide41_password_reset.md)에서 비밀번호 찾기를 추가했습니다. 40단계부터 이메일 변경도 이 화면처럼 현재 비밀번호를 확인합니다.
- 영구 잠금이 걸릴 때 기존 세션을 끊는 기능은 없습니다(잠금은 새 로그인만 막습니다). 비밀번호를 바꿀 때만 끊습니다.
- 관리자 계정의 비밀번호 변경은 이번 범위가 아닙니다.

## DB 변경

```sql
alter table users add column if not exists session_version int not null default 0;
```

[docs/migrations/guide35_password_change.sql](../migrations/guide35_password_change.sql)과 [docs/schema.sql](../schema.sql) 맨 아래에 같은 내용이 있습니다. **배포 전에 Supabase SQL Editor에서 한 번 실행**해야 합니다 — 실행하지 않으면 회원 화면에서 세션 번호를 조회하다가 오류가 납니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [tests/test_password_change.py](../../tests/test_password_change.py), [docs/migrations/guide35_password_change.sql](../migrations/guide35_password_change.sql)
- 수정: [db/users.py](../../db/users.py)(`get_user_session_version`, `update_user_password`), [helpers.py](../../helpers.py)(`member_login_required` 세대 번호 확인, `clear_member_session`), [routes/member.py](../../routes/member.py)(`POST /dashboard/password`), [routes/auth.py](../../routes/auth.py)(로그인 시 세대 번호 저장), [templates/member_profile.html](../../templates/member_profile.html), [public/css/member.css](../../public/css/member.css), [mailer.py](../../mailer.py)(변경 알림, 복구 완료 문구), [tests/conftest.py](../../tests/conftest.py)
