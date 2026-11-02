# L4 차단 강제 해제 메모 (테스트로 쌓인 차단 비우기)

촬영·테스트를 반복하면 `network_blocks`에 차단이 많이 쌓입니다. 아래로 **L4 차단을 한 번에** 풉니다.

> **중요: `DELETE` 쓰지 말 것.** fw-agent는 `network_blocks`를 "원하는 상태"로 읽어 ipset(lw_block)을
> 맞춥니다. 행을 지우면 ipset에 **그대로 남아 계속 막힙니다.** 앱 "영구 해제"와 똑같이
> `PENDING_REMOVE`로 바꿔 fw-agent가 빼게 해야 합니다(version 도 +1).

## Supabase SQL 편집기에서

### 1) 먼저 무엇이 풀릴지 미리 보기
```sql
select ip_address, status, evidence, reason, expires_at, applied_at
from network_blocks
where status in ('PENDING_APPLY','APPLIED','FAILED')
order by applied_at desc nulls last;
```

### 2) 전부 해제 요청 — fw-agent가 2초~최대 60초 안에 ipset에서 실제로 뺌
```sql
update network_blocks
set status = 'PENDING_REMOVE',
    version = version + 1,
    last_error = null
where status in ('PENDING_APPLY','APPLIED','FAILED');
```

### 3) 확인 — 이제 'APPLIED'(차단 중)가 없어야 하고, 잠시 뒤 다 'REMOVED'로 넘어감
```sql
select status, count(*) from network_blocks group by status;
```

### 4) ipset이 실제로 비었는지(차단 풀렸는지)
```bash
docker compose exec fw-agent ipset list lw_block
```
→ `Members:` 아래가 비어 있으면 완료.

## 알아둘 점
- **L3는 풀 대상이 없음.** L3(ICMP)는 IP별 차단이 아니라 정문 전체 속도제한(hashlimit) 규칙이라
  `network_blocks`에 행이 없습니다. 쌓인 건 전부 L4(`lw_block`)입니다.
- `version` 컬럼은 guide56에서 추가됨(공용 DB 적용됨). 혹시 `column "version" does not exist`
  에러가 나면 `version = version + 1` 줄만 빼고 실행.
- **공용 DB**라 모든 PC의 L4 차단이 풀립니다(팀 공용). 괜찮은 범위인지 확인하고 실행.
- 앱 쪽 **L7 IP 잠금(`lockouts`)**은 이 SQL로 안 풀립니다. 필요하면 별도 SQL이 필요합니다(이 메모는 L3/4만).
