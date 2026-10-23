# 탐지 → L4 차단 시간 측정 결과 (I2-2)

> 발표 핵심 숫자: **SYN Flood를 탐지한 뒤 5초 안에 정문(gateway)에서 L4로 막는가.** 목표는 상위 계획서 2.8.
> 측정 스크립트: `python -m scripts.net.measure_detect_to_block --scenario s5 --repeat 3` (S5b는 `--scenario s5b`)

## 어떻게 재나

시각은 PC 시계가 아니라 **DB에 남은 기록**으로 잰다. 공격 컨테이너·센서·앱의 시계가 서로 달라도 같은 기준으로 비교하기 위해서다.

| 기호 | 기록 | 뜻 |
|---|---|---|
| T0 | `network_events.observed_at` | 센서가 그 IP의 첫 SYN_FLOOD를 본 시각 |
| T1 | `network_blocks.requested_at` | 앱이 "막아라"(PENDING_APPLY)를 적은 시각 |
| T2 | `network_blocks.applied_at` | fw-agent가 ipset에 넣고 "막았음"(APPLIED)을 보고한 시각 |

| 구간 | 목표 |
|---|---|
| T0 → T1 | ≤ 2000ms |
| T1 → T2 | ≤ 2000ms |
| **T0 → T2 (전체)** | **≤ 5000ms** |

- 실행마다 측정 범위(`.150`~`.199`)에서 아직 차단된 적 없는 **새 출발지 IP**를 쓴다. 같은 IP는 앞 실행의 차단과 "사건당 규칙당 1회" 때문에 다시 잴 수 없다.
- S5 = SYN Flood 단독, S5b = SYN Flood + HTTP 폭주 동시(앱이 바쁠 때도 5초를 지키는지). S5b는 비고에 CR-02 매칭 여부를 적는다.
- 값이 `-`이면 그 시각의 기록이 생기지 않은 것이다(못 잰 것은 "초과"로 센다).

## 결과

| 시각(UTC) | 시나리오 | 출발지 IP | T0→T1(ms) | T1→T2(ms) | T0→T2(ms) | 판정 | 비고 |
|---|---|---|---|---|---|---|---|
