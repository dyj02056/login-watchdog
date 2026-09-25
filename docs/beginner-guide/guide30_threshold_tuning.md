# 30단계 — 임계값 튜닝 리포트 (Track C 4/4)

[◀ 29단계](guide29_macro_bot_detection.md) · [전체 목차](beginner-guide.md)

> Track C의 마지막 단계입니다. 지금까지 만든 탐지 로직들(브루트포스, 웹 스캐닝, 매크로/봇 등)은 전부 "고정된 숫자"(`FAILURE_THRESHOLD`, `WEB_SCANNING_ALERT_THRESHOLD` 등)를 기준으로 삼습니다. 이 숫자가 너무 낮으면 정상 사용자까지 잠그고(오탐), 너무 높으면 진짜 공격을 놓칩니다. 이번 단계는 **"지금 기준이 너무 예민한 건 아닌지"를 스스로 점검하는 리포트**를 만들었습니다 — 새 탐지 로직이 아니라, 기존 탐지 로직이 남긴 기록을 되짚어보는 도구입니다.

## 질문 하나로 시작

"IP를 잠갔는데, 관리자가 자동 만료(`LOCKOUT_DURATION_SECONDS`, 기본 5분)를 다 기다리지 않고 훨씬 빨리 수동으로 풀어준 비율이 얼마나 되는가?"

이 비율이 높다는 건, 잠긴 IP를 관리자가 보자마자 "이건 공격이 아니네" 하고 바로 풀어줬다는 뜻입니다 — 즉 그 잠금 자체가 오탐이었을 가능성이 높다는 신호입니다.

## 판단 기준 — "조기 해제"

`resolved_at - detected_at`(잠긴 순간부터 풀린 순간까지의 간격)이 `LOCKOUT_DURATION_SECONDS`의 절반(기본, `--early-release-ratio`로 조정 가능) 미만이면 "조기 해제"로 분류합니다. 관리자가 정확히 몇 초에 버튼을 눌렀는지까지는 알 수 없지만, 자동 만료 시간의 절반도 안 돼서 풀렸다면 "자동 만료를 기다리지 않고 사람이 먼저 판단해서 풀었다"고 봐도 무리가 없습니다.

## 새로 만든 것 — 완전히 읽기 전용

이번 단계는 **새 표를 만들지 않습니다.** 기존 `security_events`(CRITICAL·해결됨·기간 내)만 조회합니다.

```python
# db/security_events.py
def list_resolved_critical_events_since(hours: int) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    res = (
        db.get_client()
        .table("security_events")
        .select("event_type, detected_at, resolved_at")
        .eq("severity", "CRITICAL")
        .not_.is_("resolved_at", "null")
        .gte("detected_at", cutoff)
        .execute()
    )
    return res.data
```

`scripts/tune_thresholds.py`는 이 데이터를 `event_type`별로 묶어서(BRUTE_FORCE/PASSWORD_SPRAYING/ADMIN_BRUTE_FORCE/DISTRIBUTED_BRUTE_FORCE 등), 각각 조기 해제 비율을 계산하고 30%(임의로 정한 기준, `REVIEW_RECOMMENDATION_RATIO`) 이상이면 "기준 재검토 권장" 표시를 붙입니다.

```bash
python scripts/tune_thresholds.py --days 7
```

## 실제로 돌려본 결과

```
===== 로그인 워치독 임계값 튜닝 리포트 (최근 7일) =====
기준: 잠금 후 150초 미만에 풀리면 '조기 해제'로 분류 (자동 해제 시간 300초의 50%)

BRUTE_FORCE: 3건 중 2건(67%) 조기 해제 <- 기준 재검토 권장

전체: 3건 중 2건(67%) 조기 해제
```

이 결과는 실제 공격 대비 기준이 너무 예민하다는 뜻이 **아닙니다** — 27~29단계를 검증하면서 저희가 직접 브루트포스 시뮬레이션을 여러 번 걸고 곧바로 `unlock_ip.py`로 풀어준 기록이 그대로 쌓인 것입니다. 이 리포트는 "정답"을 내려주는 게 아니라, 이런 식으로 "왜 조기 해제가 많았는지" 되짚어볼 계기를 만들어주는 도구입니다 — 실제 운영 중이라면 이 숫자가 높을 때 "혹시 임계값이 너무 낮은가?"를 관리자가 직접 판단해야 합니다.

## 라이브 검증에서 발견한 버그 — argparse의 `%` 함정

처음 작성한 `--early-release-ratio` 옵션의 도움말 문자열에 `"...몇 % 미만이면..."`처럼 글자 그대로의 `%`를 넣었는데, 실제로 스크립트를 실행하자(단위 테스트는 `argparse`를 거치지 않아 못 잡아냄) `ValueError: unsupported format character`로 **`--help`를 부르지 않아도 스크립트 시작부터 죽는** 문제가 발생했습니다. `argparse`는 도움말 문자열의 `%`를 `%(default)s` 같은 서식 지정자로 해석하려고 시도하기 때문입니다 — 글자 그대로의 `%`를 쓰려면 `%%`로 이스케이프해야 합니다. 이 문제는 단위 테스트(`build_report()`를 직접 호출)로는 잡히지 않고, 실제로 스크립트를 실행해봐야만 드러나는 종류의 버그였습니다.

## 실제로 확인한 것

`pytest tests/` 전체 295개 통과(guide29 시점 286개 + 이번 추가 9개 — `test_db.py` 1개, `test_tune_thresholds.py` 8개(신규)). `tests/test_db.py`의 공용 가짜 Supabase 클라이언트(`_FakeQuery`)에 `.not_` 속성이 빠져있던 것도 이번에 발견해서 추가했습니다 — `count_security_events()`/`delete_resolved_security_events()` 등 기존 함수들이 이미 `.not_.is_(...)`를 쓰고 있었지만 지금까지 이 가짜 클라이언트로 테스트된 적이 없었습니다.

실제 Supabase 데이터로도 실행해서(`python scripts/tune_thresholds.py --days 7`), 위에 옮겨 적은 실제 리포트 결과를 확인했습니다. 스키마 변경이 없는 완전한 읽기 전용 스크립트라 별도 SQL 실행이나 정리 작업이 필요 없었습니다.

## 이 단계에서 만들어지거나 바뀐 파일

- [db/security_events.py](../../db/security_events.py) — `list_resolved_critical_events_since()` 신규
- [db/__init__.py](../../db/__init__.py)
- [scripts/tune_thresholds.py](../../scripts/tune_thresholds.py) — 신규
- [tests/test_db.py](../../tests/test_db.py) — `_FakeQuery.not_` 속성 추가 + 새 테스트
- [tests/test_tune_thresholds.py](../../tests/test_tune_thresholds.py) — 신규
