# 14단계 — 로그인 IP의 국가·도시 표시 (ip-api.com 연동)

[◀ 13단계](guide13_member.md) · [전체 목차](beginner-guide.md) · [15단계 ▶](guide15_design.md)


### 우리가 한 일
1. Supabase에 `ip_locations`라는 "IP 위치 조회 결과 캐시" 표를 새로 추가
2. [geoip.py](../../geoip.py)라는 새 파일을 만들어 ip-api.com(무료 IP 위치 조회 서비스)과의 통신을 전담시킴
3. 회원 본인의 로그인 기록(`/dashboard/history`), 관리자 대시보드의 "최근 로그인 시도" 표 양쪽에 **위치** 칸 추가

### 왜 했는가 (쉬운 설명)

**alert.py와 완전히 같은 패턴 — 외부 서비스 하나당 파일 하나**
4단계에서 Slack과 대화하는 일을 `alert.py` 하나에 몰아넣었던 것과 똑같은 이유로, ip-api.com과 대화하는 일도 `geoip.py`라는 새 파일 하나에 몰아넣었습니다. `db.py`(Supabase 전담), `alert.py`(Slack 전담), `geoip.py`(ip-api.com 전담) — "외부 서비스 하나당 파일 하나"라는 규칙이 이 프로젝트 전체에 일관되게 적용되고 있는 셈입니다.

**왜 굳이 "캐시 표"까지 새로 만들었나 — 9단계의 교훈을 그대로 적용**
관리자 대시보드의 "최근 로그인 시도" 표는 **10초마다** 최대 50줄을 다시 그립니다. 만약 이 50줄 하나하나에 대해 매번 ip-api.com에 새로 물어본다면, ip-api.com의 무료 사용 한도(분당 45건)를 순식간에 넘깁니다. 9단계에서 "Supabase 쿼터를 지키려고 폴링 주기를 늘렸던" 것과 똑같은 종류의 문제가, 이번엔 Supabase가 아니라 ip-api.com을 상대로 또 발생할 뻔한 것입니다.

그래서 한 번 조회한 IP는 Supabase의 `ip_locations` 표에 저장해두고, 다음부터는 ip-api.com 대신 이 저장값을 먼저 확인합니다. 브루트포스 공격은 보통 같은 IP에서 반복되기 때문에(같은 컴퓨터가 계속 틀리게 로그인을 시도하는 것이므로), 실제로는 새로운 IP를 조회하는 일이 생각보다 훨씬 적습니다.

**"IP 하나씩" 대신 "IP 목록을 통째로" 캐시에 물어본 이유**
`db.get_cached_ip_locations(ips)`는 IP 목록 전체를 `.in_()`이라는 조건으로 **한 번의 쿼리**로 조회합니다. 만약 대신 IP 50개를 하나씩 50번 따로 물어봤다면, ip-api.com 호출은 아꼈어도 이번엔 Supabase 요청이 50배로 늘어나서 결국 같은 문제를 다른 곳(Supabase)에 옮겨놓은 꼴이 됩니다. "여러 개를 조회할 땐 하나씩 묻지 말고 한꺼번에 물어봐라"는 원칙이 이번에도 그대로 적용됐습니다.

**조회에 실패한 IP도 캐시해두는 이유**
`127.0.0.1`(로컬 개발 중 계속 나오는 주소)은 ip-api.com에 물어봐도 항상 "reserved range"(예약된 사설 주소라 위치가 없음) 응답만 돌아옵니다. 이걸 캐시하지 않으면, 로컬 개발 중 대시보드를 열어둘 때마다 `127.0.0.1`에 대해 "안 되는 걸 알면서도" 계속 헛되이 ip-api.com에 새로 물어보게 됩니다. 그래서 "실패했다"는 사실 자체도 캐시에 저장해서, 같은 실패를 반복하지 않게 했습니다.

### 실제 코드 함께 보기

**`geoip.py` — 캐시를 먼저 확인하고, 없는 것만 새로 조회하는 핵심 로직**
```python
def get_locations(ips: list[str]) -> dict[str, dict]:
    unique_ips = list(dict.fromkeys(ips))  # 순서는 유지하면서 중복만 제거
    cached = db.get_cached_ip_locations(unique_ips)

    result = {}
    for ip in unique_ips:
        if ip in cached:
            result[ip] = cached[ip]
            continue
        location = _fetch_location(ip)
        db.save_ip_location(ip, location["country"], location["region_name"], location["city"], location["lookup_failed"])
        result[ip] = location
    return result
```
`dict.fromkeys(ips)`는 "리스트 안의 중복된 값을 지우되, 원래 순서는 그대로 유지해라"는 파이썬의 흔한 관용구입니다(딕셔너리는 같은 키를 두 번 넣어도 하나만 남기는 성질을 이용한 것). 캐시에 있으면(`if ip in cached`) 바로 꺼내 쓰고, 없을 때만 `_fetch_location()`으로 진짜 외부 API를 호출합니다.

**`app.py` — 회원 화면과 관리자 화면이 똑같은 함수를 공유**
```python
def _attach_locations(attempts: list[dict]) -> list[dict]:
    ips = [attempt["ip_address"] for attempt in attempts]
    locations = geoip.get_locations(ips)
    for attempt in attempts:
        attempt["location"] = geoip.format_location(locations[attempt["ip_address"]])
    return attempts
```
이 함수 하나를 `member_history()`(회원 본인 기록, 최대 20줄)와 `api_status()`(관리자 대시보드, 최대 50줄) 양쪽에서 그대로 가져다 씁니다. "로그인 시도 목록에 위치 정보를 붙인다"는 동작은 두 화면에서 완전히 똑같기 때문에, 코드를 두 번 쓰지 않고 한 곳에만 만들어뒀습니다.

### 실제로 테스트한 것
로컬 개발 환경은 전부 `127.0.0.1`이라 실제 위치가 안 나오므로, `TRUST_FORWARDED_FOR`(5단계에서 만든 데모 전용 플래그)를 잠깐 켜서 "나는 1.1.1.1에서 접속했다"고 가짜 헤더를 보내는 방식으로 검증했습니다.
1. 회원가입 → 가짜 IP(`1.1.1.1`)로 로그인 → `/dashboard/history`에 실제로 "Australia · South Brisbane"이 표시되는지 확인
2. 같은 IP로 두 번째 요청을 보냈을 때, ip-api.com을 또 부르지 않고 캐시에서 바로 가져오는지 (`test_get_locations_uses_cache_and_skips_external_call` 단위 테스트로 확인 + `ip_locations` 표에 실제로 값이 저장된 것도 직접 조회로 재확인)
3. 관리자 대시보드의 "최근 로그인 시도" 표에도 **위치** 칸이 추가되어, 과거에 쌓여있던 진짜 로그인 기록들의 위치까지 한꺼번에 조회되어 표시되는지 확인 — 신기하게도 예전 기록(스키마 변경 전에 이미 저장돼 있던 것들)도 IP만 있으면 새로 조회가 되어 자연스럽게 위치가 채워졌습니다
4. `pytest tests/` 36개 전부 통과 확인(신규 10개: `test_db.py` 4개 + `test_geoip.py` 6개), 테스트에 쓴 캐시 데이터는 확인 후 정리

### 이 단계에서 만들어지거나 바뀐 파일
- [docs/schema.sql](../schema.sql) (`ip_locations` 표 추가, Supabase에 실제 실행됨)
- [geoip.py](../../geoip.py) (신규 — ip-api.com 연동 전담 파일)
- [db.py](../../db.py) (`get_cached_ip_locations`, `save_ip_location` 2개 함수 추가)
- [app.py](../../app.py) (`_attach_locations()` 신규, `member_history()`·`api_status()`에 적용)
- [templates/member_history.html](../../templates/member_history.html), [templates/admin_dashboard.html](../../templates/admin_dashboard.html) (위치 칸 추가)
- [public/js/dashboard.js](../../public/js/dashboard.js) (`renderAttemptsTable`에 위치 칸 추가)
- [public/css/member.css](../../public/css/member.css) (표가 카드보다 넓어질 경우를 위한 가로 스크롤 처리 추가)
- [tests/test_geoip.py](../../tests/test_geoip.py) (신규 — 캐시 활용 여부, 문자열 조립 검증), [tests/test_db.py](../../tests/test_db.py) (캐시 조회/저장 함수 테스트 추가)
