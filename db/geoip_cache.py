# ============================================================================
# db/geoip_cache.py — ip_locations 표 관련 함수 — IP 위치 조회 결과 캐시 (13단계)
#
# db.get_client() 호출 이유는 db/attempts.py 상단 설명 참고.
# ============================================================================

import db


def get_cached_ip_locations(ips: list[str]) -> dict[str, dict]:
    """IP 목록을 한꺼번에 캐시에서 찾아온다.

    IP 하나마다 따로따로 물어보지 않고 .in_()으로 "이 목록에 있는 IP들만 한
    번에 줘"라고 요청하는 이유: 관리자 대시보드는 10초마다 최근 로그인 시도
    최대 50건을 다시 그리는데, 그 50건 각각에 대해 캐시 조회를 따로 하면
    Supabase 요청이 50개씩 늘어난다(9단계에서 겪었던 쿼터 문제와 같은 유형의
    실수). 딱 1번의 쿼리로 필요한 IP들을 전부 가져오면 이 문제를 피할 수 있다.

    반환값은 {"1.2.3.4": {...캐시된 행...}, ...} 형태의 딕셔너리다 — "이 IP는
    캐시에 있는가?"를 코드에서 바로 찾아보기 쉽게 하기 위해서다.
    """
    if not ips:
        return {}
    res = db.get_client().table("ip_locations").select("*").in_("ip_address", ips).execute()
    return {row["ip_address"]: row for row in res.data}


def save_ip_location(
    ip: str, country: str | None, region_name: str | None, city: str | None, lookup_failed: bool
) -> None:
    """방금 새로 조회한 IP 위치 결과를 캐시 표에 저장한다.

    조회에 실패한 경우(lookup_failed=True, 예: 127.0.0.1 같은 사설 IP)도
    똑같이 저장해둔다 — 그래야 다음에 같은 IP가 또 나왔을 때, "저번에도 안
    됐던 IP구나"를 캐시만 보고 바로 알 수 있고, 매번 다시 ip-api.com에
    헛수고로 물어보지 않는다.
    """
    db.get_client().table("ip_locations").upsert(
        {
            "ip_address": ip,
            "country": country,
            "region_name": region_name,
            "city": city,
            "lookup_failed": lookup_failed,
        }
    ).execute()
