"""샘플 로그 생성에 쓰는 재료 모음 — 나라별 IP 대역, 가짜 회원, 시각 계산 규칙.

generate_demo_logs.py(만드는 쪽), demo_server.py(보여주는 쪽), load_demo_to_supabase.py(DB에 넣는 쪽)가
같이 쓴다. 서버·DB를 모르는 순수 함수만 있어서 테스트하기 쉽다.

IP는 "실제로 그 나라에 할당된 대역"에서 뒤쪽 두 칸만 무작위로 고른다. 이 주소로 어떤 접속도 하지 않는다 —
우리 서버의 요청 헤더와 DB 값으로만 들어간다. 대역 정보는 공개 할당 정보를 바탕으로 한 것이라 외부 위치
조회 서비스에서는 도시가 다르게 나올 수 있다(나라는 대체로 같다).
"""

import random
import re
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

# (나라, 지역, 도시, 실제 할당 대역 앞 두 칸들)
COUNTRIES = [
    ("Russia", "Moscow", "Moscow", ["95.165"]),
    ("China", "Beijing", "Beijing", ["123.112"]),
    ("United States", "Washington", "Seattle", ["73.158"]),
    ("Germany", "Berlin", "Berlin", ["87.150"]),
    ("Brazil", "Sao Paulo", "Sao Paulo", ["177.92"]),
    ("India", "Maharashtra", "Mumbai", ["49.36"]),
    ("Vietnam", "Hanoi", "Hanoi", ["113.190"]),
    ("South Korea", "Seoul", "Seoul", ["211.36", "175.223"]),
    ("Japan", "Tokyo", "Tokyo", ["126.23"]),
    ("United Kingdom", "England", "London", ["86.140"]),
    ("France", "Ile-de-France", "Paris", ["90.46"]),
    ("Netherlands", "North Holland", "Amsterdam", ["84.26"]),
    ("Indonesia", "Jakarta", "Jakarta", ["114.122"]),
    ("Turkey", "Istanbul", "Istanbul", ["88.230"]),
    ("Nigeria", "Lagos", "Lagos", ["105.112"]),
    ("Canada", "Ontario", "Toronto", ["99.240"]),
    ("Australia", "New South Wales", "Sydney", ["1.128"]),
]
COUNTRY_INFO = {c[0]: {"country": c[0], "region_name": c[1], "city": c[2]} for c in COUNTRIES}
ATTACK_COUNTRIES = [c[0] for c in COUNTRIES if c[0] != "South Korea"]

# 정상 회원은 대부분 한국에서, 일부는 해외에서 접속한다.
MEMBER_COUNTRIES = ["South Korea"] * 8 + ["Japan", "United States", "South Korea", "Canada"]
MEMBER_NAMES = [
    "kim_minjae", "lee_seoyeon", "park_dohyun", "choi_harin", "jung_woojin", "kang_yuna",
    "yoon_sungho", "han_jiwoo", "lim_dayoung", "song_taeyang", "oh_soyeon", "seo_junho",
]
MEMBER_PASSWORD = "DemoPass#2026x"
ADMIN_ACCOUNTS = [  # (아이디, 역할) — 첫 계정은 서버가 .env 값으로 자동 만드는 최고 관리자
    ("demo-admin", "super_admin"),
    ("night_shift", "security_viewer"),
    ("sec_manager", "security_admin"),
]
ADMIN_PASSWORD = "DemoAdmin#2026x"

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ISO = re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d")


class IpPool:
    """나라별 IP를 겹치지 않게 뽑아주고, 뽑은 IP의 나라를 기억한다."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.country_of: dict[str, str] = {}

    def pick(self, country: str | None = None, avoid: set[str] | None = None) -> str:
        country = country or self.rng.choice(ATTACK_COUNTRIES)
        prefixes = next(c[3] for c in COUNTRIES if c[0] == country)
        while True:
            ip = f"{self.rng.choice(prefixes)}.{self.rng.randint(1, 254)}.{self.rng.randint(2, 253)}"
            if ip not in self.country_of and ip not in (avoid or ()):
                self.country_of[ip] = country
                return ip

    def pick_mixed(self, count: int) -> list[str]:
        """서로 다른 나라의 IP를 count개 뽑는다(분산 공격용)."""
        countries = self.rng.sample(ATTACK_COUNTRIES, min(count, len(ATTACK_COUNTRIES)))
        return [self.pick(c) for c in countries]

    def location_rows(self, now_iso: str) -> list[dict]:
        """ip_locations 표에 넣을 행. 위치 조회 서비스를 부르지 않도록 미리 채워 둔다."""
        return [
            {**COUNTRY_INFO[country], "ip_address": ip, "lookup_failed": False, "looked_up_at": now_iso}
            for ip, country in sorted(self.country_of.items())
        ]


def parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_time_string(value) -> bool:
    return isinstance(value, str) and bool(_ISO.match(value)) and parse_iso(value) is not None


def shift_time_string(value: str, delta: timedelta) -> str:
    return (parse_iso(value) + delta).isoformat()


def shift_row_times(row: dict, delta: timedelta, keys=None) -> None:
    """행 안의 모든 날짜 문자열을 delta만큼 옮긴다(keys를 주면 그 칸만)."""
    for key in keys if keys is not None else list(row):
        if is_time_string(row.get(key)):
            row[key] = shift_time_string(row[key], delta)


def shift_dump_to_now(dump: dict, now: datetime | None = None) -> None:
    """저장해 둔 기록 전체를 "만든 시각 → 지금"만큼 옮겨서 항상 최근 7일처럼 보이게 한다."""
    now = now or datetime.now(timezone.utc)
    delta = now - parse_iso(dump["generated_at"])
    for rows in dump["tables"].values():
        for row in rows:
            shift_row_times(row, delta)
            if "day" in row and isinstance(row["day"], str):  # 일별 요약표는 날짜만 있어서 따로 옮긴다
                moved = datetime.fromisoformat(row["day"]).replace(tzinfo=KST) + delta
                row["day"] = moved.astimezone(KST).date().isoformat()
    dump["generated_at"] = now.isoformat()
