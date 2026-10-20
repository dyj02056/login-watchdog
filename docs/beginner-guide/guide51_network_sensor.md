# 51단계 — 네트워크 센서 (Docker 단지·정문·CCTV)

[◀ 50단계](guide50_demo_sample_logs.md) · [전체 목차](beginner-guide.md) · [52단계 ▶](guide52_net_ingest_correlation.md)

> 지금까지 login-watchdog은 **앱 안에서** 로그인 실패·요청 수를 세어 공격을 찾았습니다(L7). 그런데 SYN Flood나 포트 스캔처럼 **앱까지 오지 않는 공격**은 앱이 볼 수 없습니다. Track D에서는 앱 앞에 "정문"을 세우고 정문을 지나는 통신을 지켜보는 센서를 붙입니다.
> 이 문서는 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **연습용 단지·네트워크 3개·정문(nginx)** 까지입니다. Suricata·Scapy 센서와 배달원(shipper)은 다음 절에서 다룹니다.

## 비유 — 아파트 단지와 정문

| 비유 | 실제 | 하는 일 |
|---|---|---|
| **아파트 단지** | Docker Compose 환경 (`docker-compose.yml`) | 아래 건물·도로를 명령 한 번으로 켜고 끕니다 |
| 건물 | Docker 컨테이너 | `gateway`, `app`, `mailpit`, `sensor`, `l4-detector`, `shipper`, `fw-agent`, `attacker-1~3` |
| 도로 | Docker 네트워크 `edge`·`core`·`egress` | 건물끼리 어떤 길로만 다닐 수 있는지 정합니다 |
| **정문** | `gateway` (nginx) | 바깥에서 오는 모든 요청이 거치는 단 하나의 입구. `localhost:8080` |
| 정문 CCTV | `sensor`(Suricata), `l4-detector`(Scapy) | 정문을 지나는 통신을 지켜봅니다 (다음 절) |
| 배달원 | `shipper` | CCTV 기록을 앱에 전달합니다 (다음 절) |
| 정문 차단기 담당 | `fw-agent` | 앱이 "막아라"라고 적은 주소를 정문에서 실제로 막습니다 (54단계, 작성 예정) |

> **왜 실제 서버가 아니라 Docker 단지인가:** 공격을 재현하려면 공격자·정문·앱이 모두 필요합니다. 실제 인터넷에서 하면 남의 서버를 건드릴 위험이 있고, Vercel에는 정문을 둘 수 없습니다. 그래서 내 PC 안에 작은 단지를 만들고, 공격도 단지 안에서만 일으킵니다. Vercel 배포본은 Track D 없이 그대로 동작합니다.

## 도로 3개 — 왜 네트워크를 나누나

| 도로 | Docker 이름 | 대역 | 지나는 건물 | 이유 |
|---|---|---|---|---|
| **edge** (바깥) | `lw_edge` | `${LW_EDGE_PREFIX}.0/24` (사람마다 다름) | gateway, attacker | 공격자가 서는 곳. 여기서는 정문밖에 보이지 않습니다 |
| **core** (안쪽) | `login-watchdog-core` | `172.30.0.0/24` | gateway, app, mailpit, shipper | 앱이 사는 곳. `internal: true`라 인터넷으로 나가지 못합니다 |
| **egress** (나가는 길) | `login-watchdog-egress` | Docker 자동 | app, mailpit | 앱이 Supabase·Slack에 접속하는 길. Mailpit 화면(8025)도 이 길로 엽니다 |

- **공격자는 앱에 직접 갈 수 없습니다.** attacker는 edge에만, app은 core·egress에만 붙어 있어서, 공격 요청은 반드시 정문을 지나야 합니다. 그래야 정문 CCTV가 모든 공격을 볼 수 있고, 정문 차단기가 막으면 정말로 막힙니다.
- **사람마다 edge 대역이 다릅니다**(A `172.28.11`, B `172.28.12`, C `172.28.13`, 발표 PC `172.28.0`). 세 명이 같은 Supabase DB를 쓰기 때문에, 대역이 같으면 서로의 공격 기록이 같은 IP로 섞여 가짜 사건이 생깁니다.
- **core는 172.29가 아니라 172.30입니다.** Docker Desktop(WSL2)이 내부 통신에 `172.29.0.0/24`를 써서, 겹치면 단지를 켜다가 "Network Creating"에서 멈췄습니다.

정문은 두 도로에 모두 걸쳐 있습니다.

| 정문 쪽 | 주소 | 정문 안 이름 |
|---|---|---|
| edge 쪽 (공격자가 보는 주소) | `${LW_EDGE_PREFIX}.10` | `eth0` 또는 `eth1` (PC마다 다름) |
| core 쪽 (앱이 보는 주소) | `172.30.0.10` (고정) | 나머지 하나 |

> **정문 안 이름은 PC마다 다릅니다.** Docker는 컨테이너에 네트워크를 붙이는 순서를 보장하지 않아, 10/19 통합 담당자 PC에서는 `eth1`이 edge였고 10/20 A PC에서는 `eth0`이 edge였습니다. 센서가 core 쪽을 보면 정문이 앱에 넘기는 통신만 보여서 오류 없이 L4 탐지가 0건이 됩니다.
> 그래서 이름(`SENSOR_IFACE`)만 믿지 않고 **"edge 주소(`${LW_EDGE_PREFIX}.10`)가 붙은 인터페이스"**를 기준으로 고릅니다. Suricata(`netwatch/suricata/entrypoint.sh`)와 L4 측정기(`detector_core.py`의 `resolve_sensor_iface`)가 같은 규칙으로, 지정한 이름에 edge 주소가 없으면 edge 쪽으로 바꾸고 경고를 남깁니다.

## 정문(nginx)이 하는 일 — `netwatch/nginx/nginx.conf`

정문은 받은 요청을 모두 앱(`http://app:5000`)으로 넘깁니다. 핵심은 **"원래 손님 주소" 쪽지(`X-Forwarded-For`)를 덮어쓰는 것**입니다.

```nginx
# 사용자가 보낸 값을 이어 붙이지 않고 실제 연결 IP로 덮어쓴다.
proxy_set_header X-Forwarded-For $remote_addr;
```

| 방식 | 공격자가 `X-Forwarded-For: 1.2.3.4`를 넣고 보내면 | 결과 |
|---|---|---|
| 이어 붙이기 (nginx 흔한 기본 예시 `$proxy_add_x_forwarded_for`) | `1.2.3.4, 172.28.11.101` | 앱이 맨 앞 값을 믿으면 공격자가 주소를 마음대로 바꿉니다 |
| **덮어쓰기 (우리 설정)** | `172.28.11.101` | 정문이 실제로 연결된 주소만 남습니다 |

앱이 이 쪽지를 믿으려면 두 가지가 함께 켜져 있어야 합니다(`docker-compose.yml`의 app 블록).

| 설정 | 값 | 이유 |
|---|---|---|
| `TRUST_FORWARDED_FOR` | `"true"` | 끄면 모든 요청이 정문 core 주소(`172.30.0.10`) 하나로 보여, 무차별 대입 한 번에 그 주소가 잠기고 모두가 막힙니다 |
| `TRUSTED_PROXY_IPS` | `"172.30.0.10"` | 이 주소(정문)에서 온 요청의 쪽지만 믿습니다. core 안에서 정문을 거치지 않고 앱에 직접 보내는 "옆문" 요청의 위조 쪽지는 무시합니다(C0-1, 시나리오 S8) |

## 바깥에 열리는 문은 두 개뿐

| 문 | 주소 | 이유 |
|---|---|---|
| 정문 | `127.0.0.1:8080` | 내 브라우저가 들어오는 곳 |
| Mailpit 화면 | `127.0.0.1:8025` | 단지 안에서 보낸 메일을 실제로 보내지 않고 모아 보는 곳 |

- 둘 다 `127.0.0.1`에만 열려 있어서, 같은 와이파이의 다른 PC에서는 들어올 수 없습니다.
- 앱(`5000`)은 `expose`만 하고 `ports`가 없어 바깥에서 직접 열 수 없습니다.

## 앱 컨테이너 — `Dockerfile`

| 줄 | 이유 |
|---|---|
| `python:3.12-slim` | 기존 앱과 같은 Python 버전, 작은 이미지 |
| `requirements.txt`를 먼저 복사 | 코드만 바뀌었을 때 라이브러리 설치를 다시 하지 않게(빌드 캐시) |
| `gunicorn --workers 1 --threads 8` | 프로세스는 하나, 스레드로 여러 요청을 처리합니다. 쿨다운처럼 여러 곳이 함께 지켜야 하는 값은 프로세스 메모리가 아니라 DB 표(`notification_cooldowns`)에 둡니다 |

`.dockerignore`가 `.env`, `tests/`, `docs/`, `web/`, `netwatch/`, 문서(`*.md`) 등을 빼므로 앱 이미지에 비밀값과 필요 없는 파일이 들어가지 않습니다. 비밀값은 실행할 때 `env_file: .env`로만 넣습니다.

## 직접 확인해 보기

켜는 법과 `.env` 준비는 [`netwatch/README.md`](../../netwatch/README.md)를 따릅니다.

```bash
# 단지 설정 검사 (서비스·네트워크·nginx 덮어쓰기·공개 포트)
pytest tests/track_d/test_a_compose.py -q

# 단지 켜고 상태 보기
docker compose up -d --build
docker compose ps

# 네트워크 3개 확인
docker network ls --filter name=lw_edge --filter name=login-watchdog

# 정문 안의 인터페이스 이름 확인 (172.30이 아닌 쪽이 edge — PC마다 eth0/eth1이 다름)
docker compose exec gateway ip -4 -o addr
```

- 브라우저에서 `http://localhost:8080/login`이 열리면 성공입니다.
- 이 절에서는 Supabase에 새로 볼 표가 없습니다. Track D 표는 [52단계](guide52_net_ingest_correlation.md)에서 다룹니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [Dockerfile](../../Dockerfile), [.dockerignore](../../.dockerignore), [docker-compose.yml](../../docker-compose.yml), [netwatch/nginx/nginx.conf](../../netwatch/nginx/nginx.conf), [tests/track_d/test_a_compose.py](../../tests/track_d/test_a_compose.py)
- 수정: [.env.example](../../.env.example)(Track D 구역 A 소구역)

## 알려진 제한

- 정문은 `/api/internal/*`(센서·차단 프로그램 전용 창구)도 바깥에서 넘겨 줍니다. 서명(HMAC)이 없으면 앱이 401로 거절하므로 뚫리지는 않지만, 정문에서 경로 자체를 막을지는 검토 중입니다.
