# 51단계 — 네트워크 센서 (Docker 단지·정문·CCTV)

[◀ 50단계](guide50_demo_sample_logs.md) · [전체 목차](beginner-guide.md) · [52단계 ▶](guide52_net_ingest_correlation.md)

> 지금까지 login-watchdog은 **앱 안에서** 로그인 실패·요청 수를 세어 공격을 찾았습니다(L7). 그런데 SYN Flood나 포트 스캔처럼 **앱까지 오지 않는 공격**은 앱이 볼 수 없습니다. Track D에서는 앱 앞에 "정문"을 세우고 정문을 지나는 통신을 지켜보는 센서를 붙입니다.
> 이 문서는 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **연습용 단지·네트워크 3개·정문(nginx)**, **정문 CCTV(Suricata·Scapy)와 배달원(shipper)**, **센서 정지 보고(A2-3)**, **기록 크기 제한·자동 재시작(A3-1)** 까지입니다(2026-10-26 main 기준).

## 비유 — 아파트 단지와 정문

| 비유 | 실제 | 하는 일 |
|---|---|---|
| **아파트 단지** | Docker Compose 환경 (`docker-compose.yml`) | 아래 건물·도로를 명령 한 번으로 켜고 끕니다 |
| 건물 | Docker 컨테이너 | `gateway`, `app`, `mailpit`, `sensor`, `l4-detector`, `shipper`, `fw-agent`, `attacker-1~3` |
| 도로 | Docker 네트워크 `edge`·`core`·`egress` | 건물끼리 어떤 길로만 다닐 수 있는지 정합니다 |
| **정문** | `gateway` (nginx) | 바깥에서 오는 모든 요청이 거치는 단 하나의 입구. `localhost:8080` |
| 정문 CCTV | `sensor`(Suricata), `l4-detector`(Scapy) | 정문을 지나는 통신을 지켜봅니다 (아래 ③ 절) |
| 배달원 | `shipper` | CCTV 기록을 앱에 전달하고, CCTV가 멈추면 알립니다 (아래 ③·④ 절) |
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

**내부 창구는 정문에서 끊습니다(10/26 보완).** `location ^~ /api/internal/ { return 404; }` — 센서·차단 프로그램 전용 창구는 shipper·fw-agent가 core 망에서 `app:5000`으로 바로 부르므로, 바깥(공격 상자가 있는 edge)에서 정문을 거쳐 올 일이 없습니다. 서명 없이도 이 주소를 두드려 수집 한도를 갉아먹는 일을 입구에서 막습니다([56단계](guide56_feedback_hardening.md) ①).

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

## ③ 정문 CCTV 두 대 — Suricata(`sensor`)와 Scapy(`l4-detector`) (A1-1·A1-2)

정문에는 성격이 다른 CCTV 두 대가 달려 있습니다.

| CCTV | 컨테이너 | 보는 방식 | 잘하는 것 |
|---|---|---|---|
| Suricata | `sensor` (`netwatch/suricata/`) | 통신 **내용**을 읽고 규칙과 맞춰 봅니다 | 로그인 요청 폭주, 스캐너 도구 이름 같은 HTTP(L7) 공격 |
| Scapy | `l4-detector` (`netwatch/l4_detector/`) | 패킷 **개수**만 셉니다 | SYN Flood, 포트 스캔 같은 연결 단계(L4) 공격 |

> **왜 두 대인가:** Suricata는 내용을 보는 데 강하지만, "한 주소가 10초 동안 서로 다른 포트를 몇 개 두드렸나"처럼 숫자를 세는 일은 우리가 원하는 기준대로 바꾸기 어렵습니다. Scapy 쪽은 우리가 직접 짠 짧은 코드라 기준(`L4_SYN_PER_SEC`, `L4_DISTINCT_PORTS_10S`)을 바로 고칠 수 있습니다. SYN Flood는 둘 다 잡으므로 한쪽이 놓쳐도 다른 쪽이 남깁니다.

### 어디를 보나

두 CCTV 모두 **정문(gateway) 안에 들어가** edge 쪽 인터페이스만 봅니다(`network_mode: "service:gateway"`). 그래서 공격자가 정문에 보낸 통신은 보이지만, 정문이 앱에 넘기는 core 쪽 통신은 보지 않습니다. 어느 인터페이스가 edge인지는 앞 절의 "edge 주소가 붙은 쪽" 규칙으로 고릅니다.

- Scapy는 core 대역(`172.30.0.0/24`)과 정문 자신의 주소에서 온 패킷을 아예 세지 않습니다(`detector_core.py`의 `_is_excluded_source`). 정문·앱끼리의 정상 통신을 공격으로 세지 않기 위해서입니다.

### 무엇을 잡나

| CCTV | 번호(signature_id) | 경보 이름 | 기준 | 층 |
|---|---|---|---|---|
| Suricata | 9000001 | `SYN_FLOOD` | 같은 출발지에서 8080으로 SYN 100개 / 5초 | L4 |
| Suricata | 9000003 | `LOGIN_BURST` | 같은 출발지에서 `/login` POST 20번 / 10초 | L7 |
| Suricata | 9000004 | `SCANNER_UA` | User-Agent에 sqlmap·nikto·nmap·masscan·dirbuster·gobuster | L7 |
| Scapy | 9100001 | `SYN_FLOOD` | 같은 출발지의 SYN이 1초 안에 100개 이상(기본값) | L4 |
| Scapy | 9100002 | `PORT_SCAN` | 같은 출발지가 10초 안에 서로 다른 포트 15개 이상(기본값) | L4 |

- 자체 규칙은 `netwatch/suricata/rules/local.rules`에 있습니다. 번호와 경보 이름의 짝은 계약서 K4가 기준이라 마음대로 바꾸지 않습니다.
- Scapy는 같은 출발지·같은 경보를 10초에 한 번만 씁니다(`cooldown_seconds`). 공격이 이어지는 동안 같은 줄이 패킷마다 쌓이지 않게 하려는 것입니다.
- 공개 규칙 묶음(ET Open)의 경보도 함께 나옵니다. 웹 공격 분류(`web-application-attack`)면 `WEB_ATTACK`, 그 밖은 `OTHER`로 넘깁니다.

### Suricata가 켜질 때 하는 일 — `netwatch/suricata/entrypoint.sh`

| 순서 | 하는 일 | 이유 |
|---|---|---|
| 1 | `suricata.yaml`의 `__HOME_NET__`·`__SENSOR_IFACE__`를 이 PC 값으로 바꿈 | 사람마다 edge 대역과 인터페이스 이름이 달라도 같은 설정 파일을 쓰려고 |
| 2 | ET Open 규칙 파일이 **없을 때만** `suricata-update`로 받음 | 켤 때마다 인터넷에서 받으면 느리고, 시연장 네트워크가 막히면 센서가 못 켜집니다 |
| 3 | 받기에 실패하면 빈 규칙 파일을 만들고 자체 규칙만으로 시작 | 공개 규칙이 없어도 우리 경보 세 가지는 동작하게 |

> 이 파일은 줄바꿈이 **LF**여야 합니다. Windows에서 CRLF로 바뀌면 컨테이너가 시작하자마자 `set: -: invalid option`으로 멈춥니다. 저장소의 `.gitattributes`가 `*.sh`를 LF로 꺼내 줍니다.

### 기록 파일

| 파일 | 누가 쓰나 | 들어가는 줄 |
|---|---|---|
| `eve.json` | Suricata | 경보(`alert`), 연결 기록(`flow`), HTTP 요청(`http`), 1분마다 통계(`stats`, ④ 절) |
| `l4.json` | Scapy | 경보 한 건에 한 줄(`src_ip`, `category`, `syn_per_sec`, `distinct_ports_10s`) |

두 파일은 `eve` 볼륨 하나에 함께 있습니다. sensor·l4-detector가 쓰고, shipper는 **읽기 전용**으로 붙어 있어 기록을 고칠 수 없습니다.

## ③ 배달원 — shipper (A1-3)

CCTV는 기록만 남길 뿐 앱에 알려 주지 않습니다. 배달원(`netwatch/shipper/eve_shipper.py`)이 두 파일을 계속 읽다가, 경보 줄이 생기면 앱의 수집 창구(`/api/internal/net-events`, [52단계](guide52_net_ingest_correlation.md))로 보냅니다.

| 단계 | 코드 | 하는 일 | 이유 |
|---|---|---|---|
| 읽기 | `Tailer` | 파일 **끝에서부터** 새로 붙은 완성된 줄만 읽습니다. 파일이 잘리거나 새로 만들어지면 처음부터 다시 읽습니다 | 켜기 전 기록을 한꺼번에 다시 보내지 않으려고. 리눅스가 지운 파일의 inode 번호를 새 파일에 다시 쓰는 경우도 잡아, 줄 중간부터 읽어 JSON이 깨지는 일을 막았습니다 |
| 고르기·바꾸기 | `to_event` | 경보 줄만 골라 계약서 K4 모양(`sensor`, `layer`, `category`, `signature_id`, `src_ip` …)으로 바꿉니다. `flow`·`http`·`stats` 줄은 건너뜁니다 | 앱은 경보만 필요합니다 |
| 묶기 | `Aggregator` | 같은 경보의 **첫 건은 바로** 보내고, 같은 1분 창 안에 더 오면 `packet_count`를 더해 두었다가 창이 끝날 때 **한 번 더**(갱신) 보냅니다 | 5초 안에 탐지·차단하려면 첫 건은 기다리면 안 되고, 공격 중 수천 줄을 하나하나 보내면 앱과 DB가 버티지 못합니다 |
| 이름 붙이기 | `make_event_id` | `sha256(sensor\|src_ip\|category\|signature_id\|window_start)` | 첫 전송·갱신·재시도가 모두 같은 이름이라 앱이 두 번 저장하지 않습니다(멱등) |
| 보내기 | `Sender` | 서명 헤더(`X-LW-Sender`·`X-LW-Timestamp`·`X-LW-Signature`, 계약서 K3)를 붙여 보냅니다 | 앱이 진짜 배달원이 보낸 것인지 확인합니다([52단계](guide52_net_ingest_correlation.md)) |
| 다시 보내기 | `Sender._deliver` | 5xx·429(한도 초과)나 연결 실패면 1·2·4·8초 쉬며 최대 5번(429에 `Retry-After`가 있으면 그 값, 최대 60초). 그 밖의 4xx면 다시 보내지 않습니다 | 앱이 잠깐 바쁜 것은 기다리면 풀리지만, 서명이 틀린 것(401)은 몇 번을 보내도 같습니다. 429를 예전처럼 버리면 한도에 걸린 공격 경보가 영영 앱에 닿지 않습니다(10/26 보완, [56단계](guide56_feedback_hardening.md) ①) |
| 생존 신호 | `heartbeat_body` | 30초마다 `/api/internal/heartbeat`에 파일 크기·대기열 길이를 보냅니다 | 앱이 "배달원이 살아 있나"를 압니다([54단계](guide54_l4_block_agent.md)의 장비 정지 감시) |

- 보내기는 별도 작업 스레드가 맡고, 대기열은 1000개까지입니다. 가득 차면 새 경보를 버리고 로그에 `[WARN] … 대기열이 가득 차` 를 남깁니다. 앱이 오래 멈췄을 때 배달원 메모리가 끝없이 늘어나지 않게 하려는 것입니다.
- 배달원은 **앱 코드를 import하지 않습니다.** 다른 컨테이너에서 돌기 때문에, 서명·event_id 규칙을 계약서대로 따로 구현했습니다. 받는 값도 서명 키(`NET_INGEST_SECRET`)·앱 주소·파일 경로·정지 기준뿐이고 `.env` 전체를 받지 않습니다.

## ④ 센서 정지 보고 (A2-3)

CCTV가 꺼져도 "경보가 없다"와 "CCTV가 꺼졌다"는 겉으로 똑같이 조용합니다. 공격자가 센서부터 무력화하면(대량 패킷, 디스크 가득 — 계획 V14) 관리자는 평화로운 줄 압니다. 그래서 배달원이 CCTV 기록 파일이 자라는지를 지켜봅니다.

| 코드 | 하는 일 |
|---|---|
| `StallWatch.observe(eve_bytes, l4_bytes)` | 파일마다 마지막 크기와 마지막으로 바뀐 시각을 기억합니다. **두 파일 모두** `SHIPPER_STALL_SECONDS`(기본 120초) 넘게 그대로면 정지로 봅니다. 파일이 잘리거나 새로 만들어져 작아져도 "움직였다"로 봅니다 |
| `heartbeat_body(..., stalled=, stalled_seconds=)` | 30초 생존 신호에 `"stalled": true/false`와 `detail.stalled_seconds`(마지막으로 늘어난 뒤 흐른 초)를 실어 보냅니다 |
| 앱 `routes/internal/heartbeat.py` | `stalled: true`를 받으면 Slack으로 알립니다. 같은 PC·같은 장비는 `AGENT_ALERT_COOLDOWN_SECONDS`에 한 번만 보냅니다 |

배달원 로그에는 상태가 **바뀔 때만** 한 줄씩 남습니다.

```text
[WARN] 두 센서 출력이 120초 동안 증가하지 않아 정지 상태로 판단합니다.
[OK] 센서 출력 증가를 확인하여 정지 상태가 해제되었습니다.
```

### 조용할 때 "정지"로 오해하지 않게

l4.json은 공격이 있을 때만 늘어나고, eve.json도 원래는 통신이 있을 때만 늘어났습니다. 그러면 아무도 접속하지 않는 2분 동안 센서가 멀쩡해도 "정지" 알림이 갑니다. 그래서 Suricata가 살아 있으면 통신이 없어도 **1분마다 통계 한 줄**(`stats`)을 eve.json에 쓰게 했습니다(`suricata.yaml`의 `stats: interval: 60`).

| 값 | 기본 | 이유 |
|---|---|---|
| Suricata `stats` 간격 | 60초 | 정지 기준(120초)보다 충분히 짧고, 기록이 너무 빨리 쌓이지 않게 |
| `SHIPPER_STALL_SECONDS` | 120초 | 통계 한 번이 늦어져도 오판하지 않게 그 두 배. **60초 이하로 낮추면 조용할 때 오판합니다** |

- 정지 판단 기준은 `.env`의 `SHIPPER_STALL_SECONDS`로 바꾸고, `docker-compose.yml`이 이 값을 shipper에 넘깁니다. 숫자가 아니거나 0 이하면 배달원이 시작하지 않고 `[FAIL]`을 남깁니다.
- 정지를 그 자리에서 따로 보내지 않고 30초 생존 신호에 실어 보냅니다. 알림을 너무 자주 보내지 않게 막는 쿨다운은 앱이 맡습니다.

## ⑤ 오래 켜 둘 때 — 기록 크기 제한과 자동 재시작 (A3-1)

CCTV 녹화 테이프가 끝없이 길어지면 언젠가 창고(디스크)가 가득 찹니다. 그런데 이 테이프는 배달원이 0.2초마다 새로 찍힌 부분을 가져가 이미 앱에 넘긴 상태입니다. 그래서 일정 길이가 넘으면 **같은 테이프를 처음으로 감아 다시 씁니다.**

| 기록 파일 | 설정(기본값) | 넘으면 |
|---|---|---|
| `eve.json` (Suricata) | `EVE_MAX_BYTES` (50MiB) | `entrypoint.sh`가 30초마다 크기를 보고 같은 파일을 비움. 로그 `[WARN] eve.json이 …바이트에 도달해 크기 제한(…)에 따라 비웠습니다.` |
| `l4.json` (Scapy) | `L4_MAX_BYTES` (10MiB) | 쓰기 직전에 `truncate_output_if_oversized()`가 비움. 로그 `[WARN] l4.json이 크기 제한에 도달해 기존 내용을 비웠습니다` |

- **지우지 않고 "비우는" 이유:** 파일을 지우거나 이름을 바꾸면 배달원이 붙잡고 있던 파일과 새 파일이 달라져 새 기록을 놓칠 수 있습니다. 같은 파일의 길이만 0으로 만들면, 배달원은 "크기가 줄었다 = 처음부터 다시 쓰였다"로 알아채고 새 첫 줄부터 다시 읽습니다(④의 정지 보고도 "작아짐"을 움직임으로 봅니다).
- **재시작:** 상시 서비스는 모두 `restart: unless-stopped`입니다(A3-1에서 `l4-detector`에도 추가). 예외로 죽어도 Docker가 다시 띄우고, 같은 경보는 같은 `event_id`로 오므로 앱에 두 번 저장되지 않습니다([52단계 ②](guide52_net_ingest_correlation.md)).
- 값은 `.env`에 1 이상의 정수로 바꿀 수 있습니다. 0이나 글자를 넣으면 sensor가 `[FAIL] EVE_MAX_BYTES는 1 이상의 정수여야 합니다`로 시작하지 않습니다.
- A3-1 커밋에는 탐지 기준값(SYN 비율·포트 수·Suricata 규칙) 변경이 없습니다.

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

### 센서·배달원 (③·④ 절)

```bash
# 자체 규칙·설정, L4 측정기, 인터페이스 자동 선택, 배달원(정지 판단 포함) 테스트
pytest tests/track_d/test_a_suricata_rules.py tests/track_d/test_a_l4_detector.py tests/track_d/test_a_l4_iface.py tests/track_d/test_a_shipper.py -q

# CCTV가 고른 인터페이스와 규칙 로딩
docker compose logs sensor
docker compose logs l4-detector

# 배달원이 경보를 보내는지 (Ctrl+C로 빠져나옴)
docker compose logs -f shipper

# CCTV 기록 마지막 몇 줄 — 1분마다 "event_type":"stats" 줄이 보이면 Suricata가 살아 있는 것
docker compose exec shipper tail -n 5 /var/log/suricata/eve.json
```

- 경보를 일부러 만들려면 [`netwatch/README.md`](../../netwatch/README.md) 7장의 공격 상자 명령(예: `scanner-ua`)을 씁니다. 몇 초 뒤 Supabase `network_events` 표에 새 행이 생기면 CCTV → 배달원 → 앱이 이어진 것입니다.
- 배달원 생존 신호는 Supabase `agent_heartbeats` 표의 `agent = 'shipper'` 행에 PC 이름(`node`)별로 남습니다. `detail`의 `stalled`가 `false`, `stalled_seconds`가 120보다 작으면 정상입니다.
- **정지 보고 확인(④):** 아무 접속 없이 3분 두어도 배달원 로그에 `[WARN] 두 센서 출력이 …` 줄이 **없어야** 합니다. 그다음 `docker compose stop sensor l4-detector`로 CCTV를 끄고 2분 넘게 기다리면 그 줄이 생기고 Slack 알림이 옵니다. `docker compose start sensor l4-detector`로 다시 켜면 `[OK] … 해제` 줄이 생깁니다.

## 이 단계에서 만들어지거나 바뀐 파일

- 신규: [Dockerfile](../../Dockerfile), [.dockerignore](../../.dockerignore), [docker-compose.yml](../../docker-compose.yml), [netwatch/nginx/nginx.conf](../../netwatch/nginx/nginx.conf), [tests/track_d/test_a_compose.py](../../tests/track_d/test_a_compose.py)
- 수정: [.env.example](../../.env.example)(Track D 구역 A 소구역)
- 신규(③ CCTV, A1-1·A1-2): [netwatch/suricata/suricata.yaml](../../netwatch/suricata/suricata.yaml), [netwatch/suricata/entrypoint.sh](../../netwatch/suricata/entrypoint.sh), [netwatch/suricata/rules/local.rules](../../netwatch/suricata/rules/local.rules), [netwatch/l4_detector/detector_core.py](../../netwatch/l4_detector/detector_core.py), [netwatch/l4_detector/l4_detector.py](../../netwatch/l4_detector/l4_detector.py), [tests/track_d/test_a_suricata_rules.py](../../tests/track_d/test_a_suricata_rules.py), [tests/track_d/test_a_l4_detector.py](../../tests/track_d/test_a_l4_detector.py), [tests/track_d/test_a_l4_iface.py](../../tests/track_d/test_a_l4_iface.py)
- 신규(③ 배달원, A1-3): [netwatch/shipper/eve_shipper.py](../../netwatch/shipper/eve_shipper.py), [tests/track_d/test_a_shipper.py](../../tests/track_d/test_a_shipper.py)
- 수정(④ 정지 보고, A2-3): `eve_shipper.py`(`StallWatch`), `suricata.yaml`(`stats`), [docker-compose.yml](../../docker-compose.yml)·`.env.example`(`SHIPPER_STALL_SECONDS`)
- 수정(⑤ 안정화, A3-1): `entrypoint.sh`(`EVE_MAX_BYTES`), `detector_core.py`(`truncate_output_if_oversized`)·`l4_detector.py`(`L4_MAX_BYTES`), `docker-compose.yml`(두 값 전달·`l4-detector` 재시작), 테스트 `test_a_l4_detector.py`·`test_a_shipper.py`·`test_a_suricata_rules.py`

## 알려진 제한

- 정문은 `/api/internal/*`(센서·차단 프로그램 전용 창구)도 바깥에서 넘겨 줍니다. 서명(HMAC)이 없으면 앱이 401로 거절하므로 뚫리지는 않지만, 정문에서 경로 자체를 막을지는 검토 중입니다.
- `eve.json`·`l4.json`은 크기 제한(50MiB·10MiB)에 닿으면 비워집니다(⑤). 비우기 직전 0.2초 안에 쓰인 줄은 배달원이 아직 못 가져갔다면 빠질 수 있습니다.
- SYN Flood는 Suricata와 Scapy가 둘 다 잡으므로 같은 공격이 경보 두 줄로 들어옵니다. 둘은 `sensor`·`signature_id`가 달라 서로 덮어쓰지 않습니다.
- 정지 보고는 **두 파일이 모두** 멈췄을 때만 울립니다. Suricata는 살아 있고 Scapy(`l4-detector`)만 멈춘 경우는 잡지 못합니다. 그 경우는 `docker compose ps`로 확인합니다.
