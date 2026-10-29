# netwatch — Track D 로컬 Docker 단지 실행 안내

> Track D(네트워크 계층 탐지·차단)를 **내 PC의 Docker 안에서** 켜고 끄는 방법을 위에서 아래로 적은 문서입니다.
> 처음 보는 사람이 1장부터 순서대로 따라 하면 `http://localhost:8080/login`이 열리도록 쓰는 것이 목표입니다.
> 함수 이름·주소·데이터 모양의 기준은 [`docs/track-d/contracts.md`](../docs/track-d/contracts.md)(이하 계약서)입니다. 이 문서와 다르면 계약서가 맞습니다.
>
> - 이 문서는 통합 담당자가 관리합니다. 지금은 **단지 켜기·주소표·A0-2 확인 결과, 센서·shipper·fw-agent 상태 보기와 오래 켜 둘 때의 안정화(6장), 공격 상자·victim 계정·위조 출발지·ICMP(7장), 막혔을 때(8장), 시나리오 자동 점검 S4~S9(9장)** 까지입니다(2026-10-29 guide57 기준).
> - 2026-10-29부터 역할 구분 없이 통합 담당자가 혼자 고치고 확인합니다. 예전에 절 제목에 붙어 있던 "(A 확인 전)" 표시는 뗐습니다 — 1~3·6장 명령은 10/22 병합2 종합 점검과 10/26·10/29 시연 PC의 `run_all` 실행에 실제로 쓰인 것입니다.
> - 키·비밀번호·`.env`의 실제 값은 이 문서에 적지 않습니다. 변수 **이름**만 적습니다.

---

## 1. 준비물

| 준비물 | 확인 방법 | 비고 |
|---|---|---|
| Docker Desktop (WSL2 백엔드) | Docker Desktop을 켠 뒤 터미널에서 `docker compose version`이 버전을 출력 | Windows는 WSL2 백엔드를 씁니다. 10/19 통합 담당자 PC에서 Docker Desktop 4.91(WSL2)로 확인 |
| 저장소 최신 `main` | `git switch <내 브랜치>` → `git fetch origin` → `git merge origin/main` | 팀 계획 01의 2장 ① 순서 |
| 비밀키 2개 | 팀 Infisical에서 `NET_INGEST_SECRET`, `NET_AGENT_SECRET` 값을 확인 | 메신저·AI 대화에 붙여 넣지 않습니다 |

모든 명령은 저장소 루트(`login-watchdog` 폴더)에서 실행합니다.

---

## 2. `.env` 준비

앱 컨테이너는 저장소 루트의 `.env`를 통째로 읽고(`env_file: .env`), Docker Compose는 같은 `.env`에서 대역 값(`LW_EDGE_PREFIX` 등)을 읽습니다.

1. 이미 쓰던 `.env`가 있으면 그대로 두고, `.env.example` 맨 아래 **`# === Track D ===` 구역**을 내 `.env` 맨 아래에 복사합니다. `.env`가 없으면 `.env.example`을 복사해 `.env`를 만듭니다.
2. 비밀키 2개(`NET_INGEST_SECRET`, `NET_AGENT_SECRET`)를 Infisical 값으로 채웁니다. 비어 있으면 내부 API가 모든 요청을 401로 거부해서 shipper·fw-agent가 앱과 통신하지 못합니다.
3. **사람마다 다른 4줄**을 아래 표대로 바꿉니다. `.env.example`의 `LW_EDGE_PREFIX` 기본값은 A의 값(`172.28.11`)이라 B·C는 반드시 바꿔야 합니다.

| 변수 | A 편승훈 | B 김재호 | C 유지은 | 시연용(발표 PC) |
|---|---|---|---|---|
| `LW_EDGE_PREFIX` | `172.28.11` | `172.28.12` | `172.28.13` | `172.28.0` |
| `NET_EDGE_SUBNET` | `172.28.11.0/24` | `172.28.12.0/24` | `172.28.13.0/24` | `172.28.0.0/24` |
| `PERMANENT_LOCK_IP_ALLOWLIST` | `127.0.0.1,::1,172.28.11.1` | `127.0.0.1,::1,172.28.12.1` | `127.0.0.1,::1,172.28.13.1` | `127.0.0.1,::1,172.28.0.1` |
| `LW_NODE_NAME` | `A` | `B` | `C` | `demo` |

> **왜 사람마다 대역을 나누나:** 세 명이 같은 Supabase DB를 씁니다. 대역이 같으면 내 포트 스캔과 남의 무차별 대입이 같은 IP로 기록돼 가짜 킬체인 사건이 생깁니다(팀 계획 01의 D4).
> `PERMANENT_LOCK_IP_ALLOWLIST`의 `.1`은 내 브라우저(호스트)가 edge 대역에서 쓰는 주소입니다. 허용 목록에 넣어야 내 브라우저가 차단되지 않습니다.

4. `SENSOR_IFACE`는 **모든 PC가 `eth1` 그대로**입니다(`.env.example` 기본값). 실제 edge가 eth0인 PC도 sensor·l4-detector가 `${LW_EDGE_PREFIX}.10`이 붙은 쪽을 스스로 찾아 감시합니다(5장 참고). 이때 로그의 `[WARN] …를 감시합니다` 한 줄은 정상이고, 경고 안의 ".env를 고치라"는 안내는 따르지 않습니다.
   tcpdump처럼 인터페이스 이름을 직접 써야 할 때만 아래 명령으로 실제 edge(`172.30`이 **아닌** 쪽)를 확인합니다.

   ```bash
   docker run --rm --network container:login-watchdog-gateway nicolaka/netshoot ip -br addr
   ```
5. `TRUSTED_PROXY_IPS`는 비워 둬도 됩니다. Docker에서는 `docker-compose.yml`이 앱에 `172.30.0.10`을 직접 넣습니다.

> **Vercel에는 Track D 값을 넣지 않습니다.** 비어 있으면 Track D 기능이 꺼진 채로 기존 앱이 그대로 동작합니다.

---

## 3. 켜기·끄기·상태·로그

| 하고 싶은 일 | 명령 |
|---|---|
| 켜기 (처음 또는 코드가 바뀐 뒤) | `docker compose up -d --build` |
| 켜기 (이미 빌드한 뒤) | `docker compose up -d` |
| 상태 보기 | `docker compose ps` |
| 앱 로그 보기 | `docker compose logs -f app` |
| 정문(nginx) 로그 보기 | `docker compose logs -f gateway` |
| 끄기 (컨테이너·네트워크 정리) | `docker compose down` |

- 켠 뒤 브라우저에서 `http://localhost:8080/login`이 열리면 성공입니다(M0 완료 기준).
- `docker compose ps`에서 기본으로 켜지는 서비스는 `gateway`, `app`, `mailpit`, `sensor`, `l4-detector`, `shipper`, `fw-agent`입니다. 공격 상자 `attacker-1~3`은 `attack` 프로필이라 기본으로 켜지지 않습니다(사용법은 7장).
- 앱을 Docker 없이 직접 실행할 때 쓰던 `docker-compose.mailpit.yml`은 **함께 띄우지 않습니다.** 이 단지에 Mailpit이 이미 들어 있어 컨테이너 이름·8025 포트가 충돌합니다.

---

## 4. 접속 주소표 (계약서 K2)

| 대상 | 주소 | 비고 |
|---|---|---|
| 외부 접속 (내 브라우저) | `http://localhost:8080` | gateway만 포트를 공개합니다. `127.0.0.1`에만 열려 있어 같은 와이파이의 다른 PC에서는 접속할 수 없습니다 |
| Mailpit 화면 (받은 메일) | `http://localhost:8025` | 비밀번호 복구 메일 등이 실제로 나가지 않고 여기에 쌓입니다 |
| gateway(nginx) edge 쪽 | `${LW_EDGE_PREFIX}.10` | sensor·l4-detector·fw-agent가 이 컨테이너의 네트워크를 함께 씁니다 |
| gateway core 쪽 | `172.30.0.10` (고정) | 앱의 `TRUSTED_PROXY_IPS` 값 |
| 내 브라우저(호스트) | `${LW_EDGE_PREFIX}.1` | 허용 목록에 들어가는 주소 |
| attacker-1 / 2 / 3 | `${LW_EDGE_PREFIX}.101` / `.102` / `.103` | `attack` 프로필 |
| 앱 내부 주소 | `http://app:5000` | 단지 안의 shipper·fw-agent만 씁니다. 바깥에서는 열리지 않습니다 |

**edge 대역 끝자리 나눔** (계약서 K2 밖의 운영 약속 — 같은 주소를 두 용도가 쓰면 차단·사건이 섞여 판정이 틀어집니다)

| 끝자리 | 쓰는 곳 |
|---|---|
| `.1` / `.10` | 내 브라우저 / gateway |
| `.2`~`.9` | 비워 둠 (Docker 자동 할당과 겹칠 수 있음) |
| `.11`~`.99`, `.111`~`.139` | C3-1 시나리오 점검의 일회용 공격 상자(9장, `scripts/net/check_common.py`) |
| `.101`~`.103` | 고정 공격 상자 attacker-1~3 (수동 시연) |
| `.140` | S7 위조 출발지 전용 |
| `.150`~`.199` | 5초 측정(`scripts/net/measure_*`)·수동 차단 예시 |
| `.200`~`.254` | S7 ① 출발지를 바꾸는 SYN 폭주가 돌려 쓰는 가짜 출발지(guide57, `lw.py synflood --rand-source`) |

**네트워크 3개**

| 이름 | Docker 네트워크 이름 | 대역 | 붙어 있는 것 | 역할 |
|---|---|---|---|---|
| edge | `lw_edge` | `${LW_EDGE_PREFIX}.0/24` | gateway, attacker | 바깥(공격자) 쪽. 사람마다 대역이 다릅니다 |
| core | `login-watchdog-core` | `172.30.0.0/24` | gateway, app, mailpit, shipper | 안쪽. `internal`이라 인터넷으로 나가지 못합니다 |
| egress | `login-watchdog-egress` | Docker 자동 | app, mailpit | 앱이 Supabase·Slack으로 나가는 길, Mailpit 화면 공개용 |

> **core가 172.29가 아니라 172.30인 이유:** Docker Desktop(WSL2)이 VM 내부 통신에 `172.29.0.0/24`를 써서, 겹치면 "Network Creating"에서 멈추고 엔진 연결이 끊겼습니다. 10/19에 `172.30.0.0/24`로 옮겼고 계약서 K2도 같이 고쳤습니다.

---

## 5. A0-2 세 PC 확인 결과

> A가 세 PC에서 직접 확인하고 PR 메모로 넘긴 값을 옮긴 표입니다(10/22 기준). 첫 세 줄은 화면 접속을 따로 기록하지 않았으므로, 단지가 실제로 떠서 센서가 돈 기록을 근거로 적었습니다.

| 확인 항목 | 결과 | 근거 |
|---|---|---|
| A PC에서 `docker compose up` 후 `/login` 접속 | 단지 기동 확인(`/login` 화면 접속은 따로 기록 안 함) | 2026-10-22 병합2 종합 점검 — 이 PC의 sensor·l4-detector `iface=` 줄(아래 줄) |
| B PC에서 `docker compose up` 후 `/login` 접속 | 단지 기동 확인(`/login` 화면 접속은 따로 기록 안 함) | 2026-10-22 병합2 종합 점검 — 이 PC의 sensor·l4-detector `iface=` 줄(아래 줄) |
| C PC에서 `docker compose up` 후 `/login` 접속 | 단지 기동 확인(`/login` 화면 접속은 따로 기록 안 함) | 2026-10-22 병합2 종합 점검 — 이 PC의 sensor·l4-detector `iface=` 줄(아래 줄) |
| 감시 인터페이스 이름 `SENSOR_IFACE` | **`.env`는 모두 `eth1` 고정, 실제 edge는 PC마다 다름** — 10/22 기록: A `eth1`, B `eth1`, C `eth0`, demo(통합 담당자 PC) `eth1`. A는 10/20에 `eth0`이었다가 컨테이너를 다시 만든 뒤 `eth1`로 바뀌었습니다. Docker가 네트워크를 붙이는 순서를 보장하지 않기 때문입니다 | 2026-10-22 병합2 종합 점검 — 네 PC의 `ip -br -4 addr`, sensor·l4-detector `iface=` 줄, eve.json `in_iface`(계약서 K1) |
| 인터페이스 자동 선택 | sensor(`netwatch/suricata/entrypoint.sh`)와 l4-detector(`detector_core.py`의 `resolve_sensor_iface`)가 `${LW_EDGE_PREFIX}.10`이 붙은 인터페이스를 찾아 감시합니다. `SENSOR_IFACE`가 틀리면 edge 쪽으로 바꾸고 로그에 `[WARN]`을 남깁니다 | 2026-10-20 main(f7899f1·cd4322e) |
| core 대역 충돌 | `172.29.0.0/24`는 Docker Desktop(WSL2) 내부 대역과 충돌 → `172.30.0.0/24` 사용 | 2026-10-19 통합 담당자 PC(Docker Desktop 4.91)에서 확인 |
| 출발지 위조 패킷이 gateway까지 그대로 도착하는지 (시나리오 S7 포함 여부) | **도착함 → S7 포함** (A PC). 발표 PC는 리허설 때 다시 확인 | 2026-10-22 A PC: hping3 `-a 172.28.11.150` → gateway edge(`eth1`) tcpdump에 `172.28.11.150 > 172.28.11.10.8080: Flags [S]`, `1 packet captured` |
| Suricata 이미지 태그 | `jasonish/suricata:7.0.17` | `docker-compose.yml`의 sensor 블록(A1-1) |

> 감시 인터페이스가 core 쪽이면 오류 없이 탐지가 0건이 됩니다(L4 측정기는 core 대역을 빼고 셉니다). 이런 일은 `LW_EDGE_PREFIX`가 틀려 자동 선택이 edge를 못 찾을 때만 생기고, 로그에 `…찾지 못해` 경고가 남습니다. 시연 직전에 `docker compose logs sensor`로 한 번 더 확인합니다.

---

## 6. 센서·shipper·fw-agent 상태 보기

`docker compose up -d --build` 한 번으로 아래 네 서비스가 함께 켜집니다(별도 프로필 없음).

| 서비스 | 하는 일 | 만든 작업 |
|---|---|---|
| `sensor` | Suricata. edge 쪽 통신을 보고 `eve.json`에 경보·흐름·HTTP 기록을 씁니다. 통신이 없어도 1분마다 통계(`stats`) 한 줄을 써서, shipper가 조용한 시간을 센서 정지로 오해하지 않게 합니다(A2-3). ET Open 규칙은 처음 켤 때 한 번 받고(`suricata-rules` 볼륨), 못 받으면 `local.rules`만으로 시작합니다 | A1-1 |
| `l4-detector` | Scapy. 출발지별 SYN 비율·서로 다른 포트 수를 세어 `l4.json`에 씁니다. guide57부터 위조 출발지(`SPOOFED_SRC`)·출발지를 바꾸는 SYN 폭주(`GLOBAL_SYN_FLOOD`)도 쓰고, 60초마다 생존 줄(`HEARTBEAT`)을 남깁니다 | A1-2·guide57 |
| `shipper` | 두 파일을 읽어 서명(HMAC)을 붙여 앱 수집 창구로 보내고, 30초마다 생존 신호를 보냅니다 | A1-3 |
| `fw-agent` | 앱 내부 API에서 차단 목록을 받아 gateway의 ipset `lw_block`에 넣고 빼고, 10초마다 생존 신호를 보냅니다. guide57부터 ICMP 속도 제한 체인 `LW_L3`도 걸고, 60초마다 빠진 규칙을 되살리며, 규칙 상태(`rules_ok`·`l3_ok`)를 생존 신호에 싣습니다 | C1-3·guide57 |

| 보고 싶은 것 | 명령 |
|---|---|
| 센서가 고른 인터페이스·규칙 로딩 | `docker compose logs sensor` |
| L4 측정기 로그 | `docker compose logs l4-detector` |
| 경보 전송 로그 | `docker compose logs -f shipper` |
| 차단 프로그램 로그 | `docker compose logs -f fw-agent` |
| 지금 걸린 L4 차단 목록 | `docker compose exec fw-agent ipset list lw_block` |
| 차단·ICMP 속도 제한 규칙과 버린 패킷 수 | `docker compose exec fw-agent iptables -t raw -L -v -n` (PREROUTING의 `lw_block` DROP과 `LW_L3` 체인) |
| 센서 기록 마지막 몇 줄 | `docker compose exec shipper tail -n 5 /var/log/suricata/eve.json` |

- 센서 기록 파일(`eve.json`·`l4.json`)은 `eve` 볼륨 하나에 함께 있습니다. sensor·l4-detector가 쓰고 shipper는 읽기만 합니다.
- shipper·fw-agent에는 `.env` 전체가 아니라 필요한 변수(서명 키, 앱 주소, 허용 목록)만 넘깁니다. 방화벽 권한(`NET_ADMIN`)이 있는 fw-agent에는 DB 키를 주지 않기 위해서입니다(계획 P6).
- `.env`의 `NET_INGEST_SECRET`·`NET_AGENT_SECRET`이 비어 있거나 틀리면 앱이 401로 거절합니다. 이때 shipper 로그에 `HTTP 401로 거부됐습니다`가, fw-agent 로그에는 목록 받기·보고 실패가 반복해서 보입니다.
- 공격 상자(attacker)로 경보를 일부러 만드는 방법은 7장에 있습니다.

### 6.1 오래 켜 둘 때 — 기록 크기 제한과 자동 재시작 (A3-1)

리허설·발표처럼 단지를 몇 시간씩 켜 두면 센서 기록 파일이 계속 커지고, 프로그램 하나가 죽으면 경보가 끊깁니다. 이를 막는 설정입니다(A3-1, 2026-10-26 main `f2f39bb`).

| 대상 | 설정 | 동작 |
|---|---|---|
| `eve.json` (Suricata) | `EVE_MAX_BYTES` (기본 `52428800` = 50MiB) | 30초마다 크기를 보고, 넘으면 **같은 파일을 비웁니다**(지우거나 이름을 바꾸지 않음). sensor 로그에 `[WARN] eve.json이 …바이트에 도달해 크기 제한(…)에 따라 비웠습니다.` |
| `l4.json` (Scapy) | `L4_MAX_BYTES` (기본 `10485760` = 10MiB) | 쓰기 전에 크기를 보고 넘으면 비웁니다. l4-detector 로그에 `[WARN] l4.json이 크기 제한에 도달해 기존 내용을 비웠습니다` |
| 모든 상시 서비스 | `restart: unless-stopped` | 예외로 종료돼도 Docker가 다시 띄웁니다(이번에 l4-detector에도 추가). `docker compose down`으로 끈 것은 다시 켜지 않습니다 |

- **비워도 경보가 빠지지 않는 이유:** shipper는 0.2초마다 새 줄을 읽어 바로 보내므로 파일에 남은 줄은 이미 보낸 것입니다. 파일 크기가 줄면 shipper가 "처음부터 다시 쓰였다"로 알아채고 새 첫 줄부터 다시 읽습니다.
- **재시작해도 중복 저장되지 않는 이유:** 같은 경보는 같은 서류 번호(`event_id`)로 오고, 앱 접수 창구가 이미 있는 번호를 새로 만들지 않습니다(guide52 ②).
- 값을 바꾸려면 `.env`에 `EVE_MAX_BYTES`·`L4_MAX_BYTES`를 1 이상의 정수로 넣습니다. 0이나 글자를 넣으면 sensor가 `[FAIL] EVE_MAX_BYTES는 1 이상의 정수여야 합니다`로 멈춥니다.
- A3-1 커밋(`3f02961`)에는 탐지 기준값(SYN 비율·포트 수 등) 변경이 없습니다. 정상 사용만으로 경보가 뜨는지(오탐) 확인한 결과는 A의 메모를 받으면 이 자리에 더합니다.

---

## 7. 공격 상자로 경보 만들기 (attacker)

> 단지가 탐지·차단을 제대로 하는지 보려면, 센서가 볼 수 있게 **edge 대역 안에서** 공격 트래픽을 흉내 내야 합니다. 이 일을 하는 것이 공격 상자 `lw-attacker` 이미지입니다. 대상은 늘 우리 gateway(`${LW_EDGE_PREFIX}.10:8080`) 하나로 고정돼 있고(`TARGET_URL`), 횟수·속도에 상한이 걸려 있습니다. 바깥 주소로는 쏠 수 없습니다.

### 7.1 명령과 재현하는 경보

각 명령은 결과를 JSON 한 줄로 출력합니다. `lw.py <명령>` 꼴로 부릅니다.

| 명령 | 흉내 내는 것 | 남는 경보(sid / category) | 쓰이는 시나리오 |
|---|---|---|---|
| `scan` | gateway 포트 몇 개 훑기 | Scapy `PORT_SCAN`(9100002) | S4 1단계(정찰) |
| `webscan` | 웹 경로 훑기 | — (앱 기록) | S4 2단계 |
| `brute` | 로그인 반복 시도 | — (앱 잠금) | S4 3단계 |
| `scanner-ua` | 스캐너 도구 이름을 User-Agent로 보내기 | Suricata `SCANNER_UA`(9000004) | S6 근거(L7 증거) |
| `login` | victim 계정으로 올바른 비밀번호 로그인 1회(`--username` 필수, 비밀번호는 `LW_VICTIM_PASSWORD`) | — (앱 로그인 기록) | S6(scanner-ua 뒤 로그인 성공) |
| `synflood` | gateway에 SYN 다발 보내기 | Suricata `SYN_FLOOD`(9000001)·Scapy(9100001) | S5 |
| `httpflood` | 한 경로에 요청 몰아보내기 | 앱 `HTTP_FLOOD` | S5b(synflood와 동시) |
| `probe` | gateway에 TCP 연결만 한 번 시도(`--timeout` 기본 3초), `reachable` 출력. HTTP를 보내지 않아 DB 흔적 없음 | — | S4 실제 접속 차단 확인 |
| `synflood --spoof-source <IP>` | 출발지를 꾸민 SYN 다발(hping3 `-a`). 이 PC edge 대역(.10 제외)·`172.30.0.0/24`·`192.0.2.0/24`만 허용 | 대역 안이면 SYN_FLOOD, 대역 밖이면 Scapy `SPOOFED_SRC`(9100003) | S7 ②③④ |
| `synflood --rand-source` | 출발지를 edge `.200~.254`로 돌려 쓰는 SYN 3000개(초당 2000개, raw 소켓) | Scapy `GLOBAL_SYN_FLOOD`(9100004) | S7 ① |
| `icmpflood` | gateway에 ICMP echo 다발(`--count` 기본 3000·최대 5000, 초당 1000개, `--spoof-source` 가능) | Suricata `ICMP_FLOOD`(9000005, `rules/l3.rules`) | S9 |

> `category`·`sid`의 기준은 계약서 K4입니다. `scanner-ua`가 보내는 이름은 `netwatch/suricata/rules/local.rules`의 sid 9000004 목록과 같아야 합니다.

### 7.2 고정 상자로 수동 실행 (시연용)

`attacker-1~3`(`.101`·`.102`·`.103`)은 **눈으로 보는 시연**에 씁니다. `attack` 프로필로 한 번만 띄웁니다. 적은 횟수로 확인부터 합니다.

```bash
docker compose --profile attack run --rm attacker-2 scan
docker compose --profile attack run --rm attacker-3 synflood --count 100
```

실행한 뒤 `docker compose logs sensor`(또는 shipper)에서 해당 경보가 올라오는지 봅니다.

### 7.3 일회용 새 IP 실행 (측정·시나리오 점검용)

같은 IP를 다시 쓰면 앞서 건 차단과 "사건당 규칙당 1회"에 막혀 재현이 되지 않습니다. 그래서 I2-2 측정과 C3-1 시나리오 점검은 **실행할 때마다 새 출발지 IP**로 일회용 컨테이너를 띄웁니다. edge 네트워크 이름은 `lw_edge`로 고정돼 있습니다.

```bash
docker run --rm --network lw_edge --ip ${LW_EDGE_PREFIX}.111 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 \
  lw-attacker:latest synflood --count 3000
```

- `--ip`는 측정용 범위(`.150~.199`) 또는 아직 쓰지 않은 주소로 바꿉니다. 고정 상자(`.101~.103`)·내 브라우저(`.1`)와 겹치지 않게 합니다.
- `login` 명령만 victim 계정이 필요합니다: `-e LW_VICTIM_PASSWORD=... --username victim_<역할>`을 더합니다. 비밀번호는 셸 기록에 남지 않게 환경 변수로만 넘기고, 이 문서·이미지에는 값을 적지 않습니다(victim 계정·비밀번호는 PC마다 다릅니다 — 팀 계획 01 4장). 계정 만들기와 환경 변수 설정은 7.4를 봅니다.
- 이미지가 없으면 먼저 빌드합니다: `docker compose build attacker-1`.

**S5b: SYN 폭주와 HTTP 폭주를 같은 IP에서 동시에**

S5b는 한 출발지에서 두 공격이 **동시에** 와야 CR-02(다계층 폭주)로 묶입니다. 그런데 같은 네트워크에서 컨테이너 두 개가 같은 `--ip`를 잡을 수는 없습니다(두 번째가 `Address already in use`로 바로 죽습니다). 그래서 **IP만 잡고 기다리는 자리 잡기 컨테이너**를 먼저 띄우고, 공격 두 개는 `--network container:`로 그 네트워크를 함께 씁니다. 두 공격 중 어느 쪽이 먼저 끝나도 다른 쪽이 끊기지 않습니다.

```bash
# 1) 자리 잡기: 이 IP만 쥐고 기다림(트래픽 없음)
docker run -d --rm --name lw-measure-${LW_EDGE_PREFIX}.151 --network lw_edge --ip ${LW_EDGE_PREFIX}.151 \
  --entrypoint sleep lw-attacker:latest 300

# 2) 같은 IP로 두 공격을 동시에 (터미널 두 개, 또는 뒤에 & 를 붙여서)
docker run --rm --network container:lw-measure-${LW_EDGE_PREFIX}.151 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 lw-attacker:latest synflood --count 3000
docker run --rm --network container:lw-measure-${LW_EDGE_PREFIX}.151 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 lw-attacker:latest httpflood --path /login --requests 200

# 3) 끝나면 자리 잡기 컨테이너 지우기
docker rm -f lw-measure-${LW_EDGE_PREFIX}.151
```

- `httpflood`의 `--path`는 몰아 보낼 경로(기본 `/`), `--requests`는 요청 수(기본 120, 최대 500)입니다. `synflood --count`는 기본 3000, 최대 5000입니다.
- 5초 측정 스크립트(`scripts/net/measure_detect_to_block.py --scenario s5b`)는 위 1)~3)을 실행마다 새 IP로 자동으로 합니다. 손으로 해 본 IP는 `network_blocks`에 남으므로 스크립트가 알아서 건너뜁니다. 다만 같은 IP를 손으로 다시 쓰면 앞 차단 때문에 재현이 안 되니 실행마다 끝자리를 바꿉니다.

### 7.4 victim 테스트 계정과 `LW_VICTIM_PASSWORD` (S6 `login`용)

S6(의심 로그인 성공)는 공격 상자가 **올바른 비밀번호로** 로그인해야 재현됩니다. 그래서 사람마다 테스트 계정 `victim_<역할>`을 하나씩 만들어 두고, 그 비밀번호를 환경 변수 `LW_VICTIM_PASSWORD`로만 넘깁니다. **정해진 값은 없습니다. 가입할 때 본인이 정한 비밀번호가 곧 이 값입니다.** 계정을 사람마다 나누는 이유는 남의 시험 때문에 내 계정이 잠기거나 경고 메일이 섞이지 않게 하려는 것입니다(팀 계획 01 D5).

**① 계정 만들기 (사람마다 처음 한 번)**

1. 단지를 켠 상태(3장)에서 브라우저로 `http://localhost:8080/signup`을 엽니다.
2. 아래처럼 가입합니다.

   | 칸 | 넣을 것 |
   |---|---|
   | 아이디 | A `victim_a` / B `victim_b` / C `victim_c` |
   | 이메일 | 실제로 받을 필요 없는 가짜 주소(예: `victim_<역할>@example.test`). 이메일은 중복될 수 없으니 사람마다 다르게 |
   | 비밀번호 | 본인이 정하는 8자 이상. 이 문서·채팅·AI·`.env.example`에 적지 않습니다 |

3. `http://localhost:8080/login`에서 그 계정으로 로그인되는지 한 번 확인합니다. 내 브라우저(`.1`)에는 네트워크 기록이 없어 CR-03이 걸리지 않으므로 정상 로그인되는 것이 맞습니다.

- 이메일 인증은 하지 않아도 로그인됩니다.
- DB는 세 명이 같이 쓰는 Supabase라, 한 번 만든 계정은 어느 PC에서든 그대로 쓸 수 있습니다.
- Docker 앱은 메일을 모두 Mailpit(`http://localhost:8025`)으로 보내도록 고정돼 있습니다(`docker-compose.yml`의 app `SMTP_HOST: "mailpit"`). 그래서 S6의 경고 메일도 가짜 주소 그대로 Mailpit에서 확인합니다.
- 실제로 쓰는 계정을 victim으로 쓰지 않습니다. S6가 돌면 그 계정의 기존 세션이 끊기고 경고 메일이 갑니다.

**② 시험 직전에 환경 변수 넣기 (터미널을 열 때마다)**

PowerShell에서 아래처럼 입력하면 값이 명령 기록에 남지 않습니다.

```powershell
$env:LW_VICTIM_PASSWORD = Read-Host "victim 비밀번호"
```

- 넣은 값은 **그 터미널 창에서만** 유효합니다. `docker run ... -e LW_VICTIM_PASSWORD=$env:LW_VICTIM_PASSWORD`나 C3-1 `run_all`을 실행할 같은 창에서 넣습니다.
- 값이 없으면 `login` 명령은 `"ok": false, "error": "no_password"`로 끝나고, C3-1은 S6를 SKIP합니다.
- 시연 대역 PC에서 C3-1을 돌릴 때는 `victim_c`를 쓰므로, 그 계정 주인(C)이 직접 입력하는 것이 가장 간단합니다. 다른 사람이 대신 돌려야 하면 비밀번호는 팀 비밀값 보관소(Infisical)로 넘기고 단체방에 평문으로 보내지 않습니다.

### 7.5 위조 출발지·ICMP 폭주 (S7·S9, guide57)

```bash
# S7 ③ edge 안 주소로 위조(위조 가능 증거 → TTL 차단까지만)
docker run --rm --network lw_edge --ip ${LW_EDGE_PREFIX}.111 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 lw-attacker:latest synflood --spoof-source ${LW_EDGE_PREFIX}.140 --count 3000

# S7 ① 출발지를 바꾸는 폭주(막을 주소 없음 → GLOBAL_SYN_FLOOD 알림만)
docker run --rm --network lw_edge --ip ${LW_EDGE_PREFIX}.111 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 lw-attacker:latest synflood --rand-source

# S9 ICMP 폭주(ICMP_FLOOD 기록 + 정문 커널이 초당 50개 넘는 만큼 버림, 주소 차단 없음)
docker run --rm --network lw_edge --ip ${LW_EDGE_PREFIX}.112 --cap-add NET_RAW \
  -e TARGET_URL=http://${LW_EDGE_PREFIX}.10:8080 lw-attacker:latest icmpflood
```

- **왜 위조 대역을 제한하나:** gateway는 위조된 출발지로 SYN-ACK·ICMP 응답을 돌려보냅니다. 아무 주소나 허용하면 응답이 Docker 호스트를 거쳐 실제 인터넷 주소로 나갑니다. 그래서 `--spoof-source`는 이 PC edge 대역·core 대역·문서용 `192.0.2.0/24`만 받고, 출발지를 바꾸는 폭주도 hping3 `--rand-source`(전 인터넷 주소) 대신 edge `.200~.254`만 돌려 씁니다.
- `--rand-source`는 raw 소켓을 쓰므로 `--cap-add NET_RAW`가 필요합니다.
- 결과 확인: `docker compose logs l4-detector`(`전체 SYN 폭주 의심`), Slack의 "네트워크 경보", 처리 작업대의 네트워크 이벤트(위조 출발지·전체 SYN 폭주·ICMP 플러드), `docker compose exec fw-agent iptables -t raw -L LW_L3 -v -n`의 DROP 카운터.

---

## 8. 막혔을 때

| 증상 | 확인할 것 |
|---|---|
| 단지는 켜지는데 센서 경보가 0건 | `docker compose logs sensor`에서 고른 인터페이스와 `[WARN]` 줄 확인. `…를 감시합니다`는 정상, `…찾지 못해`가 보이면 `.env`의 `LW_EDGE_PREFIX`가 내 대역인지 확인 |
| shipper·fw-agent 로그에 `501 Server Error: NOT IMPLEMENTED` 반복 | app 이미지가 예전(뼈대 단계) 코드로 만들어진 것. app은 코드를 이미지 안에 넣으므로 최신 코드를 받은 뒤에는 꼭 `docker compose up -d --build`로 다시 빌드 (2026-10-22 B PC) |
| 경보는 오는데 생존 신호(`agent_heartbeats`)에 내 PC가 없음, fw-agent 로그에 `heartbeat 실패` | `.env`에 `LW_NODE_NAME`·`NET_EDGE_SUBNET` 줄이 있는지 확인(2장 표). `LW_NODE_NAME`이 비면 생존 신호 창구가 400으로 거절합니다. 예전 `.env`를 쓰면 이 두 줄이 빠져 있을 수 있습니다. 고친 뒤 `docker compose up -d --force-recreate app fw-agent shipper` (2026-10-22 A PC) |
| fw-agent 로그에 `폴링 실패 (1회 연속): … RemoteDisconnected`가 가끔 나오고 바로 회복 | 10/22 이전 main의 gunicorn keep-alive(2초)가 fw-agent 폴링 간격(2초)과 겹친 것. 최신 main을 받아 `docker compose up -d --build app` |
| sensor가 `set: -: invalid option`으로 바로 멈춤 | `netwatch/suricata/entrypoint.sh`가 CRLF로 바뀐 것. 최신 `main`을 받아 다시 꺼내면 `.gitattributes`가 LF로 맞춥니다 |
| shipper·fw-agent 로그에 401·실패 반복 | `.env`의 두 서명 키가 Infisical 값과 같은지, 앱을 다시 띄웠는지(`docker compose up -d`) 확인 |
| `docker compose up`이 "Network Creating"에서 멈춤 | core 대역이 `172.30.0.0/24`인 최신 `main`인지 확인(옛 172.29 대역 충돌) |
| `localhost:8025`가 안 열림 | `docker-compose.mailpit.yml`을 따로 띄워 두지 않았는지 확인(이름·포트 충돌) |
| 모든 로그인이 같은 IP로 기록되거나 바로 잠김 | `docker-compose.yml`의 app에 `TRUST_FORWARDED_FOR: "true"`가 있는 최신 `main`인지 확인 |
| 대역 관련 오류·남의 기록이 내 사건에 섞임 | `.env`의 `LW_EDGE_PREFIX`·`NET_EDGE_SUBNET`이 2장 표의 내 값과 같은지 확인 |
| fw-agent 로그에 `폴링 실패 … 503` 반복 · Slack "차단 목록을 N번 연속 받지 못했습니다" | `.env`의 `NET_EDGE_SUBNET` 형식이 틀린 것(guide57 — 오타로 남의 대역까지 막지 않게 차단 목록 창구가 멈춤). `172.28.13.0/24`처럼 고치고 `docker compose up -d app` |
| Slack "방화벽 규칙이 빠져 있습니다: LW_L3" · fw-agent 로그 `ICMP 속도 제한 규칙을 넣지 못했습니다` | 커널에 `hashlimit` 모듈이 없거나 raw 표를 못 쓰는 환경입니다. L4 차단(`lw_block`)은 그대로 동작하고 ICMP 속도 제한만 빠집니다. `docker compose exec fw-agent iptables -t raw -S`로 확인 |
| Slack "방화벽 규칙이 빠져 있습니다: INPUT" | 누가 `iptables -F` 등으로 규칙을 지운 것. fw-agent가 60초 안에 되살립니다. 계속 오면 fw-agent 로그의 `규칙 되살리기 실패`를 확인 |
| Slack "센서 기록이 2분 넘게 늘지 않습니다: l4.json(Scapy l4-detector)" | l4-detector가 멈춘 것(guide57부터 60초마다 생존 줄을 씀). `docker compose logs l4-detector` 확인 후 `docker compose up -d --force-recreate l4-detector` |
| Slack "L4 차단 적용 실패" | fw-agent가 ipset에 넣지 못한 것. 앱이 10초 간격으로 3번 다시 시도하고, 그래도 안 되면 "포기" 알림이 한 번 더 옵니다. fw-agent 로그의 `add 차단 실패` 이유를 확인 |
| 공격 상자 `synflood --spoof-source`가 `[FAIL] --spoof-source는 이 PC edge 대역…` | 허용 대역 밖 주소입니다(7.5). 이 PC edge 대역·`172.30.0.0/24`·`192.0.2.0/24`만 씁니다 |
| 공격 상자 `login`이 `"error":"ValueError"`, `"status":null`로 끝남 · `brute`를 해도 gateway 로그에 `POST /login`이 없음 | 옛 공격 상자 이미지입니다. 앱의 `/login`은 Next.js 화면이라 HTML에 CSRF 입력칸이 없고, 10/26 이후 공격 상자는 `X-Requested-With: login-watchdog-spa` 헤더로 토큰을 다시 받습니다(`81be35a`). 최신 `main`을 받아 `docker compose build attacker-1` (2026-10-26 시연 PC) |
| 앱 로그에 `SMTP AUTH extension not supported by server` · S6가 `notify_owner_email 단계가 FAILED` | `.env`의 배포용 Gmail 계정 때문에 앱이 Mailpit에 로그인을 시도한 것입니다. app에 `SMTP_USER: ""`·`SMTP_PASSWORD: ""`가 있는 최신 `docker-compose.yml`인지 확인하고 `docker compose up -d app` (`1f2bb72`, 2026-10-26 시연 PC). `.env`는 고치지 않습니다 |
| S6가 `notify_owner_email 단계 기록 없음`으로 FAIL · 같은 IP가 다음 회차 S4에 다시 쓰임 | victim 비밀번호가 틀린 것입니다(CR-03은 로그인이 **성공**해야 판단). Supabase `login_attempts`에서 그 IP의 `success`가 `false`인지 봅니다. 한/영 키·앞뒤 공백을 확인하고 같은 창에서 7.4 ②를 다시 합니다. 틀린 채로 계속 돌리면 victim 계정이 잠길 수 있습니다(실패 8회 초과) |
| S6 비고가 `경고 메일은 받는 주소 쿨다운으로 생략(SKIPPED, 정상)` | **정상입니다.** 같은 victim 주소로는 1시간에 경고 메일 1통만 보냅니다 |
| 시나리오 점검이 `점검용 IP(…)를 모두 썼음 — SKIP` | 한 번 쓴 IP는 다시 쓰지 않습니다. 점검 범위는 `.111~.139`, `.11~.99`입니다(`cb58cfc`). 다 쓰면 공용 DB를 직접 지우지 말고 통합 담당자에게 알립니다 |
| PowerShell에서 `scenario-results.md`·`measurements.md`의 한글이 깨져 보임 | 파일은 정상입니다. `Get-Content <파일> -Encoding UTF8`로 봅니다 |

---

## 9. 시나리오 자동 점검 (C3-1)

시연 시나리오(S4·S5·S5b·S6·S7·S8·S9)를 실행한 뒤 기대 결과가 DB·응답·메일에 실제로 생겼는지 확인해 PASS/FAIL을 냅니다. 스크립트는 내 PC에서 돌고(앱과 같은 `.env`로 Supabase를 **읽기만** 함), 공격은 7.3의 일회용 공격 상자로 보냅니다.

**준비** — guide57 SQL을 공용 DB에 실행했는지 확인하고(`docs/migrations/guide57_track_d_reliability.sql`), 3장으로 단지를 켜고(`docker compose up -d --build`), 공격 상자 이미지를 최신으로 만들고(`docker compose build attacker-1`), S6까지 보려면 같은 창에서 7.4 ②로 `LW_VICTIM_PASSWORD`를 넣습니다.

```powershell
# 결과 표를 비우고 처음부터 (선택 — 지난 기록을 남기려면 건너뜀)
git restore docs/track-d/scenario-results.md

# 전체 시나리오 3회 연속
.\venv\Scripts\python.exe -m scripts.net.run_all --repeat 3

# 결과 보기 (한글이 깨지지 않게 UTF8 지정)
Get-Content docs\track-d\scenario-results.md -Tail 20 -Encoding UTF8
```

| 시나리오 | PASS 조건 |
|---|---|
| S4 킬체인 | 사건에 `CR-01`, IP 영구 잠금(관리자만 해제), 영구 L4 차단(`CONNECTED`)이 **적용됨**(`APPLIED`·`applied_at`), `probe`로 대상 IP는 막히고 다른 새 IP는 연결됨. `--with-release`면 영구 해제 → `REMOVED` → 대상 IP 재접속까지 |
| S5 SYN 폭주 | TTL L4 차단, 앱 잠금 없음, 미해결 `NET_BLOCKED` |
| S5b 다계층 폭주 | 사건에 `CR-02`, TTL L4 차단 (7.3의 자리 잡기 방식으로 같은 IP 동시 공격) |
| S6 의심 로그인 성공 | `login`이 `success:false`, 플레이북 `SUSPICIOUS_SUCCESS_LOGIN` 실행, 경고 메일 1통(1시간 안 재실행은 SKIPPED가 정상) |
| S7 위조 출발지 | ① 돌려 쓴 `.200~.254` 차단 없음·`GLOBAL_SYN_FLOOD` 기록, ② core 주소(`172.30.0.250`) 차단·보안 이벤트 없음, ③ `.140`은 `SPOOFABLE` TTL 차단만·앱 잠금 없음, ④ `192.0.2.50` 차단 없음·`SPOOFED_SRC` 기록, 공격 상자에서 gateway 연결 됨 |
| S8 XFF 위조 | 위조 헤더(`1.2.3.4`)가 아니라 실제 출발지가 기록됨 |
| S9 ICMP 폭주 | 그 IP의 `ICMP_FLOOD`(L3)·`NET_ICMP_FLOOD` 기록, 차단 행 없음, 정문 `LW_L3` DROP 누적 카운터 증가, TCP 연결은 됨 |

- 실행마다 **새 출발지 IP**를 씁니다(`.111~.139` 다음 `.11~.99`). 차단·사건이 한 번이라도 남은 IP는 건너뜁니다. S7·S9의 공격 상자 IP는 DB에 흔적을 남기지 않으므로 같은 실행 안에서는 따로 기억해 다시 쓰지 않습니다.
- **PC 시계와 DB 시계가 다를 수 있습니다.** 10/29 시연 PC는 PC(·WSL 센서) 시계가 Supabase보다 약 7초 앞서 있었습니다(`network_events.observed_at - received_at`). 보안 이벤트 시각(`detected_at`)은 DB 시계라, S9는 경보가 DB에 도착한 시각(`received_at`)을 기준으로 찾고, S7의 "있으면 안 되는" 확인은 60초 여유를 둡니다. 시계 차이 확인: `select extract(epoch from (observed_at - received_at)) from network_events order by received_at desc limit 5;`
- S6만 다시 볼 때는 `.\venv\Scripts\python.exe -m scripts.net.check_s6`(IP를 하나만 씀). S7·S9도 같은 방식(`check_s7`·`check_s9`).
- 2026-10-26 시연 대역 PC 결과: **S4·S5·S5b·S6·S8 3회 연속 PASS, S7 SKIP** (`baad60d`, [docs/track-d/scenario-results.md](../docs/track-d/scenario-results.md)).
- 2026-10-26 강사 피드백 반영 후(S4 판정 강화): **S4·S5·S5b·S8 3회 연속 PASS**, S6은 `LW_VICTIM_PASSWORD` 없이 돌려 SKIP, `check_s4 --with-release` PASS. fw-agent를 멈추고 돌리면 S4가 FAIL(`PENDING_APPLY`)로 바뀌는 것도 확인했습니다([guide56](../docs/beginner-guide/guide56_feedback_hardening.md)).
- S4 해제 후 재접속까지 볼 때: `.\venv\Scripts\python.exe -m scripts.net.run_all --with-release`(또는 `-m scripts.net.check_s4 --with-release`). 해제는 관리자 "영구 해제"와 같은 경로라 DB를 바꿉니다.
- `lw.py`·nginx 설정을 바꾼 뒤에는 공격 상자 이미지를 다시 만들고(`docker compose build attacker-1`), gateway를 다시 띄울 때는 `docker compose up -d --force-recreate gateway sensor l4-detector fw-agent`로 **네 개를 함께** 띄웁니다. gateway만 재시작하면 그 네트워크를 함께 쓰는 셋이 앱 주소를 찾지 못합니다.
- 시나리오를 여러 번 돌리면 L4 차단·IP 영구 잠금이 쌓입니다. 처리 작업대의 두 카드는 10줄씩 쪽으로 나뉩니다.
