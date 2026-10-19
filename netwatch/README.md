# netwatch — Track D 로컬 Docker 단지 실행 안내

> Track D(네트워크 계층 탐지·차단)를 **내 PC의 Docker 안에서** 켜고 끄는 방법을 위에서 아래로 적은 문서입니다.
> 처음 보는 사람이 1장부터 순서대로 따라 하면 `http://localhost:8080/login`이 열리도록 쓰는 것이 목표입니다.
> 함수 이름·주소·데이터 모양의 기준은 [`docs/track-d/contracts.md`](../docs/track-d/contracts.md)(이하 계약서)입니다. 이 문서와 다르면 계약서가 맞습니다.
>
> - 이 문서는 통합 담당자가 통합일마다 머지된 부분을 절 단위로 더해 갑니다. 지금은 **① 10/21 절(단지 켜기·주소표·A0-2 확인 결과)** 까지입니다.
> - 명령의 정확성은 A(편승훈)가 확인합니다. 확인 전인 절은 제목 옆에 **(A 확인 전)** 을 붙였습니다.
> - 키·비밀번호·`.env`의 실제 값은 이 문서에 적지 않습니다. 변수 **이름**만 적습니다.

---

## 1. 준비물 (A 확인 전)

| 준비물 | 확인 방법 | 비고 |
|---|---|---|
| Docker Desktop (WSL2 백엔드) | Docker Desktop을 켠 뒤 터미널에서 `docker compose version`이 버전을 출력 | Windows는 WSL2 백엔드를 씁니다. 10/19 통합 담당자 PC에서 Docker Desktop 4.91(WSL2)로 확인 |
| 저장소 최신 `main` | `git switch <내 브랜치>` → `git fetch origin` → `git merge origin/main` | 팀 계획 01의 2장 ① 순서 |
| 비밀키 2개 | 팀 Infisical에서 `NET_INGEST_SECRET`, `NET_AGENT_SECRET` 값을 확인 | 메신저·AI 대화에 붙여 넣지 않습니다 |

모든 명령은 저장소 루트(`login-watchdog` 폴더)에서 실행합니다.

---

## 2. `.env` 준비 (A 확인 전)

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

4. `SENSOR_IFACE`는 `.env.example` 값 `eth1`을 그대로 둡니다(아래 5장 A0-2 결과 참고).
5. `TRUSTED_PROXY_IPS`는 비워 둬도 됩니다. Docker에서는 `docker-compose.yml`이 앱에 `172.30.0.10`을 직접 넣습니다.

> **Vercel에는 Track D 값을 넣지 않습니다.** 비어 있으면 Track D 기능이 꺼진 채로 기존 앱이 그대로 동작합니다.

---

## 3. 켜기·끄기·상태·로그 (A 확인 전)

| 하고 싶은 일 | 명령 |
|---|---|
| 켜기 (처음 또는 코드가 바뀐 뒤) | `docker compose up -d --build` |
| 켜기 (이미 빌드한 뒤) | `docker compose up -d` |
| 상태 보기 | `docker compose ps` |
| 앱 로그 보기 | `docker compose logs -f app` |
| 정문(nginx) 로그 보기 | `docker compose logs -f gateway` |
| 끄기 (컨테이너·네트워크 정리) | `docker compose down` |

- 켠 뒤 브라우저에서 `http://localhost:8080/login`이 열리면 성공입니다(M0 완료 기준).
- `docker compose ps`에서 기본으로 켜지는 서비스는 `gateway`, `app`, `mailpit`, `sensor`, `l4-detector`, `shipper`, `fw-agent`입니다. 공격 상자 `attacker-1~3`은 `attack` 프로필이라 기본으로 켜지지 않습니다(사용법은 이후 절에서 추가).
- `sensor`는 A1-1(Suricata) 전까지 아무 일도 하지 않는 대기용 컨테이너입니다.
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

**네트워크 3개**

| 이름 | Docker 네트워크 이름 | 대역 | 붙어 있는 것 | 역할 |
|---|---|---|---|---|
| edge | `lw_edge` | `${LW_EDGE_PREFIX}.0/24` | gateway, attacker | 바깥(공격자) 쪽. 사람마다 대역이 다릅니다 |
| core | `login-watchdog-core` | `172.30.0.0/24` | gateway, app, mailpit, shipper | 안쪽. `internal`이라 인터넷으로 나가지 못합니다 |
| egress | `login-watchdog-egress` | Docker 자동 | app, mailpit | 앱이 Supabase·Slack으로 나가는 길, Mailpit 화면 공개용 |

> **core가 172.29가 아니라 172.30인 이유:** Docker Desktop(WSL2)이 VM 내부 통신에 `172.29.0.0/24`를 써서, 겹치면 "Network Creating"에서 멈추고 엔진 연결이 끊겼습니다. 10/19에 `172.30.0.0/24`로 옮겼고 계약서 K2도 같이 고쳤습니다.

---

## 5. A0-2 세 PC 확인 결과

> A가 세 PC에서 직접 확인하고 PR 메모로 넘긴 값을 옮기는 표입니다. 10/21 기준으로 확인된 값만 채웠고, 나머지는 **(A 확인 전)** 입니다.

| 확인 항목 | 결과 | 근거 |
|---|---|---|
| A PC에서 `docker compose up` 후 `/login` 접속 | (A 확인 전) | — |
| B PC에서 `docker compose up` 후 `/login` 접속 | (A 확인 전) | — |
| C PC에서 `docker compose up` 후 `/login` 접속 | (A 확인 전) | — |
| 감시 인터페이스 이름 `SENSOR_IFACE` | `eth1` — gateway 안에서 `eth0`=core(172.30), `eth1`=edge(공격이 들어오는 쪽) | 2026-10-19 통합 담당자 PC에서 `ip -4 -o addr`로 확인(계약서 K1). 세 PC 모두 같은지는 (A 확인 전) |
| core 대역 충돌 | `172.29.0.0/24`는 Docker Desktop(WSL2) 내부 대역과 충돌 → `172.30.0.0/24` 사용 | 2026-10-19 통합 담당자 PC(Docker Desktop 4.91)에서 확인 |
| 출발지 위조 패킷이 gateway까지 그대로 도착하는지 (시나리오 S7 포함 여부) | (A 확인 전) | — |
| Suricata 이미지 태그 | (A 확인 전) — A1-1에서 정함. 지금 `sensor`는 `alpine:3.20` 대기용 | — |

> `SENSOR_IFACE`가 `eth0`이면 core 트래픽만 보게 되고, L4 측정기는 core 대역을 빼고 세므로 L4 탐지가 0건이 됩니다. 값이 다르게 나오는 PC가 있으면 위 표에 적고 그 PC의 `.env`만 바꿉니다.

---

## 6. 막혔을 때 (A 확인 전)

| 증상 | 확인할 것 |
|---|---|
| `docker compose up`이 "Network Creating"에서 멈춤 | core 대역이 `172.30.0.0/24`인 최신 `main`인지 확인(옛 172.29 대역 충돌) |
| `localhost:8025`가 안 열림 | `docker-compose.mailpit.yml`을 따로 띄워 두지 않았는지 확인(이름·포트 충돌) |
| 모든 로그인이 같은 IP로 기록되거나 바로 잠김 | `docker-compose.yml`의 app에 `TRUST_FORWARDED_FOR: "true"`가 있는 최신 `main`인지 확인 |
| 대역 관련 오류·남의 기록이 내 사건에 섞임 | `.env`의 `LW_EDGE_PREFIX`·`NET_EDGE_SUBNET`이 2장 표의 내 값과 같은지 확인 |
