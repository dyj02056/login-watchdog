# S4 시연 캡처 안내 (정찰 → 침투, CR-01)

이 폴더에는 **최종 영상이 아니라** HyperFrames 애니메이션을 실제와 똑같이 그리기 위한
참고 자료(터미널 텍스트 + 대시보드 스크린샷)를 넣습니다. 동영상은 필요 없고 정지 캡처면 됩니다.

> **방식: 일회용 새 IP** — 차단·사건이 한 번이라도 남은 IP는 재현이 어긋납니다.
> 그래서 테이크마다 **쓰지 않은 새 IP**로 일회용 컨테이너를 띄웁니다. (netwatch/README.md 7.3)
>
> **중요: webscan은 쓰지 않습니다.** webscan은 404를 11번 보내다 11번째에서 스스로 차단을 유발하고,
> 로그인 공격 장면도 안 보입니다. `scan → brute`가 슬라이드 순서(포트 스캔 → 로그인 공격 → 차단)에
> 맞고 실제 로그인 시도가 화면에 보입니다.

## 0. 촬영 전 (한 번만)
```bash
docker compose up -d --build
docker compose build attacker-1   # 일회용 컨테이너가 쓰는 lw-attacker:latest 이미지 최신화
```
- 새 IP 방식이라 고정 상자를 따로 해제할 필요 없습니다.
- **재촬영할 때는 아래 IP 끝자리(.180/.181)를 안 쓴 숫자로 바꾸세요** (측정용 범위 `.150~.199`).

## 1. 터미널에 입력할 명령 (왼쪽 화면) — 끊지 말고 연속으로
공격 IP = `172.28.0.180`, 대조 IP = `172.28.0.181`.
**scan → brute → probe 를 1~2분 안에 이어서** 치세요(CR-01 상관창 15분).

```powershell
# 컷1 — 포트 스캔
docker run --rm --network lw_edge --ip 172.28.0.180 --cap-add NET_RAW -e TARGET_URL=http://172.28.0.10:8080 lw-attacker:latest scan

# 컷2 — 로그인 공격 (로그인 5번 시도까지 보이고, 6번째는 차단돼 timeout — 정상)
docker run --rm --network lw_edge --ip 172.28.0.180 --cap-add NET_RAW -e TARGET_URL=http://172.28.0.10:8080 lw-attacker:latest brute --attempts 6

# 컷3 — (명령 없음) 관제 "연관 사건" 패널에 .180 행이 뜰 때까지 기다렸다 캡처

# 컷4 — 영구 차단 확인 (막힘)
docker run --rm --network lw_edge --ip 172.28.0.180 --cap-add NET_RAW -e TARGET_URL=http://172.28.0.10:8080 lw-attacker:latest probe

# 컷5 — 대조 IP 정상 (열림)
docker run --rm --network lw_edge --ip 172.28.0.181 --cap-add NET_RAW -e TARGET_URL=http://172.28.0.10:8080 lw-attacker:latest probe
```

> brute 마지막에 `ReadTimeout`/`[FAIL]`이 떠도 **정상**입니다. 로그인 5번 실패에서 차단이 발동하고
> 6번째 요청이 그 차단에 막힌 것 — 차단이 작동한 증거입니다.

## 2. 이 폴더에 저장할 파일 (컷 번호를 이름에 그대로)
| 컷 | 터미널 텍스트 | 대시보드 스크린샷 | 스크린샷에 보여야 할 것 |
|---|---|---|---|
| 1 | `s4-cut1-scan.txt` | `s4-cut1-dashboard.png` | PORT_SCAN 경보 |
| 2 | `s4-cut2-brute.txt` | `s4-cut2-dashboard.png` | 로그인 실패 시도(터미널에 POST 5회 + 6번째 timeout) / 로그인 잠금 |
| 3 | — | `s4-cut3-dashboard.png` | **"연관 사건 (SIEM 상관분석)" 패널**의 `.180` 행 (관련 유형 2가지+: 포트 스캔 + 로그인, 등급 높음, 진행 중) — 패널 제목까지 함께 |
| 4 | `s4-cut4-probe.txt` | `s4-cut4-blocklist.png` | **"L4 차단 목록" 패널**의 `.180` 행: 증거 "연결 완성·영구 가능", 상태 "차단 중", 남은 시간 "영구", 적용 시각 있음. probe 출력은 `reachable:false` |
| 5 | `s4-cut5-probe.txt` | `s4-cut5-dashboard.png` | `.181`은 차단 목록에 **없음**. probe 출력은 `reachable:true` |

- 터미널 텍스트: JSON 한 줄(또는 로그인 시도 줄)을 그대로 복사해 `.txt`로. probe는 `reachable` 값(컷4=false, 컷5=true)이 핵심.
- 스크린샷: `Win+Shift+S` → 영역 선택. 대시보드는 같은 창 크기로 찍으면 틀을 맞추기 쉽습니다.
- 컷4의 "L4 차단 목록"과 컷3의 "연관 사건"은 **다른 패널**이니 각각 제목이 보이게 찍어 주세요.
- 일부 못 찍어도 됩니다 — 가진 것만 주시면 나머지는 README·계약서 값으로 채웁니다.
