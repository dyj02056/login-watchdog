# scripts/docs — 02-layer-order 흐름도 생성기

`docs/feature-reference/02-layer-order/NN-xxx.html`(클릭형 코드 흐름도)을 만드는 도구입니다.
코드는 손으로 붙여넣지 않고, 실제 소스 파일에서 **함수 이름으로** 자동 추출합니다(줄 번호가 밀려도 안 어긋남).

```bash
python scripts/docs/build_flowcharts.py 1        # 1단원만
python scripts/docs/build_flowcharts.py 5 6 7    # 여러 단원
python scripts/docs/build_flowcharts.py --all    # 전부
```

| 파일 | 역할 |
|---|---|
| `build_flowcharts.py` | 명세를 읽어 소스에서 코드를 뽑고 HTML 을 만든다. `db.xxx` 같은 별칭은 `db/__init__.py` 의 재내보내기 표를 읽어 실제 파일로 풀어준다 |
| `dsl.py` | 단계(step) + 호출하는 함수(call)만 적으면 좌표·화살표를 자동으로 만드는 도우미 |
| `chapters/chNN_*.py` | 단원별 명세. 강조할 줄은 줄 번호가 아니라 **문구(anchor)** 로 지정한다. 문구를 못 찾으면 에러로 멈춘다 |
| `templates/flowchart.html` | 화면 템플릿(CSS·클릭 동작·코드 강조) |

코드가 바뀐 뒤에는 `--all` 로 다시 만들면 최신 코드가 반영됩니다. 설명 문서(`NN-xxx.md`)는 손으로 쓰는 문서입니다.


## 목차 페이지(index.html)와 웹 배포

- `python3 -I scripts/docs/build_index.py` — 각 단원 명세의 `TITLE`/`SUBTITLE`을 읽어 `docs/feature-reference/02-layer-order/index.html`(목차)을 만든다. 단원 이름을 바꿨다면 흐름도 생성 뒤 이것도 다시 실행한다.
- `.github/workflows/pages.yml` — `main`에 `02-layer-order/*.html`이 바뀌어 올라오면 `.html`만 GitHub Pages로 배포한다(설명 `.md`는 올리지 않고, 흐름도의 "설명 문서 보기" 링크만 GitHub 저장소 주소로 바꿔 연결). 주소: https://dyj02056.github.io/login-watchdog/
- 최초 1회: 저장소 Settings → Pages → Source를 "GitHub Actions"로 설정해야 한다.
