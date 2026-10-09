# routes/ — app.py에서 분리된 라우트(화면 주소) 묶음. 각 파일이(관리자 화면은 하위 패키지
# routes/admin/ 전체가) Flask Blueprint 하나씩을 정의하고, app.py가 이 패키지에서 그
# Blueprint들을 가져와 등록한다.
# 자세한 배경은 docs/refactor/2026-09-15-file-split.md, docs/refactor/2026-10-09-module-plan.md 참고.
