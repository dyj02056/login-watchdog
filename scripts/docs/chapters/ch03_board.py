# 3단원 — 게시판 · 댓글 흐름도 명세

from scripts.docs.dsl import Scenario, call

SLUG = "03-board"
TITLE = "3. 게시판 · 댓글"
SUBTITLE = "글쓰기·수정·삭제·댓글·새 댓글 알림이 어떤 파일의 어떤 함수를 거치는지 보는 코드 흐름도"

FILE_ROLES = {
    "routes/board.py": "게시판(/board …) 화면과 글·댓글 처리의 입구 파일. 모든 화면이 회원 문지기로 보호된다.",
    "db/board.py": "게시글·댓글을 저장·조회하고, 글쓰기 도배 방지용 시도 기록을 다루는 저장소 파일.",
    "security/detector.py": "'수상한가?'를 판정만 하는 판사 역할 파일. (5·6단원)",
    "helpers/request_utils.py": "요청에서 IP를 알아내고 봇 함정(허니팟)을 확인하는 공용 도구.",
    "public/js/board.js": "게시글 상세 화면의 '새 댓글' 알림 배너와 삭제 확인창을 담당하는 브라우저 쪽 코드.",
    "public/js/polling.js": "탭이 보일 때만 일정 주기로 확인을 반복하는 공용 폴링 부품. (27단원)",
}

LIMITS = ("routes/board.py", "POST_TITLE_MAX_LENGTH =", "COMMENT_BODY_MAX_LENGTH =")
BOARD_NEW = "routes/board.py:board_new_submit"
BOARD_EDIT = "routes/board.py:board_edit_submit"
BOARD_CMT = "routes/board.py:board_comment_submit"
BOT = call("helpers.is_bot_submission", "봇 여부 확인", "숨은 입력칸(website)에 값이 있는지 봅니다.")
BOT_NOTI = call("soar.notify_bot_detected", "봇 감지 알림", "알림과 기록만 남깁니다.", later="10단원")

# ---------------------------------------------------------------- 글쓰기
s1 = Scenario("write", "글쓰기",
              "글을 쓰는 것도 '회원가입'처럼 검문이 먼저입니다. 봇인지, 너무 자주 쓰는지를 보고, 시도 자체를 기록한 뒤에야 내용을 검사해 저장합니다.")
s1.screen("글쓰기 폼 제출 (POST /board/new)", "로그인한 회원이 제목·내용을 적고 '등록'을 누릅니다. 문지기(@member_login_required)를 통과해야 들어옵니다.",
          fn=BOARD_NEW, hl=('@board_bp.route("/board/new", methods=["POST"])', "@member_login_required"))
s1.step("① 사람이 맞나? (허니팟)", "숨은 입력칸이 채워져 있으면 자동 프로그램으로 보고 시도 기록도 남기지 않고 거부합니다.",
        fn=BOARD_NEW, hl=("if is_bot_submission():", "post=None)"), reject="일시적인 오류가 발생했습니다.", calls=[BOT, BOT_NOTI])
s1.step("② 너무 자주 쓰나? (도배 방지)", "같은 IP가 1분 안에 5번 이상 글쓰기를 시도하면 막고, 거부 사실을 기록합니다.",
        fn=BOARD_NEW, hl=("if detector.is_post_rate_limited(ip):", "post=None)"), reject="너무 많은 게시글 작성 시도가 감지되었습니다.",
        calls=[call("detector.is_post_rate_limited", "글쓰기 도배 판정", "최근 시도 횟수가 기준치 이상인지 True/False.",
                    then=[call("db.count_recent_post_attempts", "최근 글쓰기 시도 세기", "post_attempts 표에서 이 IP의 최근 60초 시도 수를 셉니다.")]),
               call("soar.record_rejection", "거부 사실 기록", "HIGH 위험등급 이벤트로 남깁니다.", later="6단원")])
s1.step("③ 이번 시도 기록", "성공이든 실패든 '글쓰기를 시도했다'는 사실을 항상 한 줄 남깁니다. ②의 횟수가 여기서 쌓입니다.",
        fn=BOARD_NEW, hl="db.log_post_attempt(ip)",
        calls=[call("db.log_post_attempt", "글쓰기 시도 한 줄 저장", "post_attempts 표에 IP를 추가합니다.")])
s1.step("④ 제목·내용 검사", "빈칸이 없는지, 제목 100자·내용 5000자를 넘지 않는지 확인합니다. 내용 모양은 제한하지 않고 길이만 봅니다.",
        fn=BOARD_NEW, hl=('title = request.form.get("title"', "입력할 수 있습니다."), reject="제목과 내용을 모두 입력해주세요. / 길이 초과 안내",
        calls=[call(snippet=LIMITS, title="길이 제한값", plain="제목 100자, 내용 5000자, 댓글 1000자.", hl=("POST_TITLE_MAX_LENGTH =", "COMMENT_BODY_MAX_LENGTH ="), label="길이 제한값")])
s1.step("⑤ 저장하고 상세 화면으로", "글을 저장하고 방금 쓴 글의 상세 화면으로 '다시 방문(redirect)'시킵니다.",
        fn=BOARD_NEW, hl=("post = db.create_post", 'post_id=post["id"]))'),
        calls=[call("db.create_post", "게시글 저장", "posts 표에 새 글을 추가하고 저장된 행을 돌려줍니다.")])

# ---------------------------------------------------------------- 수정 · 삭제
s2 = Scenario("edit", "수정 · 삭제 (본인 글만)",
              "수정·삭제 버튼은 본인 글에만 보이지만, 서버도 제출 때 소유권을 다시 확인합니다. 개발자 도구로 요청을 직접 만들어 보내도 막기 위해서입니다.")
s2.screen("수정 폼 제출 (POST /board/<id>/edit)", "수정 화면에서 '저장'을 누릅니다.",
          fn=BOARD_EDIT, hl=('@board_bp.route("/board/<int:post_id>/edit", methods=["POST"])', "@member_login_required"))
s2.step("① 글 찾기 + 본인 글인지 확인", "글이 없으면 목록으로, 내가 쓴 글이 아니면 상세 화면으로 돌려보냅니다.",
        fn=BOARD_EDIT, hl=("post = db.get_post(post_id)", 'url_for("board.board_detail", post_id=post_id))'),
        reject="본인이 작성한 글만 수정할 수 있습니다.",
        calls=[call("db.get_post", "글 한 건 읽기", "posts 표에서 번호로 글을 찾습니다."),
               call("routes/board.py:_is_post_owner", "작성자 확인", "글의 작성자 아이디가 지금 로그인한 아이디와 같은지 비교합니다.")])
s2.step("② 봇 · 도배 검사 (글쓰기와 횟수 공유)", "수정도 도배 대상이 될 수 있어서 새 글 작성과 같은 시도 기록(post_attempts)을 함께 씁니다.",
        fn=BOARD_EDIT, hl=("form_action = url_for", "db.log_post_attempt(ip)"),
        reject="일시적인 오류 / 너무 많은 게시글 작성 시도",
        calls=[call("detector.is_post_rate_limited", "글쓰기 도배 판정", "새 글 작성과 같은 기준으로 판정합니다."),
               call("db.log_post_attempt", "시도 기록", "post_attempts 표에 한 줄 추가합니다.")])
s2.step("③ 입력 검사 후 수정 저장", "길이를 확인하고 제목·내용을 덮어씁니다. 끝나면 상세 화면으로 이동합니다.",
        fn=BOARD_EDIT, hl=('title = request.form.get("title"', 'return redirect(url_for("board.board_detail", post_id=post_id))'),
        calls=[call("db.update_post", "글 수정 저장", "posts 표의 제목·내용을 고칩니다.")])
s2.step("④ 삭제 (POST /board/<id>/delete)", "본인 글만 삭제됩니다. 글이 지워지면 딸린 댓글도 DB 규칙(on delete cascade)에 따라 함께 지워집니다.",
        fn="routes/board.py:board_delete", hl=("if not _is_post_owner(post):", "db.delete_post(post_id)"),
        reject="본인이 작성한 글만 삭제할 수 있습니다.",
        calls=[call("db.delete_post", "글 삭제", "posts 표에서 글을 지웁니다. 댓글은 자동으로 함께 지워집니다.")])

# ---------------------------------------------------------------- 댓글
s3 = Scenario("comment", "댓글 작성 · 삭제",
              "댓글도 글쓰기와 같은 순서(봇 확인 → 도배 판정 → 시도 기록 → 입력 검사 → 저장)를 따릅니다. 다만 정상적인 대화에서는 댓글이 더 자주 달려서 기준치가 더 넉넉합니다(10회).")
s3.screen("댓글 폼 제출 (POST /board/<id>/comments)", "상세 화면 아래 입력칸에서 '댓글 등록'을 누릅니다.",
          fn=BOARD_CMT, hl=('@board_bp.route("/board/<int:post_id>/comments", methods=["POST"])', "@member_login_required"))
s3.step("① 글이 있나?", "삭제된 글에는 댓글을 달 수 없습니다.",
        fn=BOARD_CMT, hl=("post = db.get_post(post_id)", 'board.board_list"))'), reject="존재하지 않는 게시글입니다.",
        calls=[call("db.get_post", "글 한 건 읽기", "posts 표에서 번호로 글을 찾습니다.")])
s3.step("② 사람이 맞나? (허니팟)", "걸리면 안내 문구 없이 상세 화면으로 돌려보냅니다.",
        fn=BOARD_CMT, hl=("if is_bot_submission():", 'board.board_detail", post_id=post_id))'), calls=[BOT, BOT_NOTI])
s3.step("③ 너무 자주 다나? + 시도 기록", "1분 안에 10번 이상이면 막고, 아니면 시도를 기록합니다.",
        fn=BOARD_CMT, hl=("if detector.is_comment_rate_limited(ip):", "db.log_comment_attempt(ip)"), reject="너무 많은 댓글 작성 시도가 감지되었습니다.",
        calls=[call("detector.is_comment_rate_limited", "댓글 도배 판정", "최근 댓글 시도 횟수가 기준치 이상인지 판정.",
                    then=[call("db.count_recent_comment_attempts", "최근 댓글 시도 세기", "comment_attempts 표에서 최근 60초 시도 수를 셉니다.")]),
               call("db.log_comment_attempt", "댓글 시도 한 줄 저장", "comment_attempts 표에 IP를 추가합니다."),
               call("soar.record_rejection", "거부 사실 기록", "HIGH 위험등급 이벤트로 남깁니다.", later="6단원")])
s3.step("④ 길이 검사 후 저장", "빈 댓글과 1000자 초과를 막고 저장합니다. 끝나면 상세 화면으로 돌아갑니다(다시 방문).",
        fn=BOARD_CMT, hl=('body = request.form.get("body"', "db.create_comment(post_id"), reject="댓글 내용을 입력해주세요. / 길이 초과",
        calls=[call("db.create_comment", "댓글 저장", "comments 표에 댓글을 추가합니다.")])
s3.step("⑤ 댓글 삭제 (본인 댓글만)", "댓글 작성자 아이디가 지금 로그인한 아이디와 같을 때만 지웁니다.",
        fn="routes/board.py:board_comment_delete", hl=("comment = db.get_comment", "db.delete_comment(comment_id)"),
        reject="본인이 작성한 댓글만 삭제할 수 있습니다.",
        calls=[call("db.get_comment", "댓글 한 건 읽기", "작성자를 확인하려고 댓글 행을 가져옵니다."),
               call("db.delete_comment", "댓글 삭제", "comments 표에서 지웁니다.")])

# ---------------------------------------------------------------- 새 댓글 알림
s4 = Scenario("poll", "새 댓글 알림 배너",
              "글을 보고 있는 동안 다른 사람이 댓글을 달면 '새로운 댓글이 추가되었습니다' 배너가 뜹니다. 5초마다 '개수와 최신 시각'만 가볍게 물어보고, 달라졌을 때만 배너를 띄웁니다.")
s4.screen("브라우저가 5초마다 확인 (board.js)", "화면이 처음 그려진 시점의 댓글 개수·최신 시각을 기준값으로 기억해 두고, 폴링 결과와 비교해 달라졌을 때만 배너를 보여줍니다.",
          snippet=("public/js/board.js", "async function checkForNewComments", "re:^}"), label="board.js 폴링 함수",
          hl=("const response = await fetch", "hidden = false"),
          calls=[call(None, title="공용 폴링 부품 (탭이 보일 때만)", plain="일정 주기로 함수를 호출하되 탭이 안 보이면 쉬고, 다시 보이면 즉시 한 번 확인합니다.",
                      snippet=("public/js/polling.js", "export function startPolling", "re:^}"), label="startPolling", later="27단원")])
s4.step("① 가벼운 확인 API (GET /api/board/<id>/comments/latest)", "댓글 전체가 아니라 '개수 + 최신 시각' 두 값만 JSON으로 돌려줍니다. 표 전체를 다시 그리지 않아 트래픽이 가볍습니다.",
        fn="routes/board.py:api_board_comments_latest", hl='return jsonify(db.get_latest_comment_info(post_id))',
        calls=[call("db.get_latest_comment_info", "댓글 개수·최신 시각", "comments 표에서 개수와 가장 최근 댓글 시각만 가져옵니다.")])

SCENARIOS = [s1.build(), s2.build(), s3.build(), s4.build()]
