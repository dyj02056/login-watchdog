"use client";

// 기록·관리 묶음 — 로그인 시도, 관리자 로그인 기록, 회원, 게시글, 댓글, 관리자 계정.
import { useState } from "react";
import { formatDateTime, formatShortDateTime } from "@/lib/format";
import { Pill } from "../Badge";
import { DataTable } from "../DataTable";
import { useFeedback } from "../Feedback";
import { Panel } from "../Panel";
import { Skeleton } from "../States";
import { post, useOps } from "./OpsContext";
import { ActionButton, PagedPanel } from "./parts";
import styles from "./ops.module.css";

const RESULT = (success: boolean) => (success ? <span className={styles.good}>성공</span> : <span className={styles.bad}>실패</span>);

type Attempt = { attempted_at: string; ip_address: string; location?: string | null; username: string; success: boolean };

export function AttemptSection() {
  return (
    <PagedPanel<Attempt>
      name="attempts"
      title="최근 로그인 시도"
      caption="회원 로그인 시도 기록"
      rowKey={(r, i) => `${r.attempted_at}-${r.ip_address}-${i}`}
      empty={{ title: "로그인 시도 기록이 없습니다." }}
      columns={[
        { header: "시각", cell: (r) => formatShortDateTime(r.attempted_at, true), num: true },
        { header: "IP", cell: (r) => r.ip_address, num: true },
        { header: "접속 위치", cell: (r) => r.location ?? "-", grow: true },
        { header: "아이디", cell: (r) => r.username },
        { header: "결과", cell: (r) => RESULT(r.success) },
      ]}
    />
  );
}

type AdminLog = { attempted_at: string; username: string; ip_address: string; success: boolean };

export function AdminLogSection() {
  return (
    <PagedPanel<AdminLog>
      name="admin_log"
      title="관리자 로그인 기록"
      caption="관리자 로그인 시도 기록"
      rowKey={(r, i) => `${r.attempted_at}-${r.username}-${i}`}
      empty={{ title: "관리자 로그인 기록이 없습니다." }}
      columns={[
        { header: "시각", cell: (r) => formatDateTime(r.attempted_at), num: true },
        { header: "아이디", cell: (r) => r.username, grow: true },
        { header: "IP", cell: (r) => r.ip_address, num: true },
        { header: "결과", cell: (r) => RESULT(r.success) },
      ]}
    />
  );
}

type User = { id: number; username: string; email: string; email_status?: string; created_at: string };

export function UserSection() {
  const { status, can, run } = useOps();
  const { confirm } = useFeedback();
  const enabled = status?.signup_enabled ?? true;
  return (
    <PagedPanel<User>
      name="users"
      title="등록된 회원"
      caption="가입된 회원 목록"
      rowKey={(r) => r.id}
      empty={{ title: "가입된 회원이 없습니다." }}
      footer={
        can("toggle_signup") ? (
          <div className={styles.signupBar}>
            <span>
              회원가입: <strong className={`${styles.signupState} ${enabled ? styles.on : styles.off}`}>{enabled ? "허용 중" : "중단됨"}</strong>
            </span>
            <ActionButton id="signup-toggle" onClick={() => run("signup-toggle", () => post("/api/settings/signup", { enabled: !enabled }), enabled ? "회원가입을 껐습니다." : "회원가입을 켰습니다.")}>
              {enabled ? "회원가입 끄기" : "회원가입 켜기"}
            </ActionButton>
          </div>
        ) : null
      }
      columns={[
        { header: "가입 시각", cell: (r) => formatDateTime(r.created_at), num: true },
        { header: "아이디", cell: (r) => r.username },
        {
          header: "이메일",
          cell: (r) => (
            <>
              {r.email} {r.email_status === "VERIFIED" ? <Pill tone="ok">인증됨</Pill> : r.email_status === "UNDELIVERABLE" ? <Pill tone="danger">반송</Pill> : <Pill tone="warn">미인증</Pill>}
            </>
          ),
          grow: true,
        },
        {
          header: "조치",
          cell: (r) =>
            can("delete_user") ? (
              <ActionButton
                danger
                id={`delete-user:${r.id}`}
                onClick={async () => {
                  const { ok } = await confirm({ title: `"${r.username}" 회원을 삭제할까요?`, body: "이 작업은 되돌릴 수 없습니다.", confirmLabel: "삭제", danger: true });
                  if (ok) await run(`delete-user:${r.id}`, () => post("/api/users/delete", { user_id: r.id }), "회원을 삭제했습니다.");
                }}
              >
                삭제
              </ActionButton>
            ) : (
              "-"
            ),
        },
      ]}
    />
  );
}

type Post = { id: number; title: string; author_username: string; created_at: string };

export function PostSection() {
  const { can, run } = useOps();
  const { confirm } = useFeedback();
  return (
    <PagedPanel<Post>
      name="posts"
      title="게시판 관리 — 게시글"
      caption="게시글 목록"
      rowKey={(r) => r.id}
      empty={{ title: "등록된 게시글이 없습니다." }}
      columns={[
        { header: "작성 시각", cell: (r) => formatShortDateTime(r.created_at), num: true },
        { header: "제목", cell: (r) => <span className={styles.ellipsis}>{r.title}</span>, grow: true },
        { header: "작성자", cell: (r) => r.author_username },
        {
          header: "조치",
          cell: (r) =>
            can("delete_post") ? (
              <ActionButton
                danger
                id={`delete-post:${r.id}`}
                onClick={async () => {
                  const { ok } = await confirm({ title: "이 게시글을 삭제할까요?", body: "댓글도 함께 삭제됩니다.", confirmLabel: "삭제", danger: true });
                  if (ok) await run(`delete-post:${r.id}`, () => post("/api/board/posts/delete", { post_id: r.id }), "게시글을 삭제했습니다.");
                }}
              >
                삭제
              </ActionButton>
            ) : (
              "-"
            ),
        },
      ]}
    />
  );
}

type Comment = { id: number; body: string; author_username: string; created_at: string };

export function CommentSection() {
  const { can, run } = useOps();
  const { confirm } = useFeedback();
  return (
    <PagedPanel<Comment>
      name="comments"
      title="게시판 관리 — 댓글"
      caption="댓글 목록"
      rowKey={(r) => r.id}
      empty={{ title: "등록된 댓글이 없습니다." }}
      columns={[
        { header: "작성 시각", cell: (r) => formatShortDateTime(r.created_at), num: true },
        { header: "내용", cell: (r) => <span className={styles.ellipsis}>{r.body}</span>, grow: true },
        { header: "작성자", cell: (r) => r.author_username },
        {
          header: "조치",
          cell: (r) =>
            can("delete_comment") ? (
              <ActionButton
                danger
                id={`delete-comment:${r.id}`}
                onClick={async () => {
                  const { ok } = await confirm({ title: "이 댓글을 삭제할까요?", confirmLabel: "삭제", danger: true });
                  if (ok) await run(`delete-comment:${r.id}`, () => post("/api/board/comments/delete", { comment_id: r.id }), "댓글을 삭제했습니다.");
                }}
              >
                삭제
              </ActionButton>
            ) : (
              "-"
            ),
        },
      ]}
    />
  );
}

export function AdminUserSection() {
  const { status, run } = useOps();
  const { confirm } = useFeedback();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("security_viewer");

  // 이 목록은 manage_admin_users 권한(super_admin)이 있을 때만 응답에 실린다
  if (status === null) return <Panel title="관리자 계정 관리"><Skeleton lines={3} /></Panel>;
  if (status.admin_users === undefined) return null;

  async function create(event: React.FormEvent) {
    event.preventDefault();
    const done = await run("create-admin", () => post("/api/admin-users/create", { username, password, role }), "관리자 계정을 만들었습니다.");
    if (done) {
      setUsername("");
      setPassword("");
    }
  }

  return (
    <Panel title="관리자 계정 관리" flush>
      <DataTable
        caption="관리자 계정 목록"
        rows={status.admin_users}
        rowKey={(r) => r.id}
        empty={{ title: "관리자 계정이 없습니다." }}
        columns={[
          { header: "생성 시각", cell: (r) => formatDateTime(r.created_at), num: true },
          { header: "아이디", cell: (r) => r.username, grow: true },
          { header: "역할", cell: (r) => r.role },
          {
            header: "조치",
            cell: (r) =>
              r.role === "super_admin" ? (
                ""
              ) : (
                <ActionButton
                  danger
                  id={`delete-admin:${r.id}`}
                  onClick={async () => {
                    const { ok } = await confirm({ title: `관리자 계정 "${r.username}"을(를) 삭제할까요?`, body: "이 작업은 되돌릴 수 없습니다.", confirmLabel: "삭제", danger: true });
                    if (ok) await run(`delete-admin:${r.id}`, () => post("/api/admin-users/delete", { admin_id: r.id }), "관리자 계정을 삭제했습니다.");
                  }}
                >
                  삭제
                </ActionButton>
              ),
          },
        ]}
      />
      <form className={styles.formRow} onSubmit={create}>
        <div className="field">
          <label htmlFor="au-name">아이디</label>
          <input id="au-name" className="input" value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" />
        </div>
        <div className="field">
          <label htmlFor="au-pw">비밀번호</label>
          <input id="au-pw" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" />
        </div>
        <div className={`field ${styles.narrow}`}>
          <label htmlFor="au-role">역할</label>
          {/* super_admin은 이 화면에서 만들 수 없다(1명만 두는 정책) — 선택지에도 넣지 않는다 */}
          <select id="au-role" className="select" value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="security_viewer">security_viewer</option>
            <option value="security_admin">security_admin</option>
          </select>
        </div>
        <button type="submit" className="btn">
          계정 생성
        </button>
      </form>
    </Panel>
  );
}
