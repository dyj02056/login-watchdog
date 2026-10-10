"use client";

// 게시판 — 목록(/board), 글쓰기(/board/new), 상세(/board/<id>), 수정(/board/<id>/edit).
// 글·댓글 작성과 삭제는 기존 라우트(request.form)를 그대로 쓴다. 상세 화면의 번호는 주소에서 읽는다.
import { useEffect, useState } from "react";
import { apiJson, getSession } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useServerPage, useSubmit } from "@/lib/useServerPage";
import { usePolling } from "@/lib/usePolling";
import { Honeypot, Notice } from "../auth/AuthLayout";
import { FeedbackProvider, useFeedback } from "../Feedback";
import { EmptyState, Skeleton } from "../States";
import { MemberShell } from "./MemberShell";
import styles from "./member.module.css";

type Post = { id: number; title: string; body: string; author_username: string; created_at: string };
type Comment = { id: number; body: string; author_username: string; created_at: string };

function postIdFromPath(): number {
  const match = window.location.pathname.match(/^\/board\/(\d+)/);
  return match ? Number(match[1]) : 0;
}

export function BoardList() {
  const page = useServerPage<{ posts?: Post[]; page?: number; total_pages?: number }>();
  const posts = page.data?.posts ?? [];
  const current = page.data?.page ?? 1;
  const total = page.data?.total_pages ?? 1;

  return (
    <MemberShell title="게시판" current="/board">
      <Notice messages={page.messages} />
      <div className={styles.head}>
        <span className={styles.note}>{page.loading ? "" : `${posts.length}개의 글`}</span>
        <a className="btn" href="/board/new">
          글쓰기
        </a>
      </div>

      {page.loading ? (
        <Skeleton lines={6} />
      ) : posts.length === 0 ? (
        <EmptyState title="아직 등록된 게시글이 없습니다." hint="첫 글을 남겨보세요." />
      ) : (
        <ul className={styles.posts}>
          {posts.map((post) => (
            <li key={post.id} className={styles.post}>
              <a href={`/board/${post.id}`}>{post.title}</a>
              <div className={styles.meta}>
                <span>{post.author_username}</span>
                <span className="num">{formatDateTime(post.created_at)}</span>
              </div>
            </li>
          ))}
        </ul>
      )}

      {total > 1 ? (
        <nav className={styles.head} aria-label="쪽 이동">
          {current > 1 ? <a href={`/board?page=${current - 1}`}>← 이전</a> : <span className={styles.note}>← 이전</span>}
          <span className="num">
            {current} / {total}
          </span>
          {current < total ? <a href={`/board?page=${current + 1}`}>다음 →</a> : <span className={styles.note}>다음 →</span>}
        </nav>
      ) : null}
    </MemberShell>
  );
}

type FormData = { form_action?: string; post?: Post | null };

/** 글쓰기·수정 공용. 수정이면 서버가 post를 내려준다. */
export function BoardForm() {
  const page = useServerPage<FormData>();
  const action = page.data?.form_action;
  const editing = Boolean(page.data?.post);
  const { pending, submit } = useSubmit<FormData>(action ?? "/board/new");
  const [title, setTitle] = useState<string | null>(null);
  const [body, setBody] = useState<string | null>(null);

  const titleValue = title ?? page.data?.post?.title ?? "";
  const bodyValue = body ?? page.data?.post?.body ?? "";

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!action) return;
    const result = await submit({ title: titleValue, body: bodyValue });
    if (result) page.apply(result);
  }

  return (
    <MemberShell title={editing ? "게시글 수정" : "새 게시글 작성"} current="/board">
      <Notice messages={page.messages} error={page.status >= 400} />
      {page.loading ? (
        <Skeleton lines={6} />
      ) : (
        <form className="form-stack" onSubmit={onSubmit}>
          <Honeypot />
          <div className="field">
            <label htmlFor="title">제목</label>
            <input id="title" className="input" value={titleValue} onChange={(e) => setTitle(e.target.value)} maxLength={100} required autoFocus />
          </div>
          <div className="field">
            <label htmlFor="body">내용</label>
            <textarea id="body" className="textarea" value={bodyValue} onChange={(e) => setBody(e.target.value)} rows={10} maxLength={5000} required />
            <span className="field-hint num">{bodyValue.length} / 5000</span>
          </div>
          <div className={styles.actions}>
            <button type="submit" className="btn" disabled={pending}>
              {pending ? "저장 중…" : editing ? "수정 완료" : "등록하기"}
            </button>
            <a className="btn-quiet btn" href={editing && page.data?.post ? `/board/${page.data.post.id}` : "/board"}>
              취소
            </a>
          </div>
        </form>
      )}
    </MemberShell>
  );
}

type DetailData = { post?: Post; comments?: Comment[]; is_owner?: boolean; poll_interval_ms?: number };

function Detail() {
  const page = useServerPage<DetailData>();
  const { confirm, toast } = useFeedback();
  const [me, setMe] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [deleting, setDeleting] = useState<string | null>(null);
  const comment = useSubmit<DetailData>(`/board/${typeof window === "undefined" ? 0 : postIdFromPath()}/comments`);
  const data = page.data;
  const known = data ? `${data.comments?.length ?? 0}|${data.comments?.at(-1)?.created_at ?? ""}` : null;

  useEffect(() => {
    void getSession().then((session) => setMe(session?.username ?? null));
  }, []);

  // 새 댓글 알림: 가볍게 개수·마지막 시각만 확인한다. 탭이 보일 때만 돈다.
  const latest = usePolling<{ count: number; latest_at: string | null }>(async () => {
    if (!data) return { data: null };
    const result = await apiJson<{ count: number; latest_at: string | null }>(`/api/board/${postIdFromPath()}/comments/latest`);
    return { data: result.ok ? result.data : null, error: result.error };
  }, data?.poll_interval_ms ?? 5000);
  const seen = latest.data ? `${latest.data.count}|${latest.data.latest_at ?? ""}` : null;
  const hasNew = known !== null && seen !== null && known !== seen;

  async function addComment(event: React.FormEvent) {
    event.preventDefault();
    const result = await comment.submit({ body: text });
    if (!result) return; // 등록 성공 → 이 화면으로 다시 이동(새 댓글 포함)
    page.apply(result);
  }

  async function remove(kind: "post" | "comment", id: number) {
    const postId = postIdFromPath();
    const { ok } = await confirm({
      title: kind === "post" ? "이 게시글을 삭제할까요?" : "이 댓글을 삭제할까요?",
      confirmLabel: "삭제",
      danger: true,
    });
    if (!ok) return;
    setDeleting(`${kind}:${id}`);
    const { postForm } = await import("@/lib/api");
    const path = kind === "post" ? `/board/${postId}/delete` : `/board/${postId}/comments/${id}/delete`;
    const result = await postForm(path, {});
    setDeleting(null);
    if (result) toast(result.messages[0] ?? "삭제하지 못했습니다.", "error");
  }

  const post = data?.post;
  const comments = data?.comments ?? [];

  return (
    <MemberShell title={post?.title ?? "게시글"} current="/board">
      <Notice messages={page.messages} />
      {hasNew ? (
        <div className={styles.newComment} role="status">
          새로운 댓글이 추가되었습니다.
          <button type="button" className="btn btn-small" onClick={() => window.location.reload()}>
            새로고침
          </button>
        </div>
      ) : null}

      {page.loading || !post ? (
        <Skeleton lines={6} />
      ) : (
        <>
          <div className={styles.meta}>
            <span>{post.author_username}</span>
            <span className="num">{formatDateTime(post.created_at)}</span>
          </div>
          <p className={styles.body}>{post.body}</p>
          {data?.is_owner ? (
            <div className={styles.actions}>
              <a className="btn-quiet btn btn-small" href={`/board/${post.id}/edit`}>
                수정
              </a>
              <button type="button" className="btn-danger btn-small" disabled={deleting !== null} onClick={() => remove("post", post.id)}>
                {deleting === `post:${post.id}` ? "삭제 중…" : "삭제"}
              </button>
            </div>
          ) : null}

          <h2 className={styles.commentsTitle}>
            댓글 {comments.length}개
          </h2>
          {comments.length === 0 ? (
            <EmptyState title="아직 댓글이 없습니다." />
          ) : (
            <ul className={styles.comments}>
              {comments.map((c) => (
                <li key={c.id} className={styles.comment}>
                  <div className={styles.meta}>
                    <span>{c.author_username}</span>
                    <span className="num">{formatDateTime(c.created_at)}</span>
                  </div>
                  <p>{c.body}</p>
                  {me && c.author_username === me ? (
                    <div>
                      <button type="button" className="btn-quiet btn-small" disabled={deleting !== null} onClick={() => remove("comment", c.id)}>
                        {deleting === `comment:${c.id}` ? "삭제 중…" : "삭제"}
                      </button>
                    </div>
                  ) : null}
                </li>
              ))}
            </ul>
          )}

          <form className="form-stack" onSubmit={addComment}>
            <Honeypot />
            <div className="field">
              <label htmlFor="comment-body">댓글 작성</label>
              <textarea id="comment-body" className="textarea" value={text} onChange={(e) => setText(e.target.value)} rows={3} maxLength={1000} required />
              <span className="field-hint num">{text.length} / 1000</span>
            </div>
            <div>
              <button type="submit" className="btn" disabled={comment.pending}>
                {comment.pending ? "등록 중…" : "댓글 등록"}
              </button>
            </div>
          </form>
        </>
      )}
      <a className={styles.back} href="/board">
        ← 게시판으로 돌아가기
      </a>
    </MemberShell>
  );
}

export function BoardDetail() {
  return (
    <FeedbackProvider>
      <Detail />
    </FeedbackProvider>
  );
}
