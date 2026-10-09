"use client";

// 회원 화면 3개 — 대시보드(/dashboard), 로그인 기록(/dashboard/history), 프로필(/dashboard/profile).
import { useState } from "react";
import { formatDateTime } from "@/lib/format";
import { useServerPage, useSubmit } from "@/lib/useServerPage";
import { Notice, Honeypot } from "../auth/AuthLayout";
import { Pill } from "../Badge";
import { EmptyState, Skeleton } from "../States";
import { MemberShell, Section } from "./MemberShell";
import styles from "./member.module.css";

type EmailStatus = "VERIFIED" | "UNDELIVERABLE" | "UNKNOWN" | string | undefined;

type HomeData = { display_name?: string; email_status?: EmailStatus };

export function MemberHome() {
  const page = useServerPage<HomeData>();
  const resend = useSubmit<HomeData>("/dashboard/email/verify/resend");
  const [notice, setNotice] = useState<string[]>([]);
  const data = page.data;

  async function sendVerification() {
    const result = await resend.submit({ next: "dashboard" });
    if (result) setNotice(result.messages);
  }

  return (
    <MemberShell title={data?.display_name ? `안녕하세요, ${data.display_name}님` : "내 대시보드"} current="/dashboard">
      <Notice messages={[...page.messages, ...notice]} />

      {data?.email_status === "UNDELIVERABLE" ? (
        <div className={`${styles.banner} ${styles.bannerBad}`}>
          <span>가입 이메일로 메일이 전달되지 않습니다.</span>
          <a href="/dashboard/profile">프로필에서 이메일 변경</a>
        </div>
      ) : data && data.email_status !== "VERIFIED" ? (
        <div className={styles.banner}>
          <span>이메일 인증이 필요합니다. 비밀번호를 잊었을 때 이 주소로 재설정합니다.</span>
          <button type="button" className="btn btn-small" onClick={sendVerification} disabled={resend.pending}>
            {resend.pending ? "보내는 중…" : "인증 메일 보내기"}
          </button>
        </div>
      ) : null}

      {page.loading ? (
        <Skeleton lines={3} />
      ) : (
        <ul className={styles.shortcuts}>
          <li>
            <a href="/dashboard/history">
              최근 로그인 기록 <small>내 계정으로 시도된 로그인</small>
            </a>
          </li>
          <li>
            <a href="/dashboard/profile">
              프로필 · 수정 <small>표시 이름, 이메일, 비밀번호</small>
            </a>
          </li>
          <li>
            <a href="/board">
              게시판 <small>글과 댓글</small>
            </a>
          </li>
        </ul>
      )}
    </MemberShell>
  );
}

type Attempt = { attempted_at: string; ip_address: string; location?: string | null; success: boolean };

export function MemberHistory() {
  const page = useServerPage<{ attempts?: Attempt[] }>();
  const attempts = page.data?.attempts ?? [];

  return (
    <MemberShell title="최근 로그인 기록" current="/dashboard/history" width="wide">
      <Notice messages={page.messages} />
      {page.loading ? (
        <Skeleton lines={5} />
      ) : attempts.length === 0 ? (
        <EmptyState title="아직 로그인 시도 기록이 없습니다." />
      ) : (
        <div className={styles.tableWrap}>
          <table className="plain-table">
            <caption className="sr-only">내 계정의 최근 로그인 시도</caption>
            <thead>
              <tr>
                <th scope="col">시각</th>
                <th scope="col">IP</th>
                <th scope="col">위치</th>
                <th scope="col">결과</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((attempt, index) => (
                <tr key={`${attempt.attempted_at}-${index}`}>
                  <td className="num">{formatDateTime(attempt.attempted_at)}</td>
                  <td className="num">{attempt.ip_address}</td>
                  <td>{attempt.location ?? "-"}</td>
                  <td>{attempt.success ? "성공" : "실패"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <a className={styles.back} href="/dashboard">
        ← 대시보드로 돌아가기
      </a>
    </MemberShell>
  );
}

type ProfileData = { user?: { username: string; name: string; email: string; email_status?: EmailStatus }; pending_email?: string | null };

export function MemberProfile() {
  const page = useServerPage<ProfileData>();
  const [notice, setNotice] = useState<string[]>([]);
  const [name, setName] = useState<string | null>(null);
  const [newEmail, setNewEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [pw, setPw] = useState({ current_password: "", new_password: "", new_password_confirm: "" });

  const profile = useSubmit<ProfileData>("/dashboard/profile");
  const emailChange = useSubmit<ProfileData>("/dashboard/email/change");
  const resend = useSubmit<ProfileData>("/dashboard/email/verify/resend");
  const password = useSubmit<ProfileData>("/dashboard/password");

  const user = page.data?.user;
  const shownName = name ?? user?.name ?? "";

  // 이 화면의 POST는 처리가 끝나면 같은 화면으로 리다이렉트한다 — 화면이 다시 열리면서 결과 문장(flash)을 보여준다.
  // 여기로 돌아오는 건 리다이렉트가 아닌 응답(오류)뿐이라 그 문장만 띄운다.
  function showResult(result: { messages: string[] } | null) {
    if (result) {
      setNotice(result.messages);
      window.scrollTo({ top: 0 });
    }
  }

  return (
    <MemberShell title="내 프로필" current="/dashboard/profile">
      <Notice messages={[...notice, ...page.messages]} />
      {page.loading || !user ? (
        <Skeleton lines={6} />
      ) : (
        <>
          <Section title="기본 정보">
            <form
              className="form-stack"
              onSubmit={async (event) => {
                event.preventDefault();
                showResult(await profile.submit({ name: shownName }));
              }}
            >
              <div className="field">
                <label htmlFor="username">아이디</label>
                <input id="username" className="input" value={user.username} readOnly />
              </div>
              <div className="field">
                <label htmlFor="name">표시 이름</label>
                <input id="name" className="input" value={shownName} onChange={(e) => setName(e.target.value)} placeholder="아직 설정하지 않았습니다" />
              </div>
              <div>
                <button type="submit" className="btn" disabled={profile.pending}>
                  {profile.pending ? "저장 중…" : "저장"}
                </button>
              </div>
            </form>
          </Section>

          <Section title="이메일">
            <p className={styles.emailLine}>
              <span>{user.email}</span>
              {user.email_status === "VERIFIED" ? <Pill tone="ok">인증됨</Pill> : user.email_status === "UNDELIVERABLE" ? <Pill tone="danger">메일 전달 불가</Pill> : <Pill tone="warn">미인증</Pill>}
            </p>
            {user.email_status === "UNDELIVERABLE" ? (
              <p className={styles.note}>이 주소로 메일이 전달되지 않습니다. 아래에서 이메일을 변경해주세요.</p>
            ) : user.email_status !== "VERIFIED" ? (
              <>
                <div>
                  <button type="button" className="btn btn-small" disabled={resend.pending} onClick={async () => showResult(await resend.submit({}))}>
                    {resend.pending ? "보내는 중…" : "인증 메일 보내기"}
                  </button>
                </div>
                <p className={styles.note}>인증된 이메일로만 비밀번호 재설정 메일을 받을 수 있습니다.</p>
              </>
            ) : null}
            {page.data?.pending_email ? (
              <p className={styles.note}>
                확인 대기 중: <strong>{page.data.pending_email}</strong> — 메일의 링크를 눌러야 변경됩니다.
              </p>
            ) : null}

            <form
              className="form-stack"
              onSubmit={async (event) => {
                event.preventDefault();
                const result = await emailChange.submit({ new_email: newEmail, current_password: emailPassword });
                setEmailPassword("");
                if (result) setNewEmail("");
                showResult(result);
              }}
            >
              <Honeypot />
              <div className="field">
                <label htmlFor="new_email">새 이메일</label>
                <input id="new_email" className="input" type="email" value={newEmail} onChange={(e) => setNewEmail(e.target.value)} autoComplete="email" required />
              </div>
              <div className="field">
                <label htmlFor="email_current_password">현재 비밀번호</label>
                <input id="email_current_password" className="input" type="password" value={emailPassword} onChange={(e) => setEmailPassword(e.target.value)} autoComplete="current-password" required />
              </div>
              <div>
                <button type="submit" className="btn" disabled={emailChange.pending}>
                  {emailChange.pending ? "요청 중…" : "이메일 변경 요청"}
                </button>
              </div>
            </form>
            <p className={styles.note}>새 주소로 확인 메일이 가고, 링크를 눌러야 바뀝니다. 바뀌면 기존 주소로 알림이 갑니다.</p>
          </Section>

          <Section title="비밀번호 변경">
            <form
              className="form-stack"
              onSubmit={async (event) => {
                event.preventDefault();
                const result = await password.submit(pw);
                setPw({ current_password: "", new_password: "", new_password_confirm: "" });
                showResult(result);
              }}
            >
              <Honeypot />
              <div className="field">
                <label htmlFor="current_password">현재 비밀번호</label>
                <input id="current_password" className="input" type="password" value={pw.current_password} onChange={(e) => setPw({ ...pw, current_password: e.target.value })} autoComplete="current-password" required />
              </div>
              <div className="field">
                <label htmlFor="new_password">새 비밀번호</label>
                <input id="new_password" className="input" type="password" value={pw.new_password} onChange={(e) => setPw({ ...pw, new_password: e.target.value })} autoComplete="new-password" minLength={8} required />
                <span className="field-hint">8자 이상</span>
              </div>
              <div className="field">
                <label htmlFor="new_password_confirm">새 비밀번호 확인</label>
                <input id="new_password_confirm" className="input" type="password" value={pw.new_password_confirm} onChange={(e) => setPw({ ...pw, new_password_confirm: e.target.value })} autoComplete="new-password" minLength={8} required />
              </div>
              <div>
                <button type="submit" className="btn" disabled={password.pending}>
                  {password.pending ? "변경 중…" : "비밀번호 변경"}
                </button>
              </div>
            </form>
            <p className={styles.note}>변경하면 이 기기를 제외한 다른 기기의 로그인은 모두 해제되고, 가입한 이메일로 알림이 갑니다.</p>
            {user.email_status === "VERIFIED" ? (
              <p className={styles.note}>
                현재 비밀번호가 기억나지 않나요? <a href={`/password/forgot?username=${encodeURIComponent(user.username)}`}>이메일로 재설정</a>
              </p>
            ) : (
              <p className={styles.note}>현재 비밀번호가 기억나지 않는다면, 먼저 위에서 이메일 인증을 해야 이메일로 재설정할 수 있습니다.</p>
            )}
          </Section>
        </>
      )}
      <a className={styles.back} href="/dashboard">
        ← 대시보드로 돌아가기
      </a>
    </MemberShell>
  );
}
