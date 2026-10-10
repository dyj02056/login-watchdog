"use client";

// 복구 흐름 — 요청(/recovery), 확인(/recovery/verify), 비밀번호 찾기(/password/forgot, /password/reset), 이메일 확인(/email/confirm).
// 서버는 계정이 있든 없든 같은 문구로 답한다(계정 존재 여부 노출 방지). 이 화면들은 그 문구를 그대로 보여주기만 한다.
import { useState } from "react";
import { useServerPage, useSubmit } from "@/lib/useServerPage";
import { formatDateTime } from "@/lib/format";
import { AuthLayout, Honeypot, Notice } from "./AuthLayout";
import styles from "./auth.module.css";

function query(name: string): string {
  return new URLSearchParams(window.location.search).get(name) ?? "";
}

type MessageData = { message?: string | null; username?: string };

/** /recovery — 아이디를 넣으면 가입한 이메일로 인증 링크와 6자리 코드를 보낸다 */
export function RecoveryRequestView() {
  const page = useServerPage<MessageData>();
  const { pending, submit } = useSubmit<MessageData>("/recovery/request");
  const [username, setUsername] = useState("");
  const [sent, setSent] = useState<string | null>(null);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit({ username });
    if (!result) return;
    setSent(result.data?.message ?? result.messages[0] ?? null);
    page.apply(result);
  }

  return (
    <AuthLayout
      title="본인 인증으로 잠금 해제"
      lead="영구 잠금된 계정의 아이디를 입력하면 가입한 이메일로 인증 링크와 6자리 코드를 보내드립니다. 몇 분 뒤 자동으로 풀리는 잠금이라면 메일이 가지 않으니, 잠시 후 다시 로그인해 보세요."
      links={[
        { href: "/recovery/verify", label: "코드로 인증하기" },
        { href: "/login", label: "로그인으로 돌아가기" },
      ]}
    >
      <Notice messages={sent ? [sent] : page.messages} />
      <form className="form-stack" onSubmit={onSubmit}>
        <Honeypot />
        <div className="field">
          <label htmlFor="username">아이디</label>
          <input id="username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
        </div>
        <button type="submit" className="btn" disabled={pending}>
          {pending ? "보내는 중…" : "인증 메일 보내기"}
        </button>
      </form>
    </AuthLayout>
  );
}

type VerifyData = { mode?: "confirm" | "code" | "wrong_device" | "invalid"; message?: string | null; masked_username?: string; requested_ip?: string; requested_at?: string; kind?: string; success?: boolean };

/** /recovery/verify — 메일 링크(?t=토큰)의 확인 화면, 또는 6자리 코드 입력. 완료되면 같은 주소가 결과 화면을 돌려준다. */
export function RecoveryVerifyView() {
  const page = useServerPage<VerifyData>();
  const { pending, submit } = useSubmit<VerifyData>("/recovery/verify");
  const [username, setUsername] = useState("");
  const [code, setCode] = useState("");
  const token = typeof window === "undefined" ? "" : query("t");

  async function onConfirm() {
    const result = await submit({ t: token });
    if (result) page.apply(result);
  }
  async function onCode(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit({ username, code });
    if (!result) return;
    setCode("");
    page.apply(result);
  }

  const data = page.data;

  // 완료/실패 결과 (서버는 recovery_done.html을 돌려준다)
  if (data && "success" in data && data.success !== undefined) {
    return (
      <AuthLayout title={data.success ? "복구 완료" : "복구할 수 없습니다"} links={[{ href: "/login", label: "로그인으로 이동" }]}>
        {data.success ? (
          <>
            <Notice messages={[data.kind === "account" ? "계정의 영구 잠금이 해제되었습니다. 이제 로그인할 수 있습니다." : "이 기기에서의 접속이 허용되었습니다. 이 IP의 다른 기기는 계속 차단됩니다."]} />
            <p className="field-hint">본인이 한 일이 아니라면 즉시 비밀번호를 변경하고 관리자에게 알려주세요.</p>
          </>
        ) : (
          <Notice messages={[data.message ?? "복구할 수 없습니다."]} error />
        )}
      </AuthLayout>
    );
  }
  return (
    <AuthLayout
      title="본인 확인"
      links={[
        { href: "/recovery", label: "복구 다시 요청하기" },
        { href: "/login", label: "로그인으로 돌아가기" },
      ]}
    >
      <Notice messages={data?.message ? [data.message] : page.messages} error={data?.mode === "invalid" || data?.mode === "code"} />

      {data?.mode === "confirm" ? (
        <>
          <dl className={styles.facts}>
            <dt>대상 계정</dt>
            <dd>{data.masked_username}</dd>
            <dt>요청 IP</dt>
            <dd className="num">{data.requested_ip}</dd>
            <dt>요청 시각</dt>
            <dd className="num">{formatDateTime(data.requested_at)}</dd>
          </dl>
          <p className="field-hint">
            {data.kind === "account"
              ? "해제하면 계정의 영구 잠금이 풀리고, 이후 24시간은 보호관찰 기간입니다."
              : "이 IP는 계속 차단된 상태이며, 회원님과 이 기기만 접속이 허용됩니다."}
          </p>
          <p className="field-hint">직접 요청하신 게 아니라면 이 화면을 닫으세요. 아무 일도 일어나지 않습니다.</p>
          <button type="button" className="btn" onClick={onConfirm} disabled={pending}>
            {pending ? "처리 중…" : "해제"}
          </button>
        </>
      ) : null}

      {data?.mode === "code" || data?.mode === "wrong_device" ? (
        <form className="form-stack" onSubmit={onCode}>
          <p className="field-hint">6자리 코드는 복구를 요청한 기기의 브라우저에서 입력해야 합니다. 다른 기기라면 메일의 링크를 이용해주세요.</p>
          <div className="field">
            <label htmlFor="username">아이디</label>
            <input id="username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="field">
            <label htmlFor="code">6자리 코드</label>
            <input id="code" className="input num" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" required />
          </div>
          <button type="submit" className="btn" disabled={pending}>
            {pending ? "확인 중…" : "인증하기"}
          </button>
        </form>
      ) : null}
    </AuthLayout>
  );
}

/** /password/forgot — 인증된 이메일로 재설정 링크를 보낸다 */
export function PasswordForgotView() {
  const page = useServerPage<MessageData>();
  const { pending, submit } = useSubmit<MessageData>("/password/forgot");
  const [username, setUsername] = useState("");
  const [prefilled, setPrefilled] = useState(false);
  const [sent, setSent] = useState<string | null>(null);

  // 프로필의 "이메일로 재설정" 링크는 아이디를 미리 채워 보낸다(서버가 형식을 검사해서 돌려준다)
  if (!prefilled && page.data?.username) {
    setPrefilled(true);
    setUsername(page.data.username);
  }

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit({ username });
    if (!result) return;
    setSent(result.data?.message ?? null);
    page.apply(result);
  }

  return (
    <AuthLayout
      title="비밀번호 찾기"
      lead={
        <>
          아이디를 입력하면 <strong>인증된 이메일</strong>로 비밀번호 재설정 링크를 보내드립니다. 이메일 인증을 하지 않았다면 메일이 가지 않으니 관리자에게 문의해주세요.
        </>
      }
      links={[{ href: "/login", label: "로그인으로 돌아가기" }]}
    >
      <Notice messages={sent ? [sent] : []} />
      <form className="form-stack" onSubmit={onSubmit}>
        <Honeypot />
        <div className="field">
          <label htmlFor="username">아이디</label>
          <input id="username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
        </div>
        <button type="submit" className="btn" disabled={pending}>
          {pending ? "보내는 중…" : "재설정 메일 보내기"}
        </button>
      </form>
    </AuthLayout>
  );
}

type ResetData = { mode?: "form" | "invalid"; message?: string | null; masked_username?: string; min_length?: number };

/** /password/reset?t=토큰 — 새 비밀번호 입력 */
export function PasswordResetView() {
  const page = useServerPage<ResetData>();
  const { pending, submit } = useSubmit<ResetData>("/password/reset");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const data = page.data;
  const min = data?.min_length ?? 8;

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit({ t: query("t"), new_password: password, new_password_confirm: confirm });
    if (!result) return; // 재설정 완료 → 로그인 화면으로 이동 중
    setPassword("");
    setConfirm("");
    page.apply(result);
  }

  return (
    <AuthLayout
      title="비밀번호 재설정"
      links={[...(data?.mode === "invalid" ? [{ href: "/password/forgot", label: "비밀번호 찾기 다시 요청" }] : []), { href: "/login", label: "로그인으로 이동" }]}
    >
      <Notice messages={data?.message ? [data.message] : page.messages} error={data?.mode === "invalid"} />
      {data?.mode === "form" ? (
        <form className="form-stack" onSubmit={onSubmit}>
          <dl className={styles.facts}>
            <dt>대상 계정</dt>
            <dd>{data.masked_username}</dd>
          </dl>
          <p className="field-hint">바꾸면 모든 기기의 로그인이 해제되고, 이메일로 알림이 갑니다.</p>
          <div className="field">
            <label htmlFor="new_password">새 비밀번호</label>
            <input id="new_password" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={min} required autoFocus />
            <span className="field-hint">{min}자 이상</span>
          </div>
          <div className="field">
            <label htmlFor="new_password_confirm">새 비밀번호 확인</label>
            <input id="new_password_confirm" className="input" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" minLength={min} required />
          </div>
          <button type="submit" className="btn" disabled={pending}>
            {pending ? "변경 중…" : "비밀번호 재설정"}
          </button>
        </form>
      ) : null}
    </AuthLayout>
  );
}

type ConfirmData = { mode?: "confirm" | "invalid" | "done"; title?: string; message?: string | null; masked_username?: string; masked_email?: string; purpose?: string };

/** /email/confirm?t=토큰 — 이메일 인증·변경 확인 */
export function EmailConfirmView() {
  const page = useServerPage<ConfirmData>();
  const { pending, submit } = useSubmit<ConfirmData>("/email/confirm");
  const data = page.data;

  async function onConfirm() {
    const result = await submit({ t: query("t") });
    if (result) page.apply(result);
  }

  return (
    <AuthLayout title={data?.title ?? "이메일 확인"} links={[{ href: "/login", label: "로그인으로 이동" }]}>
      <Notice messages={data?.message ? [data.message] : page.messages} error={data?.mode === "invalid"} />
      {data?.mode === "confirm" ? (
        <>
          <dl className={styles.facts}>
            <dt>대상 계정</dt>
            <dd>{data.masked_username}</dd>
            <dt>확인할 이메일</dt>
            <dd>{data.masked_email}</dd>
          </dl>
          <p className="field-hint">
            {data.purpose === "EMAIL_CHANGE"
              ? "버튼을 누르면 계정 이메일이 이 주소로 바뀌고, 기존 주소로 변경 알림이 갑니다."
              : "버튼을 누르면 이 주소가 인증되어, 비밀번호 재설정 메일을 받을 수 있게 됩니다."}
          </p>
          <p className="field-hint">직접 요청하신 게 아니라면 이 화면을 닫으세요. 아무 일도 일어나지 않습니다.</p>
          <button type="button" className="btn" onClick={onConfirm} disabled={pending}>
            {pending ? "처리 중…" : data.purpose === "EMAIL_CHANGE" ? "이메일 변경" : "인증"}
          </button>
        </>
      ) : null}
    </AuthLayout>
  );
}
