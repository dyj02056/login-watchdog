"use client";

// LoginView — /login(회원)과 /admin/login(관리자)이 같이 쓴다. 겉모습은 같지만 어디로 제출하는지만 다르다
// (둘의 인증·잠금 로직은 서버에서 완전히 분리되어 있다 — templates/login_form.html 설명 참고).
import { useState } from "react";
import { useServerPage, useSubmit } from "@/lib/useServerPage";
import { AuthLayout, Honeypot, Notice } from "./AuthLayout";

type LoginData = { form_action?: string; recovery_link?: boolean };

export function LoginView({ admin = false }: { admin?: boolean }) {
  const action = admin ? "/admin/login" : "/login";
  const page = useServerPage<LoginData>();
  const { pending, submit } = useSubmit<LoginData>(action);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit({ username, password });
    if (!result) return; // 로그인 성공 → 이동 중
    setPassword("");
    page.apply(result);
  }

  const failed = page.messages.length > 0;

  return (
    <AuthLayout
      title={admin ? "관리자 로그인" : "로그인"}
      links={
        admin
          ? undefined
          : [
              { href: "/signup", label: "회원가입" },
              { href: "/password/forgot", label: "비밀번호 찾기" },
              ...(page.data?.recovery_link ? [{ href: "/recovery", label: "본인 인증으로 잠금 해제" }] : []),
            ]
      }
    >
      <Notice messages={page.messages} error={failed && page.status >= 400} />
      <form className="form-stack" onSubmit={onSubmit}>
        <Honeypot />
        <div className="field">
          <label htmlFor="username">아이디</label>
          <input id="username" className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required autoFocus />
        </div>
        <div className="field">
          <label htmlFor="password">비밀번호</label>
          <input id="password" className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </div>
        <button type="submit" className="btn" disabled={pending || page.loading}>
          {pending ? "확인 중…" : "로그인"}
        </button>
      </form>
    </AuthLayout>
  );
}
