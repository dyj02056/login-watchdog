"use client";

import { useState } from "react";
import { useServerPage, useSubmit } from "@/lib/useServerPage";
import { AuthLayout, Honeypot, Notice } from "./AuthLayout";

type SignupData = { signup_enabled?: boolean };

export function SignupView() {
  const page = useServerPage<SignupData>();
  const { pending, submit } = useSubmit<SignupData>("/signup");
  const [form, setForm] = useState({ username: "", email: "", password: "", password_confirm: "" });
  const set = (key: keyof typeof form) => (event: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [key]: event.target.value }));

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    const result = await submit(form);
    if (!result) return; // 가입 성공 → 로그인 화면으로 이동 중
    setForm((f) => ({ ...f, password: "", password_confirm: "" }));
    page.apply(result);
  }

  const closed = page.data?.signup_enabled === false;

  return (
    <AuthLayout title="회원가입" links={[{ href: "/login", label: "이미 계정이 있으신가요? 로그인" }]}>
      <Notice messages={page.messages} error={page.status >= 400} />
      {closed ? (
        <p className="notice notice-error">현재 관리자가 회원가입을 잠시 중단해뒀습니다. 잠시 후 다시 시도해주세요.</p>
      ) : (
        <form className="form-stack" onSubmit={onSubmit}>
          <Honeypot />
          <div className="field">
            <label htmlFor="username">아이디</label>
            <input id="username" className="input" value={form.username} onChange={set("username")} autoComplete="username" pattern="[A-Za-z0-9_]{3,20}" required autoFocus />
            <span className="field-hint">영문자·숫자·밑줄(_) 3~20자</span>
          </div>
          <div className="field">
            <label htmlFor="email">이메일</label>
            <input id="email" className="input" type="email" value={form.email} onChange={set("email")} autoComplete="email" required />
          </div>
          <div className="field">
            <label htmlFor="password">비밀번호</label>
            <input id="password" className="input" type="password" value={form.password} onChange={set("password")} autoComplete="new-password" minLength={8} required />
            <span className="field-hint">8자 이상</span>
          </div>
          <div className="field">
            <label htmlFor="password_confirm">비밀번호 확인</label>
            <input id="password_confirm" className="input" type="password" value={form.password_confirm} onChange={set("password_confirm")} autoComplete="new-password" minLength={8} required />
          </div>
          <button type="submit" className="btn" disabled={pending || page.loading}>
            {pending ? "가입 중…" : "가입하기"}
          </button>
        </form>
      )}
    </AuthLayout>
  );
}
