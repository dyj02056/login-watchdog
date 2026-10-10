"use client";

// MemberShell — 로그인한 회원 화면(대시보드·기록·프로필·게시판) 공통 틀.
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getSession, postForm } from "@/lib/api";
import styles from "./member.module.css";

const NAV = [
  { href: "/dashboard", label: "대시보드" },
  { href: "/board", label: "게시판" },
  { href: "/dashboard/history", label: "로그인 기록" },
  { href: "/dashboard/profile", label: "프로필" },
];

export function MemberShell({ title, current, children, width = "normal" }: { title: string; current: string; children: ReactNode; width?: "normal" | "wide" }) {
  const [user, setUser] = useState<string | null>(null);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    void getSession().then((session) => setUser(session?.username ?? null));
  }, []);

  async function logout() {
    setLeaving(true);
    const result = await postForm("/dashboard/logout", {});
    if (result) setLeaving(false);
  }

  return (
    <div className={styles.shell}>
      <header className={styles.header}>
        <a className={styles.brand} href="/dashboard">
          로그인 워치독
        </a>
        <nav className={styles.nav} aria-label="회원 메뉴">
          {NAV.map((item) => (
            <a key={item.href} href={item.href} aria-current={item.href === current ? "page" : undefined}>
              {item.label}
            </a>
          ))}
        </nav>
        <div className={styles.who}>
          {user ? <span className={styles.user}>{user}</span> : null}
          <button type="button" className="btn-quiet btn-small" onClick={logout} disabled={leaving}>
            {leaving ? "로그아웃 중…" : "로그아웃"}
          </button>
        </div>
      </header>

      <main className={`${styles.main} ${width === "wide" ? styles.wide : ""}`}>
        <h1 className={styles.title}>{title}</h1>
        {children}
      </main>
    </div>
  );
}

/** 구역 하나 — 제목과 본문. 카드로 감싸지 않고 위쪽 선으로만 나눈다. */
export function Section({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <section className={styles.section}>
      {title ? <h2 className={styles.sectionTitle}>{title}</h2> : null}
      {children}
    </section>
  );
}
