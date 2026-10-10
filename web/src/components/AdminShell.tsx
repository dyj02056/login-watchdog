"use client";

// AdminShell — 관제 화면(위협 현황·공격 상세·처리 작업대) 공통 머리줄.
// 가운데 제목(HUD 프레임), 왼쪽 화면 이동, 오른쪽 시계와 로그인 정보.
// 화면 이동은 일부러 <a>만 쓴다(lib/api.ts의 go 설명 참고).
import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getSession, postForm } from "@/lib/api";
import styles from "./AdminShell.module.css";

const TABS = [
  { href: "/admin/dashboard", label: "위협 현황" },
  { href: "/admin/attack", label: "공격 상세" },
  { href: "/admin/ops", label: "처리 작업대" },
];

function useClock() {
  const [now, setNow] = useState<string | null>(null);
  useEffect(() => {
    const format = new Intl.DateTimeFormat("sv-SE", {
      timeZone: "Asia/Seoul",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    const tick = () => setNow(format.format(new Date()));
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, []);
  return now;
}

export function AdminShell({ title, current, children }: { title: string; current: string; children: ReactNode }) {
  const clock = useClock();
  const [user, setUser] = useState<string | null>(null);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    void getSession().then((session) => setUser(session?.admin_username ?? null));
  }, []);

  async function logout() {
    setLeaving(true);
    const result = await postForm("/admin/logout", {});
    if (result) setLeaving(false); // 리다이렉트가 오지 않았다 = 실패
  }

  return (
    <div className={styles.shell}>
      <header className={styles.header}>
        <nav className={styles.tabs} aria-label="관제 화면">
          {TABS.map((tab) => (
            <a key={tab.href} href={tab.href} className={styles.tab} aria-current={tab.href === current ? "page" : undefined}>
              {tab.label}
            </a>
          ))}
        </nav>

        <h1 className={styles.title}>{title}</h1>

        <div className={styles.who}>
          <time className={`${styles.clock} num`} suppressHydrationWarning>
            {clock ?? " "}
          </time>
          <span className={styles.user}>{user ?? ""}</span>
          <button type="button" className={styles.logout} onClick={logout} disabled={leaving}>
            {leaving ? "로그아웃 중…" : "로그아웃"}
          </button>
        </div>

        <svg className={styles.frame} viewBox="0 0 1200 28" preserveAspectRatio="none" aria-hidden="true" focusable="false">
          <path d="M0 6 H330 L356 22 H844 L870 6 H1200" />
          <path className={styles.frameFaint} d="M0 12 H318 L344 28 H856 L882 12 H1200" />
        </svg>
      </header>

      <main className={styles.main}>{children}</main>
    </div>
  );
}
