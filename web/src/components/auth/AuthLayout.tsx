import type { ReactNode } from "react";
import styles from "./auth.module.css";

type Props = {
  title: string;
  /** 제목 아래 설명 한두 문장 */
  lead?: ReactNode;
  children: ReactNode;
  /** 폼 아래 보조 링크 */
  links?: { href: string; label: string }[];
};

/** 비로그인 화면(로그인·가입·복구 등) 공통 틀. 로고와 폼 카드를 화면 가운데에 세로로 둔다. */
export function AuthLayout({ title, lead, children, links }: Props) {
  return (
    <main className={styles.page}>
      <div className={styles.stack}>
        <div className={styles.logo}>
          <svg className={styles.mark} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
            <path d="M16 3 5 8v8c0 6 4.2 10.6 11 13 6.8-2.4 11-7 11-13V8z" />
            <path d="m11 16 3.6 3.6L21.5 12.4" />
          </svg>
          <p className={styles.name}>로그인 워치독</p>
        </div>

        <div className={styles.card}>
          <h1 className={styles.title}>{title}</h1>
          {lead ? <p className={styles.lead}>{lead}</p> : null}
          {children}
          {links?.length ? (
            <nav className={styles.links} aria-label="관련 화면">
              {links.map((link) => (
                <a key={link.href} href={link.href}>
                  {link.label}
                </a>
              ))}
            </nav>
          ) : null}
        </div>
      </div>
    </main>
  );
}

/** 서버가 flash로 돌려준 문장. 오류 상태(4xx)면 붉은 테두리로 */
export function Notice({ messages, error }: { messages: string[]; error?: boolean }) {
  if (messages.length === 0) return null;
  return (
    <ul className={`notice ${error ? "notice-error" : ""}`} role={error ? "alert" : "status"}>
      {messages.map((message, index) => (
        <li key={`${index}-${message}`}>{message}</li>
      ))}
    </ul>
  );
}

/** 사람에게는 보이지 않는 허니팟 칸 — 봇만 채운다(helpers.is_bot_submission). 값은 postForm이 빈 문자열로 보낸다. */
export function Honeypot() {
  return (
    <div className="hp-field" aria-hidden="true">
      <label htmlFor="website">웹사이트</label>
      <input type="text" id="website" name="website" tabIndex={-1} autoComplete="off" />
    </div>
  );
}
