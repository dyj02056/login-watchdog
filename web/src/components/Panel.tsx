import type { ReactNode } from "react";
import styles from "./Panel.module.css";

type Props = {
  title: string;
  /** 제목 오른쪽에 붙는 범례·건수·필터 */
  meta?: ReactNode;
  children: ReactNode;
  className?: string;
  /** 본문 안쪽 여백을 없앤다(표·차트가 가장자리까지 차게) */
  flush?: boolean;
  as?: "section" | "div";
};

export function Panel({ title, meta, children, className, flush, as: Tag = "section" }: Props) {
  return (
    <Tag className={`${styles.panel} ${className ?? ""}`}>
      <header className={styles.head}>
        <h2 className={styles.title}>{title}</h2>
        {meta ? <div className={styles.meta}>{meta}</div> : null}
      </header>
      <div className={flush ? styles.bodyFlush : styles.body}>{children}</div>
    </Tag>
  );
}

export type Tone = "today" | "yesterday" | "week" | "cyan" | "critical" | "high" | "medium" | "ok";

/** 범례 — 색 점 + 이름. 색은 의미 이름(tone)으로만 고른다(인라인 style은 CSP가 막는다). */
export function Legend({ items }: { items: { label: string; tone: Tone; dashed?: boolean }[] }) {
  return (
    <ul className={styles.legend}>
      {items.map((item) => (
        <li key={item.label}>
          <span className={`${item.dashed ? styles.swatchDashed : styles.swatch} ${styles[item.tone]}`} aria-hidden="true" />
          {item.label}
        </li>
      ))}
    </ul>
  );
}
