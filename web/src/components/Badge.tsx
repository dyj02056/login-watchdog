import type { ReactNode } from "react";
import { severityLabel } from "@/lib/format";
import styles from "./Badge.module.css";

/** 위험 등급 배지. 색만으로 구분하지 않도록 글자(critical/high/medium)를 함께 쓴다. */
export function SeverityBadge({ severity }: { severity: string }) {
  const tone = severity.toLowerCase();
  return <span className={`${styles.badge} ${styles[tone] ?? ""}`}>{severityLabel(severity)}</span>;
}

export function Pill({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "ok" | "warn" | "danger" }) {
  return <span className={`${styles.badge} ${styles[tone]}`}>{children}</span>;
}
