import { formatCount } from "@/lib/format";
import type { Stats } from "@/lib/types";
import styles from "./KpiStrip.module.css";

type Cell = { label: string; value: number; note: string; alert?: boolean };

/** 한눈에 봐야 하는 여섯 숫자와 7일 위험등급 분포. 카드가 아니라 구분선으로 나눈 한 줄이다. */
export function KpiStrip({ kpi }: { kpi: Stats["kpi"] | null }) {
  const cells: Cell[] | null = kpi && [
    { label: "오늘 탐지", value: kpi.events_today, note: `어제 ${formatCount(kpi.events_yesterday)}건` },
    { label: "로그인 실패", value: kpi.failed_logins_today, note: "오늘 누적" },
    { label: "자동 차단", value: kpi.blocked_today, note: "잠금·요청 거부" },
    { label: "현재 잠금", value: kpi.active_locks, note: "IP·계정" },
    { label: "미처리 critical", value: kpi.unresolved_critical, note: `전체 미처리 ${formatCount(kpi.unresolved_total)}건`, alert: kpi.unresolved_critical > 0 },
    { label: "AI 승인 대기", value: kpi.pending_ai, note: "조기 경보", alert: kpi.pending_ai > 0 },
  ];
  const severity = kpi?.severity_7d;
  const total = severity ? Math.max(1, severity.CRITICAL + severity.HIGH + severity.MEDIUM) : 1;

  return (
    <div className={styles.strip} aria-busy={kpi === null}>
      {(cells ?? Array.from({ length: 6 }, () => null)).map((cell, index) => (
        <div className={styles.cell} key={cell?.label ?? index}>
          <span className={styles.label}>{cell?.label ?? " "}</span>
          <span className={`${styles.value} num ${cell?.alert ? styles.alert : ""}`}>{cell ? formatCount(cell.value) : "–"}</span>
          <span className={styles.note}>{cell?.note ?? " "}</span>
        </div>
      ))}

      <div className={`${styles.cell} ${styles.mix}`}>
        <span className={styles.label}>7일 위험등급</span>
        <svg className={styles.bar} viewBox="0 0 100 6" preserveAspectRatio="none" role="img" aria-label={severity ? `critical ${severity.CRITICAL}, high ${severity.HIGH}, medium ${severity.MEDIUM}` : "집계 중"}>
          <rect className={styles.track} x="0" y="0" width="100" height="6" />
          {severity ? (
            <>
              <rect className={styles.critical} x="0" y="0" width={(severity.CRITICAL / total) * 100} height="6" />
              <rect className={styles.high} x={(severity.CRITICAL / total) * 100} y="0" width={(severity.HIGH / total) * 100} height="6" />
              <rect className={styles.medium} x={((severity.CRITICAL + severity.HIGH) / total) * 100} y="0" width={(severity.MEDIUM / total) * 100} height="6" />
            </>
          ) : null}
        </svg>
        <span className={`${styles.note} num`}>
          {severity ? `critical ${severity.CRITICAL} · high ${severity.HIGH} · medium ${severity.MEDIUM}` : " "}
        </span>
      </div>
    </div>
  );
}
