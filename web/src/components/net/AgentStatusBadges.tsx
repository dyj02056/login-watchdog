"use client";

// AgentStatusBadges — 이 PC의 네트워크 장비(fw-agent·shipper)가 살아 있는지 보여 주는 배지 줄(계약서 K10 agent_status).
// "정지"는 서버(C2-3)가 생존 신호 시각과 기준(FW_AGENT_STALE_SECONDS·SHIPPER_STALE_SECONDS)으로 판단해 준 값을 그대로 쓴다.
// 화면에서 다시 계산하지 않는 이유: 기준 초가 서버 설정에 있고, 정지 Slack 알림도 서버가 같은 판단으로 보내기 때문이다.
import { formatShortDateTime } from "@/lib/format";
import type { AgentName, AgentStatus } from "@/lib/types";
import { Pill } from "../Badge";
import styles from "./net.module.css";

const AGENTS: { name: AgentName; label: string }[] = [
  { name: "fw-agent", label: "차단 프로그램 fw-agent" },
  { name: "shipper", label: "배달원 shipper" },
];

export function AgentStatusBadges({ status }: { status: AgentStatus | undefined }) {
  // {}이면 LW_NODE_NAME이 없는 환경(예: Vercel)이라 서버가 장비를 감시하지 않는다.
  // 칸 자체가 없으면(C2-3 머지 전 응답) 역시 감시 정보가 없으므로 같은 문구를 보여 준다.
  if (!status || Object.keys(status).length === 0) {
    return <p className={styles.agentNote}>이 환경에서는 네트워크 장비를 감시하지 않습니다.</p>;
  }
  return (
    <ul className={styles.agents} aria-label="네트워크 장비 상태">
      {AGENTS.map(({ name, label }) => {
        const beat = status[name];
        // 기록이 아예 없으면 서버가 stale=true로 준다. 화면에서는 "정지"와 "신호 없음"을 나눠 원인을 짐작하기 쉽게 한다.
        const seen = beat?.last_seen_at ?? null;
        const stale = beat ? beat.stale : true;
        return (
          <li key={name} className={styles.agent}>
            <span className={styles.agentName}>{label}</span>
            <Pill tone={stale ? "danger" : "ok"}>{stale ? (seen ? "정지" : "신호 없음") : "정상"}</Pill>
            <span className={`${styles.agentSeen} num`}>{seen ? `마지막 신호 ${formatShortDateTime(seen, true)}` : "마지막 신호 없음"}</span>
          </li>
        );
      })}
    </ul>
  );
}
