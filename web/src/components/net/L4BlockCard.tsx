"use client";

// L4BlockCard — 관제 화면 축소판(I2-1)의 "L4 차단 목록" 카드. 계약서 K10의 network_blocks를 보여 준다.
// 데이터는 처리 작업대가 이미 5초마다 받는 /api/status에서 꺼내 쓴다(새 요청을 만들지 않는다).
// 차단을 직접 걸거나 푸는 버튼은 없다. 앱은 network_blocks에 "원하는 상태"를 적기만 하고 실제 차단은 fw-agent가 하므로,
// 이 카드는 그 장부를 읽어 보여 주는 창이다. 해제 버튼은 선택 과제(01 공통 규칙 7.6)라 이번 범위 밖이다.
import { formatShortDateTime } from "@/lib/format";
import type { NetworkBlock, NetworkBlockStatus } from "@/lib/types";
import { Pill } from "../Badge";
import { DataTable } from "../DataTable";
import { Panel } from "../Panel";
import { Skeleton } from "../States";
import { useOps } from "../ops/OpsContext";
import { AgentStatusBadges } from "./AgentStatusBadges";
import styles from "./net.module.css";

// 상태 배지 — 색만으로 구분하지 않도록 글자를 함께 쓴다.
const STATUS: Record<NetworkBlockStatus, { label: string; tone: "neutral" | "ok" | "warn" | "danger" }> = {
  PENDING_APPLY: { label: "적용 대기", tone: "warn" },
  APPLIED: { label: "차단 중", tone: "danger" },
  PENDING_REMOVE: { label: "해제 대기", tone: "neutral" },
  REMOVED: { label: "해제됨", tone: "ok" },
  FAILED: { label: "실패", tone: "danger" },
};

// 계약서 K12의 network_blocks.reason 값
const REASON: Record<string, string> = {
  NET_FLOOD: "네트워크 폭주",
  KILL_CHAIN: "킬체인",
  ADMIN_MANUAL: "관리자 수동",
};

// 증거 종류를 쉬운 말로. SPOOFABLE(위조 가능)은 짧은 시간 제한 차단만, CONNECTED(연결 완성)만 영구 차단이 될 수 있다(설계 원칙 P2).
const EVIDENCE: Record<NetworkBlock["evidence"], string> = {
  SPOOFABLE: "위조 가능 · 시간 제한",
  CONNECTED: "연결 완성 · 영구 가능",
};

/** 남은 시간: 영구면 "영구", 지났으면 "만료(정리 대기)", 아니면 "1시간 12분" 꼴 */
export function remainingText(expiresAt: string | null, now: number): string {
  if (!expiresAt) return "영구";
  const end = new Date(expiresAt).getTime();
  if (Number.isNaN(end)) return "-";
  const seconds = Math.ceil((end - now) / 1000);
  // 만료된 행은 fw-agent가 다음 목록을 받아 갈 때 서버가 REMOVED로 바꾼다(K9 ① 지연 만료). 그 사이에만 보인다.
  if (seconds <= 0) return "만료(정리 대기)";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}시간 ${m}분`;
  if (m > 0) return `${m}분`;
  return `${seconds}초`;
}

export function L4BlockCard() {
  const { status } = useOps();
  const rows = status?.network_blocks ?? [];
  const now = Date.now();
  const active = rows.filter((r) => r.status === "APPLIED").length;

  return (
    <Panel title="L4 차단 목록 (정문 방화벽)" meta={status ? <span className={`${styles.count} num`}>차단 중 {active}건</span> : null} flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <>
          <div className={styles.agentBar}>
            <AgentStatusBadges status={status.agent_status} />
          </div>
          <DataTable<NetworkBlock>
            caption="gateway에서 L4로 막고 있거나 막으려는 IP 목록"
            rows={rows}
            rowKey={(r) => r.ip}
            empty={{ title: "현재 L4 차단 없음", hint: "네트워크 경보로 차단이 요청되면 여기에 나타납니다. 최근 24시간 안에 해제된 차단도 함께 보입니다." }}
            columns={[
              { header: "IP", cell: (r) => r.ip, num: true },
              { header: "사유", cell: (r) => REASON[r.reason] ?? r.reason },
              { header: "증거", cell: (r) => <span title={r.evidence}>{EVIDENCE[r.evidence] ?? r.evidence}</span> },
              { header: "상태", cell: (r) => <Pill tone={STATUS[r.status]?.tone ?? "neutral"}>{STATUS[r.status]?.label ?? r.status}</Pill> },
              { header: "남은 시간", cell: (r) => (r.status === "REMOVED" ? "-" : remainingText(r.expires_at, now)), num: true },
              { header: "적용 시각", cell: (r) => formatShortDateTime(r.applied_at, true), num: true },
              { header: "요청자", cell: (r) => <span className={styles.mono}>{r.requested_by}</span> },
              {
                header: "마지막 오류",
                cell: (r) => (r.last_error ? <span className={styles.error}>{r.last_error}</span> : <span className={styles.muted}>-</span>),
                wrap: true,
                maxWidth: "18rem",
                grow: true,
              },
            ]}
          />
        </>
      )}
    </Panel>
  );
}
