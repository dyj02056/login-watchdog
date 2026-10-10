"use client";

// 대응 묶음 — 잠금 해제, AI 조기 경보 승인, 보안 이벤트·연관 사건 처리, 영구 잠금, 복구 요청, IP 예외.
// 버튼은 권한이 있는 관리자에게만 보인다. 숨김은 편의일 뿐이고 실제 검사는 서버가 요청마다 다시 한다.
import { useState } from "react";
import { formatDateTime, formatTime } from "@/lib/format";
import { actionLabel, eventTypeLabel } from "@/lib/labels";
import { SeverityBadge, Pill } from "../Badge";
import { DataTable } from "../DataTable";
import { useFeedback } from "../Feedback";
import { Panel } from "../Panel";
import { Skeleton } from "../States";
import { post, useOps } from "./OpsContext";
import { ActionButton, PagedPanel } from "./parts";
import styles from "./ops.module.css";

type Lockout = { kind: "ip" | "account" | "admin"; target: string; failure_count: number; unlock_at: string | null };

export function LockSection() {
  const { status, can, run } = useOps();

  const rows: Lockout[] = status
    ? [
        ...status.active_lockouts.filter((l) => l.lock_type !== "PERMANENT").map((l) => ({ kind: "ip" as const, target: l.ip_address ?? "", failure_count: l.failure_count, unlock_at: l.unlock_at })),
        ...status.active_account_lockouts.filter((l) => l.lock_type !== "PERMANENT").map((l) => ({ kind: "account" as const, target: l.username ?? "", failure_count: l.failure_count, unlock_at: l.unlock_at })),
        ...status.active_admin_account_lockouts.map((l) => ({ kind: "admin" as const, target: l.username ?? "", failure_count: l.failure_count, unlock_at: l.unlock_at })),
      ]
    : [];

  const KIND = { ip: "IP 잠금", account: "계정 잠금", admin: "관리자 계정 잠금" };
  const ENDPOINT = { ip: ["/api/unlock", "ip"], account: ["/api/unlock-account", "username"], admin: ["/api/unlock-admin-account", "username"] } as const;

  return (
    <Panel title="현재 잠긴 IP · 계정" flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <DataTable
          caption="현재 잠겨 있는 IP와 계정"
          rows={rows}
          rowKey={(row) => `${row.kind}:${row.target}`}
          empty={{ title: "현재 잠긴 IP·계정이 없습니다." }}
          columns={[
            { header: "종류", cell: (r) => KIND[r.kind] },
            { header: "대상", cell: (r) => r.target, num: true, grow: true },
            { header: "실패", cell: (r) => `${r.failure_count}회`, num: true, align: "right" },
            { header: "해제 예정", cell: (r) => formatTime(r.unlock_at), num: true },
            {
              header: "조치",
              cell: (r) => {
                const allowed = r.kind === "admin" ? can("unlock_admin_account") : can("unlock_ip");
                if (!allowed) return <span className={styles.muted}>{r.kind === "admin" ? "super_admin 전용" : "-"}</span>;
                const [path, field] = ENDPOINT[r.kind];
                return (
                  <ActionButton
                    id={`unlock:${r.kind}:${r.target}`}
                    onClick={() => run(`unlock:${r.kind}:${r.target}`, () => post(path, { [field]: r.target }), `${r.target} 잠금을 해제했습니다.`)}
                  >
                    즉시 해제
                  </ActionButton>
                );
              },
            },
          ]}
        />
      )}
    </Panel>
  );
}

const EARLY_WARNING_LABELS: Record<string, string> = {
  BRUTE_FORCE: "로그인 브루트포스(IP)",
  DISTRIBUTED_BRUTE_FORCE: "계정 단위 분산 브루트포스",
  SIGNUP_RATE_LIMIT: "회원가입 남용",
  WEB_SCANNING: "웹 스캐닝",
  UNAUTHORIZED_ACCESS: "미인증 접근",
  PAGE_ACCESS: "반복 페이지 접근",
  API_MACRO_PATTERN: "매크로/봇 패턴",
  SIEM_HIGH_INCIDENT: "SIEM HIGH 사건 → 영구 잠금",
};

type AccessRequest = { request_id: number; event_type: string; target_value: string; count: number; threshold: number; llm_reason: string; requested_at: string };

export function AccessRequestSection() {
  const { can, run } = useOps();
  const { confirm } = useFeedback();
  const allowed = can("approve_pending_action");
  return (
    <PagedPanel<AccessRequest>
      name="access_requests"
      title="AI 조기 경보 (승인 대기)"
      caption="관리자 승인을 기다리는 AI 조기 경보"
      rowKey={(r) => r.request_id}
      empty={{ title: "대기 중인 AI 조기 경보가 없습니다.", hint: "임계값 직전에서 AI가 위험하다고 판단하면 여기에 올라옵니다." }}
      columns={[
        { header: "요청 시각", cell: (r) => formatTime(r.requested_at), num: true },
        { header: "유형", cell: (r) => EARLY_WARNING_LABELS[r.event_type] ?? r.event_type },
        { header: "대상", cell: (r) => r.target_value, num: true },
        { header: "현재 / 기준", cell: (r) => `${r.count} / ${r.threshold}`, num: true },
        { header: "AI 판단 근거", cell: (r) => <span className={styles.note}>{r.llm_reason}</span>, grow: true },
        {
          header: "조치",
          cell: (r) =>
            allowed ? (
              <span>
                <ActionButton
                  id={`approve:${r.request_id}`}
                  onClick={async () => {
                    const { ok } = await confirm({ title: "이 요청을 승인할까요?", body: "AI가 판단한 조치가 즉시 실행됩니다.", confirmLabel: "승인" });
                    if (ok) await run(`approve:${r.request_id}`, () => post("/api/access-requests/approve", { request_id: r.request_id }), "승인했습니다.");
                  }}
                >
                  승인
                </ActionButton>{" "}
                <ActionButton id={`reject:${r.request_id}`} onClick={() => run(`reject:${r.request_id}`, () => post("/api/access-requests/reject", { request_id: r.request_id }), "반려했습니다.")}>
                  반려
                </ActionButton>
              </span>
            ) : (
              <span className={styles.muted}>-</span>
            ),
        },
      ]}
    />
  );
}

type SecurityEvent = {
  id: number;
  event_type: string;
  severity: string;
  ip_address: string;
  username: string | null;
  path: string | null;
  count: number;
  action: string;
  detected_at: string;
  resolved_at: string | null;
};

export function SecurityEventSection() {
  const { can, run } = useOps();
  return (
    <PagedPanel<SecurityEvent>
      name="security_events"
      title="보안 이벤트"
      caption="위험등급별 보안 이벤트"
      rowKey={(r) => r.id}
      empty={{ title: "보안 이벤트가 없습니다." }}
      columns={[
        { header: "시각", cell: (r) => formatTime(r.detected_at), num: true },
        { header: "등급", cell: (r) => <SeverityBadge severity={r.severity} /> },
        { header: "유형", cell: (r) => eventTypeLabel(r.event_type) },
        { header: "IP", cell: (r) => r.ip_address, num: true },
        { header: "계정", cell: (r) => r.username ?? "-" },
        { header: "경로", cell: (r) => r.path ?? "-", grow: true },
        { header: "횟수", cell: (r) => r.count, num: true, align: "right" },
        { header: "조치", cell: (r) => actionLabel(r.action) },
        {
          header: "상태",
          cell: (r) => {
            if (r.resolved_at) return <span className={styles.good}>처리 완료</span>;
            if (r.severity === "CRITICAL") return <span className={styles.muted}>자동 해제 대기</span>;
            if (!can("resolve_security_event")) return <span className={styles.muted}>-</span>;
            return (
              <ActionButton id={`resolve-event:${r.id}`} onClick={() => run(`resolve-event:${r.id}`, () => post("/api/security-events/resolve", { event_id: r.id }), "처리 완료로 표시했습니다.")}>
                처리 완료
              </ActionButton>
            );
          },
        },
      ]}
    />
  );
}

type Incident = {
  id: number;
  ip_address: string;
  event_types: string[];
  severity_max: string;
  status: "OPEN" | "IDLE" | "CLOSED";
  first_event_at: string;
  last_event_at: string;
  resolved_at: string | null;
  resolved_by: string | null;
};

export function IncidentSection() {
  const { can, run } = useOps();
  const { confirm } = useFeedback();
  return (
    <PagedPanel<Incident>
      name="security_incidents"
      title="연관 사건 (SIEM 상관분석)"
      caption="같은 IP의 서로 다른 유형을 묶은 연관 사건"
      rowKey={(r) => r.id}
      empty={{ title: "연관된 사건이 없습니다.", hint: "같은 IP가 짧은 시간에 서로 다른 유형을 2가지 이상 남기면 묶입니다." }}
      columns={[
        { header: "시작", cell: (r) => formatTime(r.first_event_at), num: true },
        { header: "마지막 활동", cell: (r) => formatTime(r.last_event_at), num: true },
        { header: "등급", cell: (r) => <SeverityBadge severity={r.severity_max} /> },
        { header: "관련 유형", cell: (r) => r.event_types.map(eventTypeLabel).join(", "), grow: true },
        { header: "IP", cell: (r) => r.ip_address, num: true },
        { header: "상태", cell: (r) => (r.status === "CLOSED" ? <span className={styles.good}>해결됨</span> : r.status === "IDLE" ? <span className={styles.muted}>활동 없음</span> : <span className={styles.bad}>진행 중</span>) },
        {
          header: "처리",
          cell: (r) => {
            if (r.status === "CLOSED") return r.resolved_by ? <span className="num">{r.resolved_by} · {formatTime(r.resolved_at)}</span> : "-";
            if (!can("resolve_incident")) return <span className={styles.muted}>-</span>;
            return (
              <ActionButton
                id={`resolve-incident:${r.id}`}
                onClick={async () => {
                  const { ok } = await confirm({ title: "이 사건을 해결됨으로 표시할까요?", body: "해결한 사건은 되돌릴 수 없습니다.", confirmLabel: "해결" });
                  if (ok) await run(`resolve-incident:${r.id}`, () => post("/api/security-incidents/resolve", { incident_id: r.id }), "사건을 해결했습니다.");
                }}
              >
                해결
              </ActionButton>
            );
          },
        },
      ]}
    />
  );
}

const PERMANENT_REASON: Record<string, string> = {
  REPEAT_OFFENDER: "반복 위반",
  SIEM_CRITICAL: "SIEM CRITICAL 사건",
  SIEM_HIGH: "SIEM HIGH 사건",
  NETWORK_IDS: "네트워크 침입 탐지",
  ADMIN_MANUAL: "관리자 수동 승격",
};
const RECOVERABLE: Record<string, string> = {
  SELF: "이메일 인증으로 해제",
  EXEMPTION: "이메일 인증 시 본인 기기 예외",
  ADMIN_ONLY: "관리자만 해제",
};

export function PermanentLockSection() {
  const { status, can, run } = useOps();
  const { confirm } = useFeedback();
  const [kind, setKind] = useState<"ip" | "account">("ip");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");

  const locks = status?.permanent_locks ?? [];

  async function promote(event: React.FormEvent) {
    event.preventDefault();
    const label = kind === "ip" ? "IP" : "계정";
    const { ok } = await confirm({ title: `${label} "${target}"을(를) 영구 잠금할까요?`, body: "관리자만 풀 수 있게 됩니다.", confirmLabel: "영구 잠금", danger: true });
    if (!ok) return;
    const done = await run("promote", () => post("/api/permanent-locks/promote", { target_kind: kind, target_value: target, reason }), "영구 잠금을 걸었습니다.");
    if (done) {
      setTarget("");
      setReason("");
    }
  }

  return (
    <Panel title="영구 잠금" flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <DataTable
          caption="영구 잠금된 IP와 계정"
          rows={locks}
          rowKey={(r) => `${r.kind}:${r.target}`}
          empty={{ title: "영구 잠금된 IP·계정이 없습니다." }}
          columns={[
            { header: "종류", cell: (r) => (<><Pill tone="danger">영구</Pill> {r.kind === "ip" ? "IP" : "계정"}</>) },
            { header: "대상", cell: (r) => r.target, num: true },
            { header: "사유", cell: (r) => PERMANENT_REASON[r.permanent_reason ?? ""] ?? r.permanent_reason ?? "-" },
            {
              header: "해제 방법",
              cell: (r) => (
                <>
                  {RECOVERABLE[r.recoverable ?? ""] ?? r.recoverable ?? "-"} {r.email_status === "UNDELIVERABLE" ? <Pill tone="warn">이메일 확인 불가</Pill> : null}
                </>
              ),
              grow: true,
            },
            { header: "승격 시각", cell: (r) => formatDateTime(r.promoted_at ?? r.locked_at), num: true },
            {
              header: "조치",
              cell: (r) =>
                can("release_permanent_lock") ? (
                  <ActionButton
                    id={`release:${r.kind}:${r.target}`}
                    onClick={async () => {
                      const { ok, note } = await confirm({
                        title: `${r.kind === "ip" ? "IP" : "계정"} "${r.target}"의 영구 잠금을 해제합니다`,
                        noteLabel: "해제 사유",
                        confirmLabel: "영구 해제",
                        danger: true,
                      });
                      if (ok) await run(`release:${r.kind}:${r.target}`, () => post("/api/permanent-locks/release", { target_kind: r.kind, target_value: r.target, note }), "영구 잠금을 해제했습니다.");
                    }}
                  >
                    영구 해제
                  </ActionButton>
                ) : (
                  <span className={styles.muted}>super_admin 전용</span>
                ),
            },
          ]}
        />
      )}
      {can("promote_permanent_lock") ? (
        <form className={styles.formRow} onSubmit={promote}>
          <div className={`field ${styles.narrow}`}>
            <label htmlFor="pl-kind">대상 종류</label>
            <select id="pl-kind" className="select" value={kind} onChange={(e) => setKind(e.target.value as "ip" | "account")}>
              <option value="ip">IP</option>
              <option value="account">계정</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="pl-target">IP 주소 또는 아이디</label>
            <input id="pl-target" className="input" value={target} onChange={(e) => setTarget(e.target.value)} required />
          </div>
          <div className="field">
            <label htmlFor="pl-reason">승격 사유</label>
            <input id="pl-reason" className="input" value={reason} onChange={(e) => setReason(e.target.value)} required />
          </div>
          <button type="submit" className="btn-danger">
            영구 잠금 걸기
          </button>
        </form>
      ) : null}
    </Panel>
  );
}

type RecoveryRequest = { id: number; created_at: string; username: string | null; target_kind: string; target_value: string; requested_ip: string; status: string };
const RECOVERY_STATUS: Record<string, string> = { PENDING: "진행 중", VERIFIED: "완료", EXPIRED: "만료", REVOKED: "취소됨" };

export function RecoverySection() {
  const { status, can, run } = useOps();
  const { confirm } = useFeedback();
  return (
    <Panel title="복구 요청" flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <DataTable
          caption="이메일 본인 인증 복구 요청"
          rows={status.recovery_requests as RecoveryRequest[]}
          rowKey={(r) => r.id}
          empty={{ title: "복구 요청이 없습니다." }}
          columns={[
            { header: "요청 시각", cell: (r) => formatDateTime(r.created_at), num: true },
            { header: "계정", cell: (r) => r.username ?? "-" },
            { header: "대상", cell: (r) => `${r.target_kind === "ip" ? "IP" : "계정"} ${r.target_value}`, grow: true },
            { header: "요청 IP", cell: (r) => r.requested_ip, num: true },
            { header: "상태", cell: (r) => RECOVERY_STATUS[r.status] ?? r.status },
            {
              header: "조치",
              cell: (r) =>
                r.status === "PENDING" && can("revoke_recovery_request") ? (
                  <ActionButton
                    id={`revoke-recovery:${r.id}`}
                    onClick={async () => {
                      const { ok } = await confirm({ title: "이 복구 요청을 취소할까요?", body: "이미 발송된 메일의 링크와 코드는 더 이상 쓸 수 없게 됩니다.", confirmLabel: "요청 취소", danger: true });
                      if (ok) await run(`revoke-recovery:${r.id}`, () => post("/api/recovery-requests/revoke", { id: r.id }), "복구 요청을 취소했습니다.");
                    }}
                  >
                    취소
                  </ActionButton>
                ) : (
                  "-"
                ),
            },
          ]}
        />
      )}
    </Panel>
  );
}

type Exemption = { id: number; granted_at: string; ip_address: string; username: string | null; expires_at: string };

export function ExemptionSection() {
  const { status, can, run } = useOps();
  const { confirm } = useFeedback();
  return (
    <Panel title="IP 예외" flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <DataTable
          caption="본인 인증으로 발급된 IP 예외"
          rows={status.ip_exemptions as Exemption[]}
          rowKey={(r) => r.id}
          empty={{ title: "발급된 IP 예외가 없습니다." }}
          columns={[
            { header: "발급 시각", cell: (r) => formatDateTime(r.granted_at), num: true },
            { header: "IP", cell: (r) => r.ip_address, num: true, grow: true },
            { header: "계정", cell: (r) => r.username ?? "-" },
            { header: "만료", cell: (r) => formatDateTime(r.expires_at), num: true },
            {
              header: "조치",
              cell: (r) =>
                can("revoke_ip_exemption") ? (
                  <ActionButton
                    id={`revoke-exemption:${r.id}`}
                    onClick={async () => {
                      const { ok } = await confirm({ title: "이 IP 예외를 회수할까요?", body: "해당 사용자는 다시 이메일 인증을 해야 합니다.", confirmLabel: "회수", danger: true });
                      if (ok) await run(`revoke-exemption:${r.id}`, () => post("/api/ip-exemptions/revoke", { id: r.id }), "예외를 회수했습니다.");
                    }}
                  >
                    회수
                  </ActionButton>
                ) : (
                  "-"
                ),
            },
          ]}
        />
      )}
    </Panel>
  );
}
