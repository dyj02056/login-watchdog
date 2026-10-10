"use client";

// DashboardView — 화면 A "위협 현황". /api/stats 한 번으로 KPI·차트·표 네 개를 그린다.
import { apiJson } from "@/lib/api";
import { formatDateTime, formatTime } from "@/lib/format";
import { eventTypeLabel } from "@/lib/labels";
import type { Stats } from "@/lib/types";
import { usePolling } from "@/lib/usePolling";
import { AdminShell } from "./AdminShell";
import { Pill, SeverityBadge } from "./Badge";
import { DailyVolume, FlowChart, HourlyTrend, IpHeatmap } from "./charts";
import { DataTable } from "./DataTable";
import { KpiStrip } from "./KpiStrip";
import { Legend, Panel } from "./Panel";
import { EmptyState, ErrorState, Skeleton } from "./States";
import styles from "./DashboardView.module.css";

const POLL_MS = 30_000;

const LOCK_KIND = { ip: "IP", account: "회원", admin: "관리자" } as const;
// OPEN은 지금도 진행 중, IDLE은 이벤트가 끊겼는데 "해결"이 눌리지 않은 것, 자동 종료는 시스템이 닫은 것.
const INCIDENT_STATUS = { OPEN: "미처리", IDLE: "방치", CLOSED: "종료" } as const;
const INCIDENT_TONE = { OPEN: "danger", IDLE: "warn", CLOSED: "neutral" } as const;

export function DashboardView() {
  const { data, error, loading, updatedAt, refresh } = usePolling<Stats>(async () => {
    const result = await apiJson<Stats>("/api/stats");
    return { data: result.ok ? result.data : null, error: result.error };
  }, POLL_MS);

  const body = (render: (stats: Stats) => React.ReactNode, lines = 5) => {
    if (data) return render(data);
    if (error && !loading) return <ErrorState message={error} onRetry={refresh} />;
    return <Skeleton lines={lines} />;
  };

  return (
    <AdminShell title="로그인 워치독 위협 현황" current="/admin/dashboard">
      <div className={styles.grid}>
        <div className={styles.kpi}>
          <KpiStrip kpi={data?.kpi ?? null} />
          {error && data ? <p className={styles.stale}>갱신 실패 — {formatTime(new Date(updatedAt ?? 0).toISOString())} 기준 값을 보여주는 중입니다.</p> : null}
        </div>

        <Panel
          className={styles.trend}
          title="시간대별 탐지 추이"
          meta={
            <Legend
              items={[
                { label: "오늘", tone: "today" },
                { label: "어제", tone: "yesterday" },
                { label: "지난주 같은 요일", tone: "week", dashed: true },
              ]}
            />
          }
        >
          {body((s) => (
            <HourlyTrend hourly={s.hourly} />
          ), 7)}
        </Panel>

        <Panel
          className={styles.volume}
          title="최근 7일 로그 발생"
          meta={data && !data.summary_available ? <span>일별 요약 전 — 오늘 값만 있음</span> : undefined}
        >
          {body((s) => (
            <DailyVolume volume={s.log_volume} />
          ), 7)}
        </Panel>

        <Panel className={styles.heat} title="최근 7일 공격자 IP 활동">
          {body((s) =>
            s.heatmap.ips.length ? (
              <IpHeatmap heatmap={s.heatmap} />
            ) : (
              <EmptyState title="최근 7일간 기록된 공격자 이벤트가 없습니다." hint="보안 이벤트가 쌓이면 IP별·날짜별 건수가 여기에 나타납니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.flow} title="공격 흐름 (IP → 유형 → 조치)">
          {body((s) =>
            s.flow.links.length ? (
              <FlowChart links={s.flow.links} sourceLabel="공격자 IP" />
            ) : (
              <EmptyState title="표시할 공격 흐름이 없습니다." hint="최근 7일 보안 이벤트가 있으면 IP가 어떤 유형으로 이어져 어떤 조치를 받았는지 보여줍니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.newIps} title="최근 7일 신규 공격자" flush>
          {body((s) => (
            <DataTable
              caption="최근 7일 처음 나타난 공격자"
              rows={s.new_attackers}
              rowKey={(row) => row.ip}
              empty={{ title: "새로 나타난 공격자가 없습니다." }}
              columns={[
                { header: "공격자 IP", cell: (r) => r.ip, num: true },
                { header: "국가", cell: (r) => r.country ?? "-" },
                { header: "건수", cell: (r) => r.count, num: true, align: "right" },
              ]}
            />
          ))}
        </Panel>

        <Panel
          className={styles.locks}
          title="잠금 현황 (현재 · 영구)"
          flush
          meta={data ? <span>{data.locks_total}건 · 영구 {data.locks_permanent}건</span> : undefined}
        >
          {body((s) => (
            <DataTable
              caption="현재 잠긴 IP·계정과 영구 잠금"
              rows={s.locks}
              rowKey={(row) => `${row.kind}-${row.target}`}
              empty={{ title: "잠긴 IP·계정이 없습니다." }}
              columns={[
                { header: "대상", cell: (r) => r.target, num: true, grow: true },
                { header: "구분", cell: (r) => LOCK_KIND[r.kind] },
                { header: "상태", cell: (r) => <Pill tone={r.permanent ? "danger" : "warn"}>{r.permanent ? "영구" : "임시"}</Pill> },
                { header: "잠긴 시각", cell: (r) => (r.locked_at ? formatDateTime(r.locked_at).slice(5, 16) : "-"), num: true },
              ]}
            />
          ))}
        </Panel>

        <Panel className={styles.open} title="미처리 보안 이벤트" flush>
          {body((s) => (
            <DataTable
              caption="아직 처리되지 않은 보안 이벤트"
              rows={s.unresolved}
              rowKey={(row) => row.id}
              empty={{ title: "처리를 기다리는 이벤트가 없습니다." }}
              columns={[
                { header: "등급", cell: (r) => <SeverityBadge severity={r.severity} /> },
                { header: "유형", cell: (r) => eventTypeLabel(r.event_type), grow: true },
                { header: "IP", cell: (r) => r.ip, num: true },
                { header: "탐지 시각", cell: (r) => formatDateTime(r.detected_at).slice(5), num: true },
              ]}
            />
          ))}
        </Panel>

        <Panel
          className={styles.compound}
          title="연관 사건 (미처리 · 방치)"
          flush
          meta={data ? <span>{data.open_incidents_total}건</span> : undefined}
        >
          {body((s) => (
            <DataTable
              caption="해결 처리가 되지 않은 연관 사건"
              rows={s.open_incidents}
              rowKey={(row) => row.id}
              empty={{ title: "미처리 연관 사건이 없습니다.", hint: "같은 IP에서 여러 유형이 이어진 사건 중 해결되지 않은 것이 표시됩니다." }}
              columns={[
                { header: "IP", cell: (r) => r.ip, num: true },
                { header: "등급", cell: (r) => <SeverityBadge severity={r.severity} /> },
                { header: "상태", cell: (r) => <Pill tone={INCIDENT_TONE[r.status]}>{r.auto_closed ? "자동 종료" : INCIDENT_STATUS[r.status]}</Pill> },
              ]}
            />
          ))}
        </Panel>
      </div>
    </AdminShell>
  );
}
