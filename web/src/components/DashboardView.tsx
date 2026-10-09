"use client";

// DashboardView — 화면 A "위협 현황". /api/stats 한 번으로 KPI·차트·표 네 개를 그린다.
import { apiJson } from "@/lib/api";
import { formatDateTime, formatTime } from "@/lib/format";
import { eventTypeLabel } from "@/lib/labels";
import type { Stats } from "@/lib/types";
import { usePolling } from "@/lib/usePolling";
import { AdminShell } from "./AdminShell";
import { SeverityBadge } from "./Badge";
import { DailyVolume, FlowChart, HourlyTrend, IpHeatmap } from "./charts";
import { DataTable } from "./DataTable";
import { KpiStrip } from "./KpiStrip";
import { Legend, Panel } from "./Panel";
import { EmptyState, ErrorState, Skeleton } from "./States";
import styles from "./DashboardView.module.css";

const POLL_MS = 30_000;

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

        <Panel className={styles.repeat} title="지속 공격자 (3일 이상)" flush>
          {body((s) => (
            <DataTable
              caption="최근 7일 중 3일 이상 탐지된 공격자"
              rows={s.repeat_attackers}
              rowKey={(row) => row.ip}
              empty={{ title: "3일 이상 이어진 공격자가 없습니다." }}
              columns={[
                { header: "공격자 IP", cell: (r) => r.ip, num: true },
                { header: "일수", cell: (r) => `${r.days}일`, num: true, align: "right" },
                { header: "건수", cell: (r) => r.count, num: true, align: "right" },
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

        <Panel className={styles.compound} title="복합 공격" flush>
          {body((s) => (
            <DataTable
              caption="서로 다른 공격 유형이 3개 이상 겹친 IP"
              rows={s.compound}
              rowKey={(row) => `${row.ip}-${row.last_event_at}`}
              empty={{ title: "복합 공격이 없습니다.", hint: "한 IP에서 3가지 이상 유형이 겹치면 표시됩니다." }}
              columns={[
                { header: "IP", cell: (r) => r.ip, num: true },
                { header: "유형", cell: (r) => `${r.type_count}종`, num: true, align: "right" },
                { header: "등급", cell: (r) => <SeverityBadge severity={r.severity} /> },
              ]}
            />
          ))}
        </Panel>
      </div>
    </AdminShell>
  );
}
