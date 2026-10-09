"use client";

// AttackView — 화면 B "공격 상세 모니터링". 시간대별 탐지, 국가 흐름, 출발지·유형·경로 Top 5, 실시간 이벤트.
import { apiJson } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { actionLabel, eventTypeLabel } from "@/lib/labels";
import type { Stats } from "@/lib/types";
import { usePolling } from "@/lib/usePolling";
import { AdminShell } from "./AdminShell";
import { SeverityBadge } from "./Badge";
import { FlowChart, HourlyMixed, PathDonut, TopBars } from "./charts";
import { DataTable } from "./DataTable";
import { Legend, Panel } from "./Panel";
import { EmptyState, ErrorState, Skeleton } from "./States";
import styles from "./AttackView.module.css";

const POLL_MS = 15_000;

export function AttackView() {
  const { data, error, loading, refresh } = usePolling<Stats>(async () => {
    const result = await apiJson<Stats>("/api/stats");
    return { data: result.ok ? result.data : null, error: result.error };
  }, POLL_MS);

  const body = (render: (stats: Stats) => React.ReactNode, lines = 5) => {
    if (data) return render(data);
    if (error && !loading) return <ErrorState message={error} onRetry={refresh} />;
    return <Skeleton lines={lines} />;
  };

  return (
    <AdminShell title="공격 상세 모니터링" current="/admin/attack">
      <div className={styles.grid}>
        <Panel
          className={styles.hourly}
          title="시간대별 탐지량"
          meta={
            <Legend
              items={[
                { label: "오늘", tone: "today" },
                { label: "어제", tone: "yesterday" },
                { label: "지난주", tone: "week", dashed: true },
              ]}
            />
          }
        >
          {body((s) => (
            <HourlyMixed hourly={s.hourly} />
          ), 7)}
        </Panel>

        <Panel className={styles.network} title="네트워크 계층 (L3/L4) 탐지">
          {body((s) =>
            s.network_layer.length === 0 ? (
              <EmptyState
                title="수집 전입니다."
                hint="SYN 플러드·포트 스캔 같은 L3/L4 공격은 네트워크 센서가 연동되면 이 칸에 나타납니다. 지금 보이는 모든 숫자는 애플리케이션 계층(L7) 기록입니다."
              />
            ) : null,
          )}
        </Panel>

        <Panel className={styles.country} title="공격 국가별 흐름 (국가 → 유형)">
          {body((s) =>
            s.country_flow.links.length ? (
              <FlowChart links={s.country_flow.links} sourceLabel="국가" />
            ) : (
              <EmptyState title="표시할 흐름이 없습니다." hint="최근 7일 보안 이벤트가 있고 IP 위치가 조회된 경우에 국가별로 묶입니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.sources} title="출발지 IP Top 5">
          {body((s) =>
            s.top_sources.length ? (
              <TopBars items={s.top_sources} tone="cyan" label="이벤트가 가장 많은 출발지 IP 다섯 개" />
            ) : (
              <EmptyState title="기록이 없습니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.types} title="공격 유형 Top 5">
          {body((s) =>
            s.top_types.length ? (
              <TopBars items={s.top_types} tone="pink" format={eventTypeLabel} label="가장 많이 발생한 공격 유형 다섯 개" />
            ) : (
              <EmptyState title="기록이 없습니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.paths} title="대상 경로 (미확인 포함) 비중">
          {body((s) =>
            s.top_paths.length || s.pathless_total ? (
              <PathDonut items={s.top_paths} pathless={s.pathless_types} pathlessTotal={s.pathless_total} />
            ) : (
              <EmptyState title="기록이 없습니다." />
            ),
          )}
        </Panel>

        <Panel className={styles.events} title="최근 보안 이벤트" meta={data ? <span className="num">{data.events.length}건</span> : undefined} flush>
          {body((s) => (
            <div className={styles.scroll}>
              <DataTable
                caption="최근 보안 이벤트 30건"
                rows={s.events}
                rowKey={(r) => r.id}
                alignTop
                empty={{ title: "보안 이벤트가 없습니다." }}
                columns={[
                  { header: "발생 시각", cell: (r) => formatDateTime(r.detected_at), num: true },
                  { header: "등급", cell: (r) => <SeverityBadge severity={r.severity} /> },
                  { header: "유형", cell: (r) => eventTypeLabel(r.event_type), wrap: true, maxWidth: "9rem" },
                  { header: "출발지 IP", cell: (r) => r.ip, num: true },
                  { header: "국가", cell: (r) => r.country ?? "-" },
                  { header: "대상 경로", cell: (r) => r.path ?? "-", wrap: true, maxWidth: "13rem" },
                  { header: "건수", cell: (r) => r.count, num: true, align: "right" },
                  { header: "조치", cell: (r) => actionLabel(r.action), wrap: true, maxWidth: "6rem" },
                  { header: "상태", cell: (r) => (r.resolved ? "처리됨" : "미처리") },
                ]}
              />
            </div>
          ))}
        </Panel>
      </div>
    </AdminShell>
  );
}
