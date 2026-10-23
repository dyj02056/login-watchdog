"use client";

// NetworkEventsCard — 관제 화면 축소판(I2-1)의 "네트워크 이벤트(최근 L3/L4 탐지)" 카드. 계약서 K10의 network_events를 보여 준다.
// 데이터는 처리 작업대가 이미 5초마다 받는 /api/status의 network_events(최근 50건)에서 꺼내 쓴다(새 요청을 만들지 않는다).
// 50건을 서버에 다시 요청하지 않고 프론트에서 쪽으로 나눠 보여 준다 — 한 화면에 50줄이 쏟아지면 보기 어려우므로,
// 다른 처리 작업대 목록과 같은 Pagination UI를 재사용해 조작감을 맞춘다.
import { useEffect, useState } from "react";
import { formatShortDateTime } from "@/lib/format";
import { netCategoryLabel } from "@/lib/labels";
import type { NetworkEvent } from "@/lib/types";
import { Pill } from "../Badge";
import { DataTable } from "../DataTable";
import { Pagination } from "../Pagination";
import { Panel } from "../Panel";
import { Skeleton } from "../States";
import { useOps } from "../ops/OpsContext";
import styles from "./net.module.css";

// 한 쪽에 보여 줄 줄 수. 다른 목록(8~10줄)과 비슷하게 둔다.
const PAGE_SIZE = 8;

export function NetworkEventsCard() {
  const { status } = useOps();
  const rows = status?.network_events ?? [];
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const [page, setPage] = useState(1);
  // 폴링으로 건수가 줄면 지금 쪽이 범위를 벗어날 수 있으니 마지막 쪽으로 맞춘다(서버 페이징의 total 처리와 같은 뜻).
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const current = Math.min(page, totalPages);
  const start = (current - 1) * PAGE_SIZE;
  const pageRows = rows.slice(start, start + PAGE_SIZE);

  return (
    <Panel title="네트워크 이벤트 (최근 L3/L4 탐지)" meta={status ? <span className={`${styles.count} num`}>{rows.length}건</span> : null} flush>
      {status === null ? (
        <Skeleton lines={3} />
      ) : (
        <>
          <DataTable<NetworkEvent>
            caption="센서가 탐지한 최근 네트워크 계층 이벤트 목록"
            rows={pageRows}
            rowKey={(r) => r.id}
            empty={{
              title: "현재 네트워크 이벤트 없음",
              hint: "센서(Suricata·Scapy)가 공격을 탐지하면 여기에 최근 50건이 나타납니다.",
            }}
            columns={[
              { header: "시각", cell: (r) => formatShortDateTime(r.observed_at, true), num: true },
              { header: "출발지 IP", cell: (r) => r.src_ip, num: true },
              { header: "계층", cell: (r) => <span className={styles.mono}>{r.layer}</span> },
              { header: "종류", cell: (r) => <span title={r.signature ?? undefined}>{netCategoryLabel(r.category)}</span> },
              { header: "패킷 수", cell: (r) => r.packet_count.toLocaleString(), num: true },
              {
                // 보안 기록으로 올라간 경보인지(promoted). 올라간 것만 상관분석·차단 대상이 된다.
                header: "승격",
                cell: (r) => (r.promoted ? <Pill tone="danger">보안 기록</Pill> : <span className={styles.muted}>-</span>),
              },
            ]}
          />
          <Pagination page={current} total={totalPages} onChange={setPage} label="네트워크 이벤트 쪽 이동" />
        </>
      )}
    </Panel>
  );
}
