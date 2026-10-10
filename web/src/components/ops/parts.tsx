"use client";

import type { ReactNode } from "react";
import { DataTable } from "../DataTable";
import type { Column } from "../DataTable";
import { Pagination } from "../Pagination";
import { Panel } from "../Panel";
import { Skeleton } from "../States";
import { useOps } from "./OpsContext";
import type { SectionName } from "./OpsContext";
import styles from "./ops.module.css";

/** 처리 버튼. 누르는 즉시 "처리 중…"으로 바뀌고 다시 누를 수 없다. */
export function ActionButton({
  id,
  children,
  onClick,
  danger,
  disabled,
}: {
  id: string;
  children: ReactNode;
  onClick: () => void;
  danger?: boolean;
  disabled?: boolean;
}) {
  const { busy } = useOps();
  const working = busy === id;
  return (
    <button type="button" className={`${danger ? "btn-danger" : "btn"} btn-small`} onClick={onClick} disabled={working || (busy !== null && busy !== id) || disabled}>
      {working ? "처리 중…" : children}
    </button>
  );
}

/** 쪽수가 있는 표 하나: 제목, 표, 쪽 이동. 쪽을 넘기면 표만 흐려졌다가 그 표만 다시 받아 온다. */
export function PagedPanel<T>({
  name,
  title,
  caption,
  columns,
  rowKey,
  empty,
  meta,
  footer,
}: {
  name: SectionName;
  title: string;
  caption: string;
  columns: Column<T>[];
  rowKey: (row: T, index: number) => string | number;
  empty: { title: string; hint?: string };
  meta?: ReactNode;
  footer?: ReactNode;
}) {
  const ops = useOps();
  const table = ops.table<T>(name);
  return (
    <Panel title={title} meta={meta} flush>
      {ops.status === null ? (
        <Skeleton lines={5} />
      ) : (
        <div className={table.loading ? styles.dim : undefined}>
          <DataTable caption={caption} columns={columns} rows={table.rows} rowKey={rowKey} empty={empty} />
        </div>
      )}
      <Pagination page={table.page} total={table.total} busy={table.loading} onChange={table.setPage} label={`${title} 쪽 이동`} />
      {footer}
    </Panel>
  );
}
