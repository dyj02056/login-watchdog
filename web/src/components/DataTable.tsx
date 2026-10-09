import type { ReactNode } from "react";
import { EmptyState } from "./States";
import styles from "./DataTable.module.css";

export type Column<T> = {
  header: string;
  cell: (row: T) => ReactNode;
  /** 숫자·시각처럼 자릿수가 맞아야 하는 칸 */
  num?: boolean;
  align?: "right";
  /** 열 너비 힌트 (CSS 클래스가 아니라 비율 이름) */
  grow?: boolean;
};

type Props<T> = {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string | number;
  empty: { title: string; hint?: string };
  /** 접근성용 표 이름 (화면에는 보이지 않는다 — 제목은 Panel이 보여준다) */
  caption: string;
};

export function DataTable<T>({ columns, rows, rowKey, empty, caption }: Props<T>) {
  if (rows.length === 0) return <EmptyState title={empty.title} hint={empty.hint} />;
  return (
    <div className={styles.wrap}>
      <table className={styles.table}>
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.header} scope="col" className={column.align === "right" ? styles.right : undefined}>
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={rowKey(row, index)}>
              {columns.map((column) => (
                <td
                  key={column.header}
                  className={[column.num ? "num" : "", column.align === "right" ? styles.right : "", column.grow ? styles.grow : ""].join(" ")}
                >
                  {column.cell(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
