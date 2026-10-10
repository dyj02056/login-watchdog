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
  /** 내용이 maxWidth를 넘으면 줄바꿈해서 열 너비를 일정하게 유지한다(긴 경로 등) */
  wrap?: boolean;
  maxWidth?: string;
};

type Props<T> = {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string | number;
  empty: { title: string; hint?: string };
  /** 접근성용 표 이름 (화면에는 보이지 않는다 — 제목은 Panel이 보여준다) */
  caption: string;
  /** 줄바꿈으로 행 높이가 달라질 때 칸들을 위쪽 기준으로 맞춘다 */
  alignTop?: boolean;
};

export function DataTable<T>({ columns, rows, rowKey, empty, caption, alignTop }: Props<T>) {
  if (rows.length === 0) return <EmptyState title={empty.title} hint={empty.hint} />;
  return (
    <div className={styles.wrap}>
      <table className={`${styles.table} ${alignTop ? styles.top : ""}`}>
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
                  {column.wrap ? (
                    <div className={styles.wrapText} style={{ maxWidth: column.maxWidth }}>
                      {column.cell(row)}
                    </div>
                  ) : (
                    column.cell(row)
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
