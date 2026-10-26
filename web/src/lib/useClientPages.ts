"use client";

// useClientPages — 이미 받아 둔 목록을 프론트에서 쪽으로 나눈다(서버에 다시 요청하지 않는다).
// 처리 작업대의 카드들은 /api/status가 5초마다 통째로 주는 목록을 그대로 쓰므로, 줄이 늘면 화면이 끝없이 길어진다.
// 네트워크 이벤트·L4 차단 목록·영구 잠금이 같은 규칙으로 쪽을 나누도록 한곳에 모았다.
import { useEffect, useState } from "react";

export type ClientPages<T> = {
  /** 지금 쪽에 보여 줄 줄 */
  pageRows: T[];
  /** 지금 쪽 번호(1부터) */
  page: number;
  /** 전체 쪽 수(줄이 없어도 1) */
  totalPages: number;
  setPage: (page: number) => void;
};

export function useClientPages<T>(rows: T[], pageSize: number): ClientPages<T> {
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const [page, setPage] = useState(1);
  // 폴링으로 건수가 줄면(해제·만료로 목록에서 빠짐) 지금 쪽이 범위를 벗어날 수 있으니 마지막 쪽으로 맞춘다.
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const current = Math.min(page, totalPages);
  const start = (current - 1) * pageSize;
  return { pageRows: rows.slice(start, start + pageSize), page: current, totalPages, setPage };
}
