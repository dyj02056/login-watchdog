"use client";

// OpsContext — 처리 작업대의 공용 상태: /api/status 폴링, 페이지 있는 표 8개, 처리 요청(버튼) 실행기.
import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { apiJson } from "@/lib/api";
import type { JsonResult } from "@/lib/api";
import type { Status } from "@/lib/types";
import { usePolling } from "@/lib/usePolling";
import { useFeedback } from "../Feedback";

// 서버의 _PAGED_SECTIONS(routes/admin/status.py)와 같은 이름·키
export const SECTIONS = {
  attempts: { param: "attempts_page", rows: "recent_attempts", total: "attempts_total_pages" },
  users: { param: "users_page", rows: "users", total: "users_total_pages" },
  posts: { param: "posts_page", rows: "recent_posts", total: "posts_total_pages" },
  comments: { param: "comments_page", rows: "recent_comments", total: "comments_total_pages" },
  admin_log: { param: "admin_log_page", rows: "admin_login_log", total: "admin_log_total_pages" },
  security_events: { param: "security_events_page", rows: "security_events", total: "security_events_total_pages" },
  security_incidents: { param: "security_incidents_page", rows: "security_incidents", total: "security_incidents_total_pages" },
  access_requests: { param: "access_requests_page", rows: "access_requests", total: "access_requests_total_pages" },
} as const;

export type SectionName = keyof typeof SECTIONS;
type Patch = { rows: unknown[]; total: number };

export type Table<T> = { rows: T[]; page: number; total: number; loading: boolean; setPage: (page: number) => void };

type Api = {
  status: Status | null;
  error: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
  can: (action: string) => boolean;
  busy: string | null;
  /** 처리 요청을 보낸다. 성공하면 알림을 띄우고 화면을 다시 불러온다. */
  run: (key: string, task: () => Promise<JsonResult<Record<string, unknown>>>, successText: string) => Promise<boolean>;
  table: <T>(name: SectionName) => Table<T>;
};

const OpsContext = createContext<Api | null>(null);

export function useOps(): Api {
  const api = useContext(OpsContext);
  if (!api) throw new Error("OpsProvider 안에서만 쓸 수 있습니다.");
  return api;
}

const POLL_MS = 5000;

export function OpsProvider({ children }: { children: ReactNode }) {
  const { toast } = useFeedback();
  const [pages, setPages] = useState<Record<SectionName, number>>(() => Object.fromEntries(Object.keys(SECTIONS).map((k) => [k, 1])) as Record<SectionName, number>);
  const pagesRef = useRef(pages);
  pagesRef.current = pages;
  const [patches, setPatches] = useState<Partial<Record<SectionName, Patch>>>({});
  const [loadingSection, setLoadingSection] = useState<Partial<Record<SectionName, boolean>>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const requestId = useRef<Record<string, number>>({});

  const poll = usePolling<Status>(async () => {
    const params = new URLSearchParams();
    for (const [name, spec] of Object.entries(SECTIONS)) params.set(spec.param, String(pagesRef.current[name as SectionName]));
    const result = await apiJson<Status>(`/api/status?${params}`);
    if (result.ok) setPatches({}); // 전체 응답이 이미 지금 페이지를 담고 있다
    return { data: result.ok ? result.data : null, error: result.error };
  }, POLL_MS);

  const { refresh } = poll;
  const permissions = poll.data?.permissions;
  const can = useCallback((action: string) => Boolean(permissions?.includes(action)), [permissions]);

  const fetchSection = useCallback(async (name: SectionName, page: number) => {
    const spec = SECTIONS[name];
    const id = (requestId.current[name] = (requestId.current[name] ?? 0) + 1);
    const result = await apiJson<Record<string, unknown>>(`/api/status?${new URLSearchParams({ only: name, [spec.param]: String(page) })}`);
    if (id !== requestId.current[name]) return; // 더 새로운 요청이 나갔다
    setLoadingSection((current) => ({ ...current, [name]: false }));
    if (!result.ok || !result.data) return;
    const total = Number(result.data[spec.total] ?? 1);
    if (page > total) {
      setPages((current) => ({ ...current, [name]: total }));
      void fetchSection(name, total);
      return;
    }
    setPatches((current) => ({ ...current, [name]: { rows: result.data![spec.rows] as unknown[], total } }));
  }, []);

  const table = useCallback(
    <T,>(name: SectionName): Table<T> => {
      const spec = SECTIONS[name];
      const patch = patches[name];
      const source = poll.data as unknown as Record<string, unknown> | null;
      return {
        rows: ((patch?.rows ?? source?.[spec.rows]) as T[] | undefined) ?? [],
        total: patch?.total ?? Number(source?.[spec.total] ?? 1),
        page: pages[name],
        loading: Boolean(loadingSection[name]),
        setPage: (page: number) => {
          const next = Math.max(1, page);
          setPages((current) => ({ ...current, [name]: next }));
          setLoadingSection((current) => ({ ...current, [name]: true }));
          void fetchSection(name, next);
        },
      };
    },
    [patches, poll.data, pages, loadingSection, fetchSection],
  );

  const run = useCallback<Api["run"]>(
    async (key, task, successText) => {
      setBusy(key);
      try {
        const result = await task();
        if (!result.ok) {
          toast(result.error ?? "처리하지 못했습니다.", "error");
          return false;
        }
        toast(successText);
        await refresh();
        return true;
      } finally {
        setBusy(null);
      }
    },
    [refresh, toast],
  );

  const value = useMemo<Api>(
    () => ({ status: poll.data, error: poll.error, loading: poll.loading, refresh, can, busy, run, table }),
    [poll.data, poll.error, poll.loading, refresh, can, busy, run, table],
  );

  return <OpsContext.Provider value={value}>{children}</OpsContext.Provider>;
}

/** 서버로 보내는 처리 요청 한 줄 */
export function post(path: string, body: unknown) {
  return apiJson<Record<string, unknown>>(path, { method: "POST", body });
}
