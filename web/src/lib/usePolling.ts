"use client";

// usePolling — 주기적으로 불러오는 훅. 기존 public/js/polling.js(guide45)와 같은 규칙을 지킨다.
//  - 탭이 숨겨지면 멈추고, 다시 보이면 즉시 한 번 불러온 뒤 재개한다
//  - 응답을 받은 뒤에 다음 요청을 예약해서 서버가 느려도 요청이 겹치지 않는다
//  - 실패해도 계속 돈다(마지막으로 성공한 값은 그대로 보여준다)
import { useCallback, useEffect, useRef, useState } from "react";

export type PollState<T> = {
  data: T | null;
  error: string | null;
  loading: boolean;
  updatedAt: number | null;
  refresh: () => Promise<void>;
};

type Loader<T> = () => Promise<{ data: T | null; error?: string | null }>;

export function usePolling<T>(load: Loader<T>, intervalMs: number): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);
  const loadRef = useRef(load);
  loadRef.current = load;
  const inFlight = useRef<Promise<void> | null>(null);

  const refresh = useCallback(async () => {
    if (inFlight.current) return inFlight.current;
    const run = (async () => {
      const result = await loadRef.current();
      if (result.data !== null) {
        setData(result.data);
        setUpdatedAt(Date.now());
        setError(null);
      } else {
        setError(result.error ?? "불러오지 못했습니다.");
      }
      setLoading(false);
    })().finally(() => {
      inFlight.current = null;
    });
    inFlight.current = run;
    return run;
  }, []);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;

    const tick = async () => {
      if (document.hidden) return; // 보이지 않는 동안은 예약하지 않는다. visibilitychange가 깨운다.
      await refresh();
      if (!stopped && !document.hidden) timer = setTimeout(tick, intervalMs);
    };
    const onVisibility = () => {
      clearTimeout(timer);
      if (!document.hidden) void tick();
    };

    void tick();
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [intervalMs, refresh]);

  return { data, error, loading, updatedAt, refresh };
}
