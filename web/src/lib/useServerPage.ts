"use client";

// useServerPage — 화면이 열릴 때 같은 주소를 어댑터 헤더와 함께 요청해, 기존 라우트가 만든 값(템플릿에 넘기던 값)과
// flash 문장을 받아온다. 로그인이 필요한 화면에서 세션이 없으면 서버가 리다이렉트로 답하고, 그 주소로 이동한다.
import { useCallback, useEffect, useState } from "react";
import { getPage, postForm } from "./api";
import type { Envelope } from "./api";

export type ServerPage<T> = {
  loading: boolean;
  data: T | null;
  messages: string[];
  /** HTTP 상태(429 등). 정상이면 200 */
  status: number;
  /** 폼 제출 결과를 화면 상태에 반영한다(다시 그려진 화면의 값과 메시지) */
  apply: (envelope: Envelope<T>) => void;
};

export function useServerPage<T>(path?: string): ServerPage<T> {
  const [state, setState] = useState<{ loading: boolean; data: T | null; messages: string[]; status: number }>({
    loading: true,
    data: null,
    messages: [],
    status: 200,
  });

  const apply = useCallback((envelope: Envelope<T>) => {
    setState((current) => ({
      loading: false,
      data: envelope.data ?? current.data,
      messages: envelope.messages,
      status: envelope.status ?? 200,
    }));
  }, []);

  useEffect(() => {
    let cancelled = false;
    void getPage<T>(path ?? `${window.location.pathname}${window.location.search}`).then((envelope) => {
      if (cancelled || !envelope) return; // null = 다른 화면으로 이동 중
      apply(envelope);
    });
    return () => {
      cancelled = true;
    };
  }, [path, apply]);

  return { ...state, apply };
}

/** 폼 제출. 리다이렉트가 오면 그 주소로 이동하고(null), 아니면 다시 그려진 화면 값을 돌려준다. */
export function useSubmit<T = Record<string, unknown>>(path: string) {
  const [pending, setPending] = useState(false);
  const submit = useCallback(
    async (fields: Record<string, string>): Promise<Envelope<T> | null> => {
      setPending(true);
      try {
        return await postForm<T>(path, fields);
      } finally {
        setPending(false);
      }
    },
    [path],
  );
  return { pending, submit };
}
