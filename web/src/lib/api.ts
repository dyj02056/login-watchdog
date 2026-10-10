// api.ts — Flask와 대화하는 얇은 클라이언트.
//
// 화면은 정적 HTML이라 서버가 값을 채워주지 못한다. 대신 같은 주소를 어댑터 헤더와 함께 다시
// 요청하면(helpers/spa.py) 기존 라우트가 평소대로 실행되고 결과가 JSON 봉투로 온다.
//   { page?, data?, messages[], csrf, redirect?, status? }
// 봉투의 csrf는 다음 POST에 X-CSRFToken으로 실어 보낸다.

export const SPA_HEADERS = { "X-Requested-With": "login-watchdog-spa", Accept: "application/json" } as const;

export type Envelope<T = Record<string, unknown>> = {
  page?: string;
  data?: T;
  messages: string[];
  csrf?: string;
  redirect?: string;
  status?: number;
};

let csrfToken = "";

function remember(body: { csrf?: string }) {
  if (body.csrf) csrfToken = body.csrf;
}

/** 화면 이동. next/link·router를 쓰지 않는다 — 정적 내보내기의 RSC 조각(.txt)을 요청하면
 *  Flask가 404로 기록해 "웹 스캐닝"으로 오인하기 때문에, 항상 일반 주소 이동을 한다. */
export function go(path: string) {
  window.location.assign(path);
}

async function readJson<T>(response: Response): Promise<T | null> {
  try {
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

export type SessionInfo = { csrf: string; member: boolean; admin: boolean; username: string | null; admin_username: string | null };

/** 로그인 상태와 CSRF 토큰. 조회만 하고 DB는 건드리지 않는다. */
export async function getSession(): Promise<SessionInfo | null> {
  try {
    const body = await readJson<SessionInfo>(await fetch("/api/spa/session", { headers: SPA_HEADERS, cache: "no-store" }));
    if (body) remember(body);
    return body;
  } catch {
    return null;
  }
}

async function sessionCsrf(): Promise<string> {
  if (csrfToken) return csrfToken;
  await getSession();
  return csrfToken;
}

function networkError<T>(): Envelope<T> {
  return { messages: ["서버에 연결하지 못했습니다. 잠시 후 다시 시도해주세요."], status: 0 };
}

/** 화면 데이터 조회. 리다이렉트 응답이면 그 주소로 이동하고 null을 돌려준다. */
export async function getPage<T = Record<string, unknown>>(path: string): Promise<Envelope<T> | null> {
  try {
    const response = await fetch(path, { headers: SPA_HEADERS, cache: "no-store" });
    const body = await readJson<Envelope<T>>(response);
    if (!body) return { messages: ["응답을 읽지 못했습니다."], status: response.status };
    remember(body);
    if (body.redirect && body.status !== 400) {
      go(body.redirect);
      return null;
    }
    return body;
  } catch {
    return networkError<T>();
  }
}

/** 폼 제출(기존 라우트는 request.form을 읽는다). 허니팟 칸은 일부러 비워서 보낸다. */
export async function postForm<T = Record<string, unknown>>(
  path: string,
  fields: Record<string, string>,
): Promise<Envelope<T> | null> {
  try {
    const token = await sessionCsrf();
    const response = await fetch(path, {
      method: "POST",
      headers: { ...SPA_HEADERS, "X-CSRFToken": token, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ website: "", ...fields }),
    });
    const body = await readJson<Envelope<T>>(response);
    if (!body) return { messages: ["응답을 읽지 못했습니다."], status: response.status };
    remember(body);
    if (body.redirect && body.status !== 400) {
      go(body.redirect);
      return null;
    }
    return body;
  } catch {
    return networkError<T>();
  }
}

export type JsonResult<T> = { ok: boolean; status: number; data: T | null; error?: string };

type JsonBody = { redirect?: string; error?: string; csrf?: string; status?: number; messages?: string[] };

/** 관리자 화면이 쓰는 JSON API. 세션이 끝났으면 로그인 화면으로 보낸다. */
export async function apiJson<T = Record<string, unknown>>(
  path: string,
  options: { method?: "GET" | "POST"; body?: unknown } = {},
): Promise<JsonResult<T>> {
  const method = options.method ?? "GET";
  try {
    const headers: Record<string, string> = { ...SPA_HEADERS };
    if (method === "POST") {
      headers["X-CSRFToken"] = await sessionCsrf();
      headers["Content-Type"] = "application/json";
    }
    const response = await fetch(path, {
      method,
      headers,
      cache: "no-store",
      body: method === "POST" ? JSON.stringify(options.body ?? {}) : undefined,
    });
    const body = await readJson<T & JsonBody>(response);
    if (body?.csrf) remember(body);
    if (body?.redirect && body.status !== 400) {
      go(body.redirect);
      return { ok: false, status: 401, data: null, error: "로그인이 필요합니다." };
    }
    if (response.status === 401) {
      go("/admin/login");
      return { ok: false, status: 401, data: null, error: "세션이 만료되었습니다." };
    }
    const error = body?.error ?? body?.messages?.[0];
    return { ok: response.ok && body?.status !== 400, status: response.status, data: body as T | null, error };
  } catch {
    return { ok: false, status: 0, data: null, error: networkError().messages[0] };
  }
}
