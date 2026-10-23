// 서버 응답 모양. db/stats.py(/api/stats)와 routes/admin/status.py(/api/status)가 만든다.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM";

export type IpRow = {
  ip: string;
  country: string | null;
  count: number;
  types: string[];
  last_seen: string;
  days?: number;
};

export type Stats = {
  generated_at: string;
  kpi: {
    events_today: number;
    events_yesterday: number;
    failed_logins_today: number;
    blocked_today: number;
    active_locks: number;
    pending_ai: number;
    unresolved_critical: number;
    unresolved_total: number;
    severity_7d: Record<Severity, number>;
  };
  hourly: { today: (number | null)[]; yesterday: number[]; last_week: number[] };
  log_volume: { day: string; count: number; live: boolean }[];
  summary_available: boolean;
  heatmap: { days: string[]; ips: string[]; cells: number[][] };
  flow: { links: { source: string; target: string; value: number }[] };
  new_attackers: IpRow[];
  repeat_attackers: IpRow[];
  unresolved: { id: number; severity: Severity; event_type: string; ip: string; country: string | null; path: string | null; detected_at: string }[];
  compound: { ip: string; types: string[]; type_count: number; severity: Severity; status: string; last_event_at: string; country: string | null }[];
  open_incidents: { id: number; ip: string; types: string[]; severity: Severity; status: "OPEN" | "IDLE" | "CLOSED"; auto_closed: boolean; last_event_at: string }[];
  open_incidents_total: number;
  locks: { kind: "ip" | "account" | "admin"; target: string; permanent: boolean; locked_at: string | null; unlock_at: string | null }[];
  locks_total: number;
  locks_permanent: number;
  top_sources: { name: string; count: number }[];
  top_types: { name: string; count: number }[];
  top_paths: { name: string; count: number }[];
  /** 경로가 기록되지 않은 이벤트를 공격 유형별로 센 것(상위 몇 개 + "기타") */
  pathless_types: { name: string; count: number }[];
  pathless_total: number;
  country_flow: { links: { source: string; target: string; value: number }[] };
  events: {
    id: number;
    detected_at: string;
    severity: Severity;
    event_type: string;
    ip: string;
    country: string | null;
    path: string | null;
    count: number;
    action: string;
    resolved: boolean;
  }[];
  network_layer: unknown[];
};

export type Lockout = {
  ip_address?: string;
  username?: string;
  locked_at: string;
  unlock_at: string | null;
  failure_count: number;
  lock_type?: string;
};

export type Attempt = { id?: number; ip_address: string; username: string; success: boolean; attempted_at: string; location?: string | null };

// ── Track D (계약서 K10) — 네트워크 계층 데이터. /api/status의 새 칸은 C2-3이 채운다.

/** network_events 한 줄(최근 50건, 최신순) */
export type NetworkEvent = {
  id: number;
  observed_at: string;
  src_ip: string;
  layer: "L3" | "L4" | "L7";
  category: string;
  signature: string | null;
  packet_count: number;
  promoted: boolean;
};

export type NetworkBlockStatus = "PENDING_APPLY" | "APPLIED" | "PENDING_REMOVE" | "REMOVED" | "FAILED";

/** network_blocks 한 줄. expires_at이 null이면 영구 차단이다(CONNECTED 증거만 가능). */
export type NetworkBlock = {
  ip: string;
  reason: string;
  evidence: "SPOOFABLE" | "CONNECTED";
  status: NetworkBlockStatus;
  expires_at: string | null;
  requested_by: string;
  applied_at: string | null;
  last_error: string | null;
};

export type AgentName = "fw-agent" | "shipper";

/** 장비 하나의 생존 신호. last_seen_at이 null이면 한 번도 신호가 없었다. */
export type AgentHeartbeat = { last_seen_at: string | null; stale: boolean; detail: Record<string, unknown> };

/** 이 PC(LW_NODE_NAME)의 장비 상태. LW_NODE_NAME이 없는 환경(예: Vercel)은 빈 객체 {}다. */
export type AgentStatus = Partial<Record<AgentName, AgentHeartbeat>>;

export type Status = {
  recent_attempts: Attempt[];
  attempts_total_pages: number;
  active_lockouts: Lockout[];
  active_account_lockouts: Lockout[];
  active_admin_account_lockouts: Lockout[];
  admin_login_log: { id?: number; username: string; success: boolean; ip_address: string; attempted_at?: string; logged_at?: string; location?: string | null }[];
  admin_log_total_pages: number;
  users: { id: number; username: string; email: string; name?: string; created_at: string; email_status?: string; email_verified?: boolean }[];
  users_total_pages: number;
  signup_enabled: boolean;
  recent_posts: { id: number; title: string; author_username: string; created_at: string }[];
  posts_total_pages: number;
  recent_comments: { id: number; post_id: number; body: string; author_username: string; created_at: string }[];
  comments_total_pages: number;
  security_events: Record<string, unknown>[];
  security_events_total_pages: number;
  security_incidents: Record<string, unknown>[];
  security_incidents_total_pages: number;
  access_requests: Record<string, unknown>[];
  access_requests_total_pages: number;
  permanent_locks: { kind: "ip" | "account"; target: string; locked_at?: string; promoted_at?: string; permanent_reason?: string; recoverable?: string; failure_count?: number; email_status?: string | null }[];
  recovery_requests: Record<string, unknown>[];
  ip_exemptions: Record<string, unknown>[];
  permissions: string[];
  admin_users?: { id: number; username: string; role: string; created_at?: string }[];
  // Track D(K10) — 선택 칸으로 둔다. C2-3이 머지되기 전 응답이나 Vercel 응답에도 화면이 깨지지 않게.
  network_events?: NetworkEvent[];
  network_blocks?: NetworkBlock[];
  agent_status?: AgentStatus;
};
