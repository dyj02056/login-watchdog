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
};
