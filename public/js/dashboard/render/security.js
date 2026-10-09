// ============================================================================
// dashboard/render/security.js — 보안 이벤트·연관 사건·AI 조기 경보 표
// 원래 render.js 한 파일(556줄)이었는데 화면 영역별로 나눴다. 다른 파일은 예전처럼
// "./render.js"에서 가져다 쓴다(render.js가 재내보내기). 배경 설명은 dashboard/main.js 상단 주석 참고.
// ============================================================================

import { SEVERITY_LABELS } from "../state.js";
import { escapeHtml, formatTime } from "../utils.js";

/**
 * 보안 이벤트(위험등급 통합) 표를 채운다. 각 줄에 등급 배지와, 미해결 HIGH/MEDIUM
 * 이벤트에는 "처리 완료" 버튼이 붙는다. CRITICAL(IP 잠금)은 잠금이 풀리면 자동으로
 * 처리되므로 버튼 대신 안내 문구만 보여준다(security/soar/lockouts.py가 부르는 db.resolve_security_events_for_ip 참고).
 * "계정" 칸은 계정 단위 이벤트(분산 브루트포스로 인한 계정 잠금 등)에만 값이 있다 —
 * 그 외 IP 단위 이벤트는 username이 비어 있어 "-"로 표시한다. 계정 잠금은 5분 뒤
 * 풀리면 "현재 잠긴 IP / 계정" 카드에서 사라지므로, 잠금이 풀린 뒤에도 어느 계정이
 * 공격받았는지 남아 있는 곳은 이 칸뿐이다.
 * @param {Array} events - [{id, event_type, severity, ip_address, username, path, count, action, detected_at, resolved_at}, ...]
 */
export function renderSecurityEventsTable(events) {
    const tbody = document.getElementById("security-events-table-body");

    if (events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">보안 이벤트가 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = events
        .map((event) => {
            const severityClass = `severity-${event.severity.toLowerCase()}`;
            const severityLabel = SEVERITY_LABELS[event.severity] || event.severity;

            let statusCell;
            if (event.resolved_at) {
                statusCell = `<span class="success-true">처리 완료</span>`;
            } else if (event.severity === "CRITICAL") {
                statusCell = `<span class="empty-state">자동 해제 대기</span>`;
            } else {
                statusCell = `<button data-event-id="${event.id}" class="resolve-event-btn">처리 완료</button>`;
            }

            return `
                <tr>
                    <td class="mono">${formatTime(event.detected_at)}</td>
                    <td><span class="severity-badge ${severityClass}">${severityLabel}</span></td>
                    <td>${escapeHtml(event.event_type)}</td>
                    <td class="mono">${escapeHtml(event.ip_address)}</td>
                    <td>${escapeHtml(event.username || "-")}</td>
                    <td>${escapeHtml(event.path || "-")}</td>
                    <td>${event.count}</td>
                    <td>${escapeHtml(event.action)}</td>
                    <td>${statusCell}</td>
                </tr>
            `;
        })
        .join("");
}

/**
 * 연관 사건(SIEM 상관분석) 표를 채운다. 같은 IP가 짧은 시간 안에 서로 다른
 * event_type을 2개 이상 남겼을 때만 여기 나타난다(security/correlate.py 참고) — 단발성
 * 보안 이벤트는 위 "보안 이벤트" 표에만 남고 여기에는 묶이지 않는다.
 * 사건은 IP 잠금 해제와 별개로, 관리자가 "해결" 버튼을 눌러야 CLOSED(해결됨)가
 * 된다(db/incidents.py의 resolve_incident 참고 — PERMANENT_LOCK_AUTO_CLOSE_INCIDENT를 켜면
 * 영구 잠금이 걸린 사건은 시스템이 자동으로 닫는다). 상태는 세 가지다 — OPEN(진행 중),
 * IDLE(마지막 이벤트로부터 오래 조용해서 새 사건이 따로 열렸지만 아직 미해결),
 * CLOSED(해결됨, 누가 언제 해결했는지 함께 표시).
 * @param {Array} incidents - [{id, ip_address, event_types, severity_max, status, first_event_at, last_event_at, resolved_at, resolved_by}, ...]
 */
export function renderSecurityIncidentsTable(incidents) {
    const tbody = document.getElementById("security-incidents-table-body");

    if (incidents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">연관된 사건이 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = incidents
        .map((incident) => {
            const severityClass = `severity-${incident.severity_max.toLowerCase()}`;
            const severityLabel = SEVERITY_LABELS[incident.severity_max] || incident.severity_max;
            const eventTypes = incident.event_types.map((type) => escapeHtml(type)).join(", ");

            let statusClass;
            let statusLabel;
            let actionCell;
            if (incident.status === "CLOSED") {
                statusClass = "success-true";
                statusLabel = "해결됨";
                // 예전에 잠금 해제로 자동 종료된 사건은 해결자/시각 기록이 없다.
                actionCell = incident.resolved_by
                    ? `<span class="mono">${escapeHtml(incident.resolved_by)} · ${formatTime(incident.resolved_at)}</span>`
                    : "-";
            } else {
                statusClass = incident.status === "IDLE" ? "status-idle" : "success-false";
                statusLabel = incident.status === "IDLE" ? "활동 없음" : "진행 중";
                actionCell = `<button data-incident-id="${incident.id}" class="resolve-incident-btn">해결</button>`;
            }

            return `
                <tr>
                    <td class="mono">${formatTime(incident.first_event_at)}</td>
                    <td class="mono">${formatTime(incident.last_event_at)}</td>
                    <td><span class="severity-badge ${severityClass}">${severityLabel}</span></td>
                    <td>${eventTypes}</td>
                    <td class="mono">${escapeHtml(incident.ip_address)}</td>
                    <td class="${statusClass}">${statusLabel}</td>
                    <td>${actionCell}</td>
                </tr>
            `;
        })
        .join("");
}

// 유형 코드(security/soar/의 event_type과 동일한 문자열) → 화면에 보여줄 한글 라벨.
// security/soar/early_warning.py의 _EARLY_WARNING_LABELS와 같은 매핑을 자바스크립트 쪽에도 둔다 —
// 서버가 라벨 문자열까지 내려주지 않고 event_type 코드만 보내므로(다른
// 표들의 event_type 칸도 코드 그대로 보여주는 것과 같은 방식), 이 표만
// 예외적으로 한글로 바꿔서 보여준다(AI 판단 근거와 나란히 놓였을 때 코드
// 문자열보다 읽기 편하다).
const EARLY_WARNING_LABELS = {
    BRUTE_FORCE: "로그인 브루트포스(IP)",
    DISTRIBUTED_BRUTE_FORCE: "계정 단위 분산 브루트포스",
    SIGNUP_RATE_LIMIT: "회원가입 남용",
    WEB_SCANNING: "Web Scanning",
    UNAUTHORIZED_ACCESS: "Unauthorized Access",
    PAGE_ACCESS: "반복 페이지 접근",
    API_MACRO_PATTERN: "매크로/봇 패턴",
    SIEM_HIGH_INCIDENT: "SIEM HIGH 사건 → 영구 잠금",
};

/**
 * "AI 조기 경보" 표를 채운다 (Track A, guide31). 아직 임계값을 넘지 않은
 * 상태에서 LLM이 위험하다고 판단해 등록한 PENDING 요청과, SIEM HIGH 사건의 영구 잠금
 * 후보(SIEM_HIGH_INCIDENT, guide33)가 여기 나타난다 —
 * 관리자가 승인하면 그 유형이 원래 임계값을 넘었을 때 하던 조치가 실행되고,
 * 반려하면 아무 일도 일어나지 않는다(security/soar/early_warning.py의 execute_approved_request()/
 * reject_pending_request() 참고).
 * @param {Array} requests - [{request_id, event_type, target_kind, target_value,
 *   count, threshold, llm_reason, requested_at}, ...]
 */
export function renderAccessRequestsTable(requests) {
    const tbody = document.getElementById("access-requests-table-body");

    if (requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">대기 중인 AI 조기 경보가 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = requests
        .map((req) => {
            const label = EARLY_WARNING_LABELS[req.event_type] || req.event_type;
            return `
                <tr>
                    <td class="mono">${formatTime(req.requested_at)}</td>
                    <td>${escapeHtml(label)}</td>
                    <td class="mono">${escapeHtml(req.target_value)}</td>
                    <td>${req.count} / ${req.threshold}</td>
                    <td>${escapeHtml(req.llm_reason)}</td>
                    <td>
                        <button data-request-id="${req.request_id}" class="approve-request-btn">승인</button>
                        <button data-request-id="${req.request_id}" class="reject-request-btn">반려</button>
                    </td>
                </tr>
            `;
        })
        .join("");
}
