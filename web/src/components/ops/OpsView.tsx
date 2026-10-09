"use client";

// OpsView — 화면 C "처리 작업대". 기존 관리자 대시보드의 모든 처리 기능을 세 묶음으로 나눠 담는다.
//   대응: 잠금·AI 경보·보안 이벤트·연관 사건·영구 잠금·복구 요청·IP 예외
//   기록: 로그인 시도·관리자 로그인 기록
//   관리: 회원·게시글·댓글·관리자 계정
// 5초마다 /api/status를 다시 받고(보이는 탭에서만), 쪽을 넘기면 그 표 하나만 다시 받는다.
import { useEffect, useState } from "react";
import { AdminShell } from "../AdminShell";
import { FeedbackProvider } from "../Feedback";
import { ErrorState } from "../States";
import { OpsProvider, useOps } from "./OpsContext";
import { AdminLogSection, AdminUserSection, AttemptSection, CommentSection, PostSection, UserSection } from "./RecordSections";
import {
  AccessRequestSection,
  ExemptionSection,
  IncidentSection,
  LockSection,
  PermanentLockSection,
  RecoverySection,
  SecurityEventSection,
} from "./ResponseSections";
import styles from "./ops.module.css";

const GROUPS = [
  { id: "respond", label: "대응" },
  { id: "records", label: "기록" },
  { id: "manage", label: "관리" },
] as const;
type GroupId = (typeof GROUPS)[number]["id"];

function Board() {
  const { status, error, refresh } = useOps();
  const [group, setGroup] = useState<GroupId>("respond");

  // 주소 해시(#records)로 묶음을 기억한다 — 새로고침·링크 공유 때 같은 자리로 돌아온다
  useEffect(() => {
    const fromHash = window.location.hash.slice(1) as GroupId;
    if (GROUPS.some((g) => g.id === fromHash)) setGroup(fromHash);
  }, []);
  const choose = (id: GroupId) => {
    setGroup(id);
    history.replaceState(null, "", `#${id}`);
  };

  const waiting = status ? status.access_requests.length : 0;

  return (
    <div className={styles.page}>
      <ul className={styles.groups}>
        {GROUPS.map((g) => (
          <li key={g.id}>
            <button type="button" className={styles.group} aria-pressed={group === g.id} onClick={() => choose(g.id)}>
              {g.label}
              {g.id === "respond" && waiting > 0 ? <span className={`${styles.count} num`}>{waiting}</span> : null}
            </button>
          </li>
        ))}
      </ul>

      {error && status === null ? <ErrorState message={error} onRetry={refresh} /> : null}

      {group === "respond" ? (
        <div className={styles.cols}>
          <div className={styles.wide}>
            <AccessRequestSection />
          </div>
          <LockSection />
          <ExemptionSection />
          <div className={styles.wide}>
            <PermanentLockSection />
          </div>
          <div className={styles.wide}>
            <RecoverySection />
          </div>
          <div className={styles.wide}>
            <SecurityEventSection />
          </div>
          <div className={styles.wide}>
            <IncidentSection />
          </div>
        </div>
      ) : null}

      {group === "records" ? (
        <div className={styles.cols}>
          <AttemptSection />
          <AdminLogSection />
        </div>
      ) : null}

      {group === "manage" ? (
        <div className={styles.cols}>
          <div className={styles.wide}>
            <UserSection />
          </div>
          <PostSection />
          <CommentSection />
          <div className={styles.wide}>
            <AdminUserSection />
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function OpsView() {
  return (
    <FeedbackProvider>
      <AdminShell title="로그인 워치독 처리 작업대" current="/admin/ops">
        <OpsProvider>
          <Board />
        </OpsProvider>
      </AdminShell>
    </FeedbackProvider>
  );
}
