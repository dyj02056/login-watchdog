import styles from "./States.module.css";

/** 데이터가 없을 때. 왜 비었는지와, 있다면 어떻게 채워지는지를 한 줄로 알려준다. */
export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className={styles.empty}>
      <p className={styles.emptyTitle}>{title}</p>
      {hint ? <p className={styles.hint}>{hint}</p> : null}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className={styles.error} role="alert">
      <p>{message}</p>
      {onRetry ? (
        <button type="button" onClick={onRetry}>
          다시 불러오기
        </button>
      ) : null}
    </div>
  );
}

/** 자리를 미리 잡아두는 로딩 표시 — 불러온 뒤 레이아웃이 밀리지 않게 */
export function Skeleton({ lines = 4 }: { lines?: number }) {
  return (
    <div className={styles.skeleton} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className={styles.bar} />
      ))}
    </div>
  );
}
