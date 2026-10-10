import styles from "./Pagination.module.css";

type Props = { page: number; total: number; busy?: boolean; onChange: (page: number) => void; label: string };

/** 이전/다음 + "n / 전체". 누르는 즉시 번호가 바뀌므로(부르는 쪽이 상태를 먼저 바꾼다) 응답을 기다리는 느낌이 없다. */
export function Pagination({ page, total, busy, onChange, label }: Props) {
  if (total <= 1) return null;
  return (
    <nav className={styles.nav} aria-label={label}>
      <button type="button" className="btn-quiet btn-small" disabled={page <= 1} onClick={() => onChange(page - 1)}>
        이전
      </button>
      <span className={`${styles.count} num`} aria-live="polite" aria-busy={busy}>
        {page} / {total}
      </span>
      <button type="button" className="btn-quiet btn-small" disabled={page >= total} onClick={() => onChange(page + 1)}>
        다음
      </button>
    </nav>
  );
}
