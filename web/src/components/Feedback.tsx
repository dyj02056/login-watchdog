"use client";

// Feedback — 확인창과 알림. 브라우저 기본 confirm()/alert()/prompt() 대신 <dialog>를 쓴다.
// 포커스는 대화상자 안에 갇히고, Esc로 취소할 수 있다(<dialog>의 기본 동작).
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import styles from "./Feedback.module.css";

type ConfirmOptions = {
  title: string;
  body?: string;
  confirmLabel?: string;
  danger?: boolean;
  /** 지정하면 사유 입력칸이 나온다(비어 있으면 확인할 수 없다) */
  noteLabel?: string;
};
type ConfirmResult = { ok: boolean; note: string };
type Toast = { id: number; text: string; tone: "ok" | "error" };

type Api = {
  confirm: (options: ConfirmOptions) => Promise<ConfirmResult>;
  toast: (text: string, tone?: "ok" | "error") => void;
};

const FeedbackContext = createContext<Api | null>(null);

export function useFeedback(): Api {
  const api = useContext(FeedbackContext);
  if (!api) throw new Error("FeedbackProvider 안에서만 쓸 수 있습니다.");
  return api;
}

export function FeedbackProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<(ConfirmOptions & { resolve: (r: ConfirmResult) => void }) | null>(null);
  const [note, setNote] = useState("");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dialog = useRef<HTMLDialogElement>(null);
  const nextId = useRef(1);

  const confirm = useCallback(
    (options: ConfirmOptions) =>
      new Promise<ConfirmResult>((resolve) => {
        setNote("");
        setPending({ ...options, resolve });
      }),
    [],
  );

  const toast = useCallback((text: string, tone: "ok" | "error" = "ok") => {
    const id = nextId.current++;
    setToasts((current) => [...current, { id, text, tone }]);
    setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), tone === "error" ? 7000 : 3500);
  }, []);

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (pending && !element.open) element.showModal();
    if (!pending && element.open) element.close();
  }, [pending]);

  const finish = (ok: boolean) => {
    if (!pending) return;
    pending.resolve({ ok, note: note.trim() });
    setPending(null);
  };

  const needsNote = Boolean(pending?.noteLabel);
  const canConfirm = !needsNote || note.trim().length > 0;

  return (
    <FeedbackContext.Provider value={{ confirm, toast }}>
      {children}

      <dialog ref={dialog} className={styles.dialog} onCancel={(event) => { event.preventDefault(); finish(false); }} aria-labelledby="dialog-title">
        {pending ? (
          <form
            method="dialog"
            className={styles.form}
            onSubmit={(event) => {
              event.preventDefault();
              if (canConfirm) finish(true);
            }}
          >
            <h2 id="dialog-title" className={styles.title}>
              {pending.title}
            </h2>
            {pending.body ? <p className={styles.body}>{pending.body}</p> : null}
            {pending.noteLabel ? (
              <div className="field">
                <label htmlFor="dialog-note">{pending.noteLabel}</label>
                <input id="dialog-note" className="input" value={note} onChange={(event) => setNote(event.target.value)} autoFocus autoComplete="off" />
              </div>
            ) : null}
            <div className={styles.actions}>
              <button type="button" className="btn-quiet" onClick={() => finish(false)}>
                취소
              </button>
              <button type="submit" className={pending.danger ? "btn-danger" : "btn"} disabled={!canConfirm}>
                {pending.confirmLabel ?? "확인"}
              </button>
            </div>
          </form>
        ) : null}
      </dialog>

      <div className={styles.toasts} role="status" aria-live="polite">
        {toasts.map((t) => (
          <p key={t.id} className={`${styles.toast} ${t.tone === "error" ? styles.toastError : ""}`}>
            {t.text}
          </p>
        ))}
      </div>
    </FeedbackContext.Provider>
  );
}
