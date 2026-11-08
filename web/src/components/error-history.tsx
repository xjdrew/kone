import { createPortal } from "react-dom";
import { useEffect, useState, useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import {
  clearErrors,
  dismissError,
  errorSnapshot,
  subscribeErrors,
  type ErrorEntry,
} from "../error-history";
import { Button } from "./ui";
function Message({ entry }: { entry: ErrorEntry }) {
  const { t, i18n } = useTranslation();
  const key = `api.${entry.error.code}`;
  return (
    <>
      <strong>{t(i18n.exists(key) ? key : "api.request", entry.error.details.params ?? {})}</strong>
      {entry.error.uncertain && <p>{t("common.uncertain")}</p>}
      {(entry.error.details.details || entry.error.details.message) && (
        <details>
          <summary>{t("common.details")}</summary>
          <pre>{entry.error.details.details || entry.error.details.message}</pre>
        </details>
      )}
    </>
  );
}
export function ErrorHistory() {
  const { t, i18n } = useTranslation();
  const state = useSyncExternalStore(subscribeErrors, errorSnapshot);
  const [open, setOpen] = useState(false);

  const active = state.entries.find((e) => e.id === state.active);
  const activeId = active?.id;
  useEffect(() => {
    if (activeId === undefined) return;
    const timer = setTimeout(dismissError, 8000);
    return () => clearTimeout(timer);
  }, [activeId]);
  useEffect(() => {
    if (!open) return;
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [open]);
  return (
    <>
      <button
        className={state.entries.length ? "errorCount" : ""}
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {t("nav.errors")} <span>{state.entries.length}</span>
      </button>
      {active &&
        createPortal(
          <aside className="errorToast" role="alert">
            <Message entry={active} />
            <div className="actions">
              <Button
                onClick={() => {
                  setOpen(true);
                  dismissError();
                }}
              >
                {t("errors.history")}
              </Button>
              <Button aria-label={t("common.close")} onClick={dismissError}>
                ×
              </Button>
            </div>
          </aside>,
          document.querySelector('[role="dialog"]') ?? document.body,
        )}
      {open && (
        <section className="errorHistory" aria-label={t("errors.history")}>
          <header className="toolbar">
            <strong>{t("errors.history")}</strong>
            <Button onClick={clearErrors}>{t("errors.clear")}</Button>
            <Button aria-label={t("common.close")} onClick={() => setOpen(false)}>
              ×
            </Button>
          </header>
          <div className="errorEntries">
            {state.entries.length ? (
              state.entries.map((entry) => (
                <article key={entry.id}>
                  <time>{new Date(entry.last).toLocaleTimeString(i18n.language)}</time>
                  <span className="pill">×{entry.count}</span>
                  <Message entry={entry} />
                </article>
              ))
            ) : (
              <p>{t("errors.empty")}</p>
            )}
          </div>
        </section>
      )}
    </>
  );
}
