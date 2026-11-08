import { createPortal } from "react-dom";
import { useEffect, useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import {
  clearErrors,
  dismissError,
  errorSnapshot,
  subscribeErrors,
  type ErrorEntry,
} from "../error-history";
import { Button } from "./ui";
import { useConsole } from "../context";
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
export function NotificationCount() {
  const state = useSyncExternalStore(subscribeErrors, errorSnapshot);
  return (
    <span className={state.entries.length ? "errorCount" : undefined}>{state.entries.length}</span>
  );
}
export function ErrorToasts() {
  const { t } = useTranslation();
  const { setTool } = useConsole();
  const state = useSyncExternalStore(subscribeErrors, errorSnapshot);
  const active = state.entries.find((e) => e.id === state.active);
  const activeId = active?.id;
  useEffect(() => {
    if (activeId === undefined) return;
    const timer = setTimeout(dismissError, 8000);
    return () => clearTimeout(timer);
  }, [activeId]);
  if (!active) return null;
  return createPortal(
    <aside className="errorToast" role="alert">
      <Message entry={active} />
      <div className="actions">
        <Button
          onClick={() => {
            setTool("notifications");
            dismissError();
          }}
        >
          {t("nav.notifications")}
        </Button>
        <Button aria-label={t("common.close")} onClick={dismissError}>
          ×
        </Button>
      </div>
    </aside>,
    document.querySelector('[role="dialog"]') ?? document.body,
  );
}
export function Notifications() {
  const { t, i18n } = useTranslation();
  const state = useSyncExternalStore(subscribeErrors, errorSnapshot);
  return (
    <div className="notifications">
      <div className="toolbar">
        <Button tone="quiet" disabled={!state.entries.length} onClick={clearErrors}>
          {t("errors.clear")}
        </Button>
      </div>
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
    </div>
  );
}
