import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole, useWorkspaceState } from "../context";
import { request, ApiError } from "../api/client";
import { api } from "../api/endpoints";
import { Button, Details, ErrorNotice, Modal, Status } from "../components/ui";
import { timestamp } from "../domain";
import type { Operation } from "../model";
import styles from "./recovery.module.css";
interface Report {
  required: boolean;
  ownership: string;
  can_clear: boolean;
  can_recover: boolean;
  capture_active: boolean;
  blocker: string;
  inspection_error?: string;
  run_id?: string;
  recorded_at?: string;
  next_action?: string;
  items: { kind: string; identity?: string; status: string; message: string }[];
}
export function Recovery() {
  const { t } = useTranslation();
  const context = useConsole();
  const client = useQueryClient();
  const [task, setTask] = useWorkspaceState<Operation | null>("recovery.task", null);
  const [confirm, setConfirm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>();
  const report = useQuery({
    queryKey: ["recovery", context.state.data_state],
    queryFn: ({ signal }) => request<Report>("/recovery", { signal }),
    refetchInterval: 10000,
  });
  const progress = useQuery({
    queryKey: ["recovery-operation", task?.id],
    queryFn: () => api.operation(task!.id),
    enabled: !!task && task.status === "running",
    initialData: task ?? undefined,
    refetchInterval: (q) => (q.state.data?.status === "running" ? 500 : false),
  });
  const operation = progress.data ?? task;
  const finished = useRef("");
  useEffect(() => {
    if (operation && operation.status !== "running" && finished.current !== operation.id) {
      finished.current = operation.id;
      void report.refetch();
      void context.refresh();
    }
  }, [operation, report, context]);
  const data = report.data;
  const active =
    data?.capture_active ||
    ["running", "degraded", "starting", "pausing"].includes(context.state.data_state);
  const busy = submitting || operation?.status === "running";
  const local = context.admin && context.state.local_access;
  const blocker = report.error
    ? "inspection_failed"
    : active
      ? "active"
      : (data?.blocker ?? "checking");
  const allowed =
    !!data?.can_recover && !report.error && !active && local && !busy && !report.isFetching;
  async function recover() {
    setSubmitting(true);
    setError(undefined);
    try {
      const next = await api.lifecycle("recover", { confirm: true });
      client.setQueryData(["recovery-operation", next.id], next);
      setTask(next);
      context.track(next);
      setConfirm(false);
    } catch (cause) {
      setError(cause);
    } finally {
      setSubmitting(false);
    }
  }
  const failure = operation?.status === "failed" || operation?.status === "canceled";
  return (
    <section className={styles.recovery} aria-label={t("settings.recovery")}>
      <header className={styles.heading}>
        <h2>{t("settings.recovery")}</h2>
        <Button
          disabled={report.isFetching || busy}
          onClick={() => {
            setError(undefined);
            void report.refetch();
          }}
        >
          {t(report.isFetching ? "recovery.checking" : "recovery.refresh")}
        </Button>
      </header>
      <p className={styles.hint}>{t("recovery.purpose")}</p>
      {report.dataUpdatedAt > 0 && (
        <small className="muted">
          {t("recovery.checkedAt", {
            time: timestamp(new Date(report.dataUpdatedAt).toISOString()),
          })}
        </small>
      )}
      <ErrorNotice error={error ?? report.error ?? progress.error} />
      <div className={styles.summary}>
        <output>
          <strong>{t(`recovery.summary.${blocker}`, { defaultValue: t("common.unknown") })}</strong>
        </output>
        <p>{t(`recovery.next.${blocker}`, { defaultValue: t("recovery.next.unverified") })}</p>
      </div>
      {!local && <p className="inlineNote">{t("recovery.localRequired")}</p>}
      {!!data?.items.length && (
        <div className={styles.resources}>
          <h3>{t("recovery.resources")}</h3>
          {data.items.map((item, index) => (
            <div className={styles.resource} key={`${item.kind}:${item.identity}:${index}`}>
              <strong>{t(`recovery.${item.kind}`, { defaultValue: t("common.details") })}</strong>
              <code>{item.identity || "—"}</code>
              <span>{t(`recovery.${item.status}`, { defaultValue: t("common.unknown") })}</span>
              <details>
                <summary>{t("common.details")}</summary>
                <pre>{item.message}</pre>
              </details>
            </div>
          ))}
        </div>
      )}
      {data?.inspection_error && (
        <details className={styles.technical}>
          <summary>{t("common.details")}</summary>
          <pre>{data.inspection_error}</pre>
        </details>
      )}
      <div className={styles.actions}>
        <Button tone="primary" disabled={!allowed} onClick={() => setConfirm(true)}>
          {t(busy ? "recovery.running" : "settings.recover")}
        </Button>
        <small>{t("recovery.scope")}</small>
      </div>
      {operation && (
        <section className={styles.result} aria-label={t("recovery.execution")}>
          <header>
            <strong>{t("recovery.execution")}</strong>
            <Status value={progress.error ? "unknown" : operation.status} />
          </header>
          <p>
            {t(
              progress.error
                ? "recovery.unknownTask"
                : busy
                  ? "recovery.runningHint"
                  : failure
                    ? "recovery.failedHint"
                    : "recovery.completedHint",
            )}
          </p>
          <small>{timestamp(operation.finished_at || operation.started_at)}</small>
          {operation.error && (
            <ErrorNotice
              error={
                new ApiError(operation.error_code || "request", 400, {
                  code: operation.error_code || "request",
                  details: operation.error,
                })
              }
            />
          )}
          <Button tone="quiet" onClick={() => context.setTool("logs")}>
            {t("nav.logs")}
          </Button>
          <Details value={operation.result ?? { id: operation.id, stage: operation.stage }} />
        </section>
      )}
      {data?.run_id && (
        <details className={styles.technical}>
          <summary>{t("recovery.record")}</summary>
          <code>{data.run_id}</code>
          <p>{timestamp(data.recorded_at)}</p>
          <pre>{data.next_action}</pre>
        </details>
      )}
      <Modal
        open={confirm}
        onClose={() => {
          if (!submitting) setConfirm(false);
        }}
        title={t("settings.recover")}
        description={t("recovery.confirmScope")}
      >
        <ul>
          {data?.items
            .filter((i) => i.kind !== "firewall")
            .map((item, index) => (
              <li key={index}>
                {t(`recovery.${item.kind}`)} {item.identity && <code>{item.identity}</code>}
              </li>
            ))}
        </ul>
        <div className="actions">
          <Button disabled={submitting} onClick={() => setConfirm(false)}>
            {t("common.cancel")}
          </Button>
          <Button tone="primary" disabled={!allowed} onClick={() => void recover()}>
            {t(submitting ? "recovery.running" : "recovery.confirm")}
          </Button>
        </div>
      </Modal>
    </section>
  );
}
