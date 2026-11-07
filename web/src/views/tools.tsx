import { DiagnosticTarget } from "../components/diagnostic-target";
import {
  diagnosticElapsed,
  diagnosticHistoryKey,
  readDiagnosticHistory,
  rememberDiagnostic,
  type DiagnosticHistoryEntry,
} from "../diagnostic-history";
import { diagnosticRequest } from "../diagnostic-request";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole, useWorkspaceState } from "../context";
import { api } from "../api/endpoints";
import {
  ActionMenu,
  Button,
  Details,
  Empty,
  ErrorNotice,
  Field,
  KeyValues,
  Status,
  Toggle,
} from "../components/ui";
import { OutboundName, OutboundSelect } from "./policy";
import { useTargetActions } from "./traffic";
import { timestamp } from "../domain";
import type { Json, Operation } from "../model";
import styles from "./tools.module.css";

export function Tools() {
  const { t } = useTranslation();
  const { tool, setTool } = useConsole();
  return (
    <section className={styles.tools} aria-label={t(`nav.${tool}`)}>
      <header>
        <div role="tablist">
          <button
            role="tab"
            aria-selected={tool === "diagnostics"}
            onClick={() => setTool("diagnostics")}
          >
            {t("nav.diagnostics")}
          </button>
          <button role="tab" aria-selected={tool === "logs"} onClick={() => setTool("logs")}>
            {t("nav.logs")}
          </button>
        </div>
        <Button tone="quiet" onClick={() => setTool(null)} aria-label={t("common.close")}>
          ×
        </Button>
      </header>
      <div className={styles.body}>{tool === "diagnostics" ? <Diagnostics /> : <Logs />}</div>
    </section>
  );
}
function Diagnostics() {
  const { t } = useTranslation();
  const context = useConsole();
  const [target, setTarget] = useWorkspaceState("tools.target", context.diagnosticTarget || "");
  const [outbound, setOutbound] = useWorkspaceState(
    "tools.outbound",
    context.document?.config.outbounds.find((item) => item.enabled !== false)?.name ?? "direct",
  );
  const [mode, setMode] = useWorkspaceState<"connection" | "dns">("tools.mode", "connection");
  const [dnsServer, setDNSServer] = useWorkspaceState("tools.dnsServer", "");
  const [history, setHistory] = useState(() => {
    try {
      return readDiagnosticHistory(localStorage.getItem(diagnosticHistoryKey));
    } catch {
      return readDiagnosticHistory(null);
    }
  });
  function saveHistory(entries: DiagnosticHistoryEntry[]) {
    setHistory(entries);
    try {
      localStorage.setItem(diagnosticHistoryKey, JSON.stringify(entries));
    } catch {
      /* Diagnostics remain usable when browser storage is unavailable. */
    }
  }
  const protocol = mode === "dns" ? "udp" : "tcp";
  const currentTarget = mode === "dns" ? dnsServer : target;
  const [tls, setTLS] = useWorkspaceState("tools.tls", true);
  const [dnsName, setDNSName] = useWorkspaceState("tools.dnsName", "example.com");
  const [dnsType, setDNSType] = useWorkspaceState("tools.dnsType", "A");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const tasks = useQuery({
    queryKey: ["operations"],
    queryFn: ({ signal }) => api.operations(signal),
    refetchInterval: (query) =>
      query.state.data?.operations.some((item) => item.status === "running") ? 1500 : false,
  });
  useEffect(() => {
    // Synchronize a target selected outside the diagnostic form.
    // oxlint-disable-next-line react/set-state-in-effect
    if (context.diagnosticTarget) {
      setTarget(context.diagnosticTarget);
      setMode("connection");
      context.diagnose("");
    }
  }, [context, setTarget, setMode]);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const request = diagnosticRequest(
        currentTarget.trim(),
        outbound,
        protocol,
        tls,
        dnsName.trim(),
        dnsType,
      );
      const operation = await api.diagnose(request);
      saveHistory(
        rememberDiagnostic(history, {
          mode,
          target: currentTarget.trim(),
          tls: request.tls,
          ...(mode === "dns" ? { dnsName, dnsType: dnsType as "A" | "AAAA" } : {}),
        }),
      );
      context.track(operation);
      await tasks.refetch();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  const operations =
    tasks.data?.operations.filter(
      (item) =>
        item.kind.includes("diagnos") &&
        (mode === "dns" ? item.protocol === "udp" : item.protocol !== "udp"),
    ) ?? [];
  return (
    <div className={styles.diagnostics}>
      <form
        className={styles.probeForm}
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <h2 className={styles.diagnosticTitle}>{t("diagnostics.title")}</h2>
        <fieldset className={styles.diagnosticModes}>
          <legend className="srOnly">{t("diagnostics.mode")}</legend>
          <button
            type="button"
            aria-pressed={mode === "connection"}
            onClick={() => setMode("connection")}
          >
            {t("diagnostics.connectionMode")}
          </button>
          <button type="button" aria-pressed={mode === "dns"} onClick={() => setMode("dns")}>
            {t("diagnostics.dnsMode")}
          </button>
        </fieldset>
        <DiagnosticTarget
          label={t(mode === "dns" ? "diagnostics.dnsServer" : "diagnostics.target")}
          value={currentTarget}
          history={history.filter((entry) => entry.mode === mode)}
          placeholder={mode === "dns" ? "192.168.1.1:53" : "example.com:443"}
          onChange={mode === "dns" ? setDNSServer : setTarget}
          onClear={() => saveHistory(history.filter((entry) => entry.mode !== mode))}
          onSelect={(entry) => {
            if (entry.mode === "dns") {
              setDNSServer(entry.target);
              setDNSName(entry.dnsName ?? "");
              setDNSType(entry.dnsType ?? "A");
            } else {
              setTarget(entry.target);
              setTLS(entry.tls);
            }
          }}
        />
        <Field label={t("common.outbound")}>
          <OutboundSelect value={outbound} onChange={setOutbound} />
        </Field>
        {protocol === "tcp" ? (
          <Toggle
            checked={target === "149.154.167.50:443" ? false : tls}
            disabled={target === "149.154.167.50:443"}
            onChange={setTLS}
            label={t("diagnostics.tls")}
          />
        ) : (
          <div className="formGrid">
            <Field label={t("diagnostics.dnsName")}>
              <input
                className="mono"
                required
                value={dnsName}
                onChange={(event) => setDNSName(event.target.value)}
              />
            </Field>
            <Field label={t("diagnostics.dnsType")}>
              <select value={dnsType} onChange={(event) => setDNSType(event.target.value)}>
                <option>A</option>
                <option>AAAA</option>
              </select>
            </Field>
          </div>
        )}
        <small className="muted">
          {t(
            mode === "dns"
              ? "diagnostics.dnsHint"
              : target === "149.154.167.50:443"
                ? "diagnostics.telegramHint"
                : "diagnostics.compare",
          )}
        </small>
        <Button tone="primary" type="submit" disabled={!context.admin || busy}>
          {t(mode === "dns" ? "diagnostics.startDNS" : "diagnostics.start")}
        </Button>
        <ErrorNotice error={error || tasks.error} />
      </form>
      <div className={styles.results}>
        <div className={styles.resultsHeading}>
          <span>{t(mode === "dns" ? "diagnostics.dnsQueryResult" : "diagnostics.target")}</span>
          <span>{t("common.outbound")}</span>
          <span>{t("diagnostics.latency")}</span>
          <span>{t("common.status")}</span>
        </div>
        {!operations.length ? (
          <Empty
            title={t(mode === "dns" ? "diagnostics.dnsEmpty" : "diagnostics.empty")}
            description={t("diagnostics.notApplication")}
          />
        ) : (
          operations.map((operation) => (
            <DiagnosticTask
              key={operation.id}
              operation={operation}
              onCancel={async () => {
                try {
                  await api.cancel(operation.id);
                  await tasks.refetch();
                } catch (caught) {
                  setError(caught);
                }
              }}
            />
          ))
        )}
      </div>
    </div>
  );
}
function DiagnosticTask({ operation, onCancel }: { operation: Operation; onCancel: () => void }) {
  const { t } = useTranslation();
  const { admin } = useConsole();
  const result = operation.result;
  const rawRows = Array.isArray(result)
    ? result
    : result && typeof result === "object" && "results" in result && Array.isArray(result.results)
      ? result.results
      : [];
  const rows: Json[] = operation.outbounds?.length
    ? operation.outbounds.map(
        (name) =>
          rawRows.find(
            (row) => row && typeof row === "object" && !Array.isArray(row) && row.outbound === name,
          ) ?? {
            target: operation.target ?? "",
            outbound: name,
            protocol: operation.protocol ?? "tcp",
            status: operation.status === "running" ? "pending" : "not_run",
            stage: operation.stage,
          },
      )
    : rawRows;
  return (
    <article className={styles.task}>
      <header>
        <span className="muted">{timestamp(operation.started_at)}</span>
        {operation.status === "running" && (
          <Button onClick={onCancel} disabled={!admin}>
            {t("diagnostics.cancel")}
          </Button>
        )}
      </header>
      {rows.map((row, index) =>
        row && typeof row === "object" && !Array.isArray(row) ? (
          <DiagnosticResult key={index} result={row} />
        ) : null,
      )}
      {operation.error && <Details value={{ error: operation.error }} />}
    </article>
  );
}
function DiagnosticResult({ result }: { result: Record<string, Json> }) {
  const { t } = useTranslation();
  const target = String(result.target ?? "");
  const actions = useTargetActions(target, String(result.protocol ?? "tcp"));
  const running = result.status === "running" || result.status === "testing";
  const pending = running || result.status === "pending";
  const protocols =
    result.protocols && typeof result.protocols === "object" && !Array.isArray(result.protocols)
      ? result.protocols
      : {};
  return (
    <details className={styles.result}>
      <summary className={styles.resultSummary} aria-busy={running}>
        <span className={styles.target}>
          <code>{target || "—"}</code>
          <small>
            {result.protocol === "udp"
              ? `${result.dns_name ?? "DNS"} · ${result.dns_type ?? ""}`
              : protocols.tls &&
                  typeof protocols.tls === "object" &&
                  !Array.isArray(protocols.tls) &&
                  protocols.tls.tested
                ? "TCP + TLS"
                : "TCP"}
          </small>
        </span>
        <OutboundName name={String(result.outbound ?? "")} />
        <span className="mono numeric">
          {pending ? "—" : diagnosticElapsed(result.duration_ms)}
        </span>
        <span className={styles.resultState}>
          {running && <span className={styles.spinner} aria-hidden="true" />}
          <Status value={String(result.status ?? "unknown")} />
        </span>
      </summary>
      <div className={styles.resultDetails}>
        <div className="actions">
          <strong>{t(`stage.${result.stage}`, { defaultValue: t("common.details") })}</strong>
          <span className="spacer" />
          <ActionMenu actions={actions} />
        </div>
        <KeyValues
          entries={[
            [t("diagnostics.elapsed"), diagnosticElapsed(result.duration_ms)],
            [t("diagnostics.endpointElapsed"), diagnosticElapsed(result.connect_latency_ms)],
            [t("outbounds.endpoint"), String(result.remote_address || "—")],
            [t("common.version"), String(result.config_version ?? "—")],
          ]}
        />
        <p className="muted">
          {t(result.protocol === "udp" ? "diagnostics.dnsElapsedHint" : "diagnostics.elapsedHint")}
        </p>
        <div className={styles.protocolChecks}>
          {Object.entries(protocols).map(([name, value]) => {
            const check = value && typeof value === "object" && !Array.isArray(value) ? value : {};
            return (
              <div key={name}>
                <span className="mono">{name.toUpperCase()}</span>
                <Status value={String(check.status ?? "unknown")} />
                <span className="muted">
                  {t(check.tested ? "diagnostics.measured" : "diagnostics.notMeasured")}
                </span>
              </div>
            );
          })}
        </div>
        {result.message && <p className={styles.technicalMessage}>{String(result.message)}</p>}
        <Details value={result} />
      </div>
    </details>
  );
}
function Logs() {
  const { t } = useTranslation();
  const [filters, setFilters] = useWorkspaceState<Record<string, string>>("logs.filters", {
    min_level: "info",
    limit: "50",
    source: "",
    from: "",
    to: "",
  });
  const [applied, setApplied] = useWorkspaceState("logs.applied", filters);
  const [cursor, setCursor] = useWorkspaceState<{ before?: string; after?: string }>(
    "logs.cursor",
    {},
  );
  const [paused, setPaused] = useWorkspaceState("logs.paused", false);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<unknown>();
  const history = !!cursor.before || !!cursor.after;
  const data = useQuery({
    queryKey: ["logs", applied, cursor],
    queryFn: ({ signal }) => api.logs({ ...applied, ...cursor }, signal),
    refetchInterval: history || paused || editing ? false : 2000,
  });
  const records = data.data?.records ?? [];
  function apply() {
    setError(null);
    try {
      const next = { ...filters };
      for (const key of ["from", "to"])
        if (next[key]) next[key] = new Date(next[key]).toISOString();
      if (next.from && next.to && next.from > next.to) throw new Error(t("common.fieldError"));
      setApplied(next);
      setCursor({});
      setEditing(false);
    } catch (caught) {
      setError(caught);
    }
  }
  return (
    <div className={styles.logView}>
      <form
        className="toolbar"
        onSubmit={(event) => {
          event.preventDefault();
          apply();
        }}
      >
        <select
          onFocus={() => setEditing(true)}
          aria-label={t("logs.level")}
          value={filters.min_level}
          onChange={(event) => setFilters({ ...filters, min_level: event.target.value })}
        >
          {["debug", "info", "warn", "error"].map((level) => (
            <option key={level}>{level}</option>
          ))}
        </select>
        <select
          onFocus={() => setEditing(true)}
          aria-label={t("common.source")}
          value={filters.source}
          onChange={(event) => setFilters({ ...filters, source: event.target.value })}
        >
          <option value="">
            {t("common.source")}: {t("common.all")}
          </option>
          {["management", "desktop", "helper"].map((source) => (
            <option key={source}>{source}</option>
          ))}
        </select>
        <select
          aria-label={t("common.count")}
          value={filters.limit}
          onChange={(event) => setFilters({ ...filters, limit: event.target.value })}
        >
          {[50, 100, 200].map((count) => (
            <option key={count}>{count}</option>
          ))}
        </select>
        <details>
          <summary>{t("common.time")}</summary>
          <div className="actions">
            <Field label={t("logs.from")}>
              <input
                type="datetime-local"
                onFocus={() => setEditing(true)}
                value={filters.from}
                onChange={(event) => setFilters({ ...filters, from: event.target.value })}
              />
            </Field>
            <Field label={t("logs.to")}>
              <input
                type="datetime-local"
                onFocus={() => setEditing(true)}
                value={filters.to}
                onChange={(event) => setFilters({ ...filters, to: event.target.value })}
              />
            </Field>
          </div>
        </details>
        <Button type="submit">{t("common.apply")}</Button>
        <span className="spacer" />
        <Button
          onClick={() => {
            setPaused(!paused);
            setEditing(false);
          }}
        >
          {t(paused ? "common.resume" : "common.freeze")}
        </Button>
      </form>
      <ErrorNotice error={error || data.error} />
      <div className="tableWrap">
        <table className="dataTable">
          <thead>
            <tr>
              {["common.time", "logs.level", "common.source", "logs.message", "common.details"].map(
                (key) => (
                  <th key={key}>{t(key)}</th>
                ),
              )}
            </tr>
          </thead>
          <tbody>
            {records.map((record) => (
              <tr key={record.id}>
                <td className="mono nowrap muted">{timestamp(record.time)}</td>
                <td
                  className={
                    record.level.toLowerCase() === "error" ? "dangerText mono" : "mono muted"
                  }
                >
                  {record.level}
                </td>
                <td>{record.source}</td>
                <td className={styles.message}>{record.message}</td>
                <td>
                  <Details value={record} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!records.length && <Empty title={t("logs.empty")} />}
      </div>
      <div className="tableFoot">
        {history && <span>{t("logs.history")}</span>}
        {data.data?.gap && <span>{t("common.truncated")}</span>}
        <Button
          disabled={!records.length}
          onClick={() => {
            setCursor({ before: records[0].id });
            setEditing(false);
          }}
        >
          {t("logs.older")}
        </Button>
        <Button
          disabled={!history || !records.length}
          onClick={() => setCursor({ after: records.at(-1)!.id })}
        >
          {t("logs.newer")}
        </Button>
        <Button
          onClick={() => {
            setCursor({});
            setPaused(false);
            setEditing(false);
          }}
        >
          {t("common.latest")}
        </Button>
        <span className="mono">
          {records.length} / {data.data?.capacity ?? "—"}
        </span>
      </div>
    </div>
  );
}
