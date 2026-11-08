import { Fragment, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { request } from "../api/client";
import { ActionMenu, Button, ErrorNotice, Toggle } from "../components/ui";
import type { Document } from "../model";
import { exactRule, timestamp } from "../domain";
import styles from "./connection-health.module.css";
interface Result {
  dns_code?: string;
  message?: string;
  protocol: string;
  port: number;
  source: string;
  outbound: string;
  status: string;
  stage: string;
  duration_ms: number;
  time: string;
}
interface Incident {
  transitions?: { generation: number; resolution: string; time: string }[];
  checking?: boolean;
  id: number;
  generation: number;
  domain: string;
  scope: string;
  status: string;
  reason: string;
  first: string;
  last: string;
  count: number;
  resolution?: string;
  results: Result[];
  suggestions?: Record<string, string>;
  temporary?: Record<string, string>;
  expires?: string;
}
interface HealthState {
  status: string;
  error?: string;
  auto_enabled: boolean;
  entries: Incident[];
  total: number;
  dropped: number;
}
export function ConnectionHealth() {
  const { t } = useTranslation();
  const region = useRef<HTMLElement>(null);
  const context = useConsole();
  const doc = context.document;
  const [offset, setOffset] = useState(0);
  const [view, setView] = useState("attention");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<number>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const query = useQuery({
    queryKey: ["connection-health", offset, doc?.version, view, search],
    queryFn: ({ signal }) =>
      request<HealthState>(
        `/connection-health?offset=${offset}&limit=100&status=${view}&search=${encodeURIComponent(search)}`,
        { signal },
      ),
    refetchInterval: 3000,
    enabled: !!doc,
  });
  const smart = doc?.config.policy?.smart;
  const running = context.state.data_state === "running";
  const rows = (query.data?.entries ?? []).filter(
    (e) =>
      (view === "all" ||
        (view === "history" && (e.status === "history" || !!e.transitions?.length)) ||
        e.status === view) &&
      e.domain.toLowerCase().includes(search.toLowerCase()),
  );
  async function configure(values: Partial<NonNullable<typeof smart>>) {
    if (!doc) return;
    setBusy(true);
    setError(undefined);
    try {
      const config = structuredClone(doc.config);
      config.policy = { mode: "direct-first", ...config.policy };
      config.policy.smart = { enabled: false, ...config.policy.smart, ...values };
      await context.save(doc, config);
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  async function action(kind: string, e: Incident) {
    if (!doc) return;
    setBusy(true);
    setError(undefined);
    try {
      const result = await request<Document>("/connection-health", {
        method: "POST",
        body: {
          action: kind,
          domain: e.domain,
          scope: e.scope,
          generation: e.generation,
          version: doc.version,
        },
      });
      if (kind === "pin") {
        await context.refresh();
        context.notify({
          key: result.apply_error ? "common.savedNotApplied" : "health.pinned",
          details: result.apply_error,
          undo: result.apply_error
            ? undefined
            : async () => {
                await context.save({ ...doc, version: result.version }, doc.config);
              },
        });
      }
      await query.refetch();
      if (kind !== "recheck") {
        region.current?.querySelector<HTMLButtonElement>('[role="toolbar"] button')?.focus();
      }
      if (kind === "handled") context.notify({ key: "health.handledDone" });
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  if (!doc) return null;
  const candidateIDs =
    smart?.candidates ??
    (doc.config.policy?.["preferred-proxy-id"] ? [doc.config.policy["preferred-proxy-id"]] : []);
  return (
    <section ref={region} className={styles.health} aria-label={t("health.title")}>
      <div className="toolbar">
        <h2>{t("health.title")}</h2>
        <Toggle
          label={t("health.auto")}
          checked={smart?.["auto-enabled"] ?? false}
          disabled={busy || !context.admin || doc.config.policy?.["rule-version"] !== 2}
          onChange={(value) => configure({ "auto-enabled": value })}
        />
        <span className="muted">
          {t(running ? "health.monitoring" : "health.paused")} ·{" "}
          {t(query.data?.auto_enabled ? "health.autoActive" : "health.autoOff")}
        </span>
        <details>
          <summary>{t("health.candidates")}</summary>
          <div className={styles.candidates}>
            {doc.config.outbounds
              .filter((o) => o.enabled !== false)
              .map((o) => (
                <label key={o.id}>
                  <input
                    type="checkbox"
                    checked={
                      candidateIDs.includes(o.id) ||
                      (doc.config.policy?.mode === "proxy-first" &&
                        doc.config.policy?.["preferred-proxy-id"] === o.id)
                    }
                    disabled={
                      busy ||
                      !context.admin ||
                      (doc.config.policy?.mode === "proxy-first" &&
                        doc.config.policy?.["preferred-proxy-id"] === o.id)
                    }
                    onChange={(event) => {
                      const ids = event.target.checked
                        ? [...candidateIDs, o.id]
                        : candidateIDs.filter((id) => id !== o.id);
                      const config = structuredClone(doc.config);
                      config.policy = {
                        mode: "direct-first",
                        ...config.policy,
                        "preferred-proxy-id":
                          config.policy?.mode === "proxy-first"
                            ? config.policy["preferred-proxy-id"]
                            : (ids[0] ?? ""),
                        smart: { enabled: false, ...smart, candidates: ids },
                      };
                      setBusy(true);
                      void context
                        .save(doc, config)
                        .catch(setError)
                        .finally(() => setBusy(false));
                    }}
                  />
                  {o.name}
                </label>
              ))}
            <Toggle
              label={t("health.allowDirect")}
              checked={smart?.["allow-direct"] ?? false}
              disabled={busy || !context.admin}
              onChange={(value) => configure({ "allow-direct": value })}
            />
          </div>
        </details>
      </div>
      <p className={styles.hint}>{t("health.scopeHint")}</p>
      {doc.config.policy?.["rule-version"] !== 2 && (
        <p className={styles.hint}>{t("smart.upgrade")}</p>
      )}
      <ErrorNotice error={error ?? query.error} />
      {query.data?.error && (
        <div role="alert" className="dangerText">
          {t("health.storageError")}
          <details>
            <summary>{t("common.details")}</summary>
            <pre>{query.data.error}</pre>
          </details>
        </div>
      )}
      {!!query.data?.dropped && (
        <p className="muted">{t("health.deferred", { count: query.data.dropped })}</p>
      )}
      <div className="toolbar" role="toolbar" aria-label={t("health.filter")}>
        {["attention", "adjusted", "all", "history"].map((value) => (
          <Button
            key={value}
            aria-pressed={view === value}
            onClick={() => {
              setView(value);
              setOffset(0);
            }}
          >
            {t(`health.view.${value}`)}
          </Button>
        ))}
        <input
          type="search"
          aria-label={t("common.search")}
          placeholder={t("common.search")}
          value={search}
          onChange={(event) => {
            setSearch(event.target.value);
            setOffset(0);
          }}
        />
      </div>
      <div className={styles.table}>
        <table className="dataTable">
          <thead>
            <tr>
              {["target", "outbound", "dns", "ports", "reason", "last", "actions"].map((value) => (
                <th key={value}>{t(`health.column.${value}`)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => {
              const results = e.results ?? [];
              const latest = new Map<string, Result>();
              for (const r of results) {
                if (r.source === "candidate" && e.temporary?.[r.port] !== r.outbound) continue;
                const key = `${r.protocol}:${r.port}`;
                const previous = latest.get(key);
                if (!previous || new Date(r.time) >= new Date(previous.time)) latest.set(key, r);
              }
              const ports = [...latest.values()]
                .filter((r) => r.port > 0)
                .sort((a, b) => a.port - b.port);
              const outbounds = [...new Set(ports.map((r) => r.outbound).filter(Boolean))];
              const dns = results.filter((r) => r.protocol === "dns").at(-1);
              const dnsCode =
                dns?.status === "answered"
                  ? "NOERROR"
                  : (dns?.dns_code ?? [...results].reverse().find((r) => r.dns_code)?.dns_code);
              const suggestions = Object.entries(e.suggestions ?? {});
              const stale = !e.expires || new Date(e.expires).getTime() <= query.dataUpdatedAt;
              return (
                <Fragment key={e.id}>
                  <tr>
                    <td>
                      <button
                        className="textButton mono"
                        aria-expanded={expanded === e.id}
                        onClick={() => setExpanded(expanded === e.id ? undefined : e.id)}
                      >
                        {e.checking && (
                          <span className={styles.running} aria-label={t("common.running")}>
                            ◌
                          </span>
                        )}{" "}
                        {e.domain}
                      </button>
                      {e.scope && <small>{e.scope}</small>}
                    </td>
                    <td>
                      {outbounds.length === 1
                        ? outbounds[0]
                        : outbounds.length > 1
                          ? t("health.byPort")
                          : "—"}
                    </td>
                    <td>
                      {dns
                        ? dnsCode || t(`health.result.${dns.status}`, { defaultValue: dns.status })
                        : "—"}
                    </td>
                    <td className={styles.ports}>
                      {ports.length
                        ? ports.map((r) => (
                            <span
                              key={`${r.protocol}:${r.port}`}
                              className={r.status === "failed" ? "dangerText" : undefined}
                              aria-label={`${r.protocol} ${r.port} ${t(`health.result.${r.status}`, { defaultValue: r.status })}`}
                            >
                              {r.port}
                              {r.protocol === "udp" ? "/UDP" : ""}{" "}
                              {r.status === "reachable" ? "✓" : r.status === "failed" ? "×" : "—"}
                            </span>
                          ))
                        : "—"}
                    </td>
                    <td>
                      {t(`health.reason.${e.resolution || e.reason}`, { defaultValue: e.reason })}
                      {suggestions.map(([port, outbound]) => (
                        <div className="mono" key={port}>
                          TCP/{port} → {outbound}
                        </div>
                      ))}
                    </td>
                    <td className="mono">{timestamp(e.last)}</td>
                    <td>
                      <div className="actions">
                        <Button
                          disabled={busy || !running || !context.admin}
                          onClick={() => action("recheck", e)}
                        >
                          {t("health.recheck")}
                        </Button>
                        {suggestions.length > 0 && (
                          <>
                            <Button
                              disabled={busy || !running || !context.admin || stale}
                              onClick={() => action("pin", e)}
                            >
                              {t("health.pin")}
                            </Button>
                            <ActionMenu
                              actions={[
                                {
                                  id: "apply",
                                  label: t("health.use"),
                                  disabled: busy || !running || !context.admin || stale,
                                  run: () => {
                                    void action("apply", e);
                                  },
                                },
                                {
                                  id: "edit",
                                  label: t("health.edit"),
                                  disabled: busy || !context.admin,
                                  run: () => {
                                    const [port, outbound] = suggestions[0]!;
                                    const target = e.domain.includes(":")
                                      ? `[${e.domain}]:${port}`
                                      : `${e.domain}:${port}`;
                                    const draft = { ...exactRule(target, "tcp"), outbound };
                                    const existing = doc.config.rules.find(
                                      (r) =>
                                        r.type === draft.type &&
                                        r.pattern === draft.pattern &&
                                        r.protocol === "tcp" &&
                                        r.ports?.includes(Number(port)),
                                    );
                                    context.setRuleDraft(existing ?? draft);
                                  },
                                },
                                ...(e.status === "attention"
                                  ? [
                                      {
                                        id: "handled",
                                        label: t("health.handled"),
                                        disabled: busy || !context.admin,
                                        run: () => {
                                          void action("handled", e);
                                        },
                                      },
                                    ]
                                  : []),
                              ]}
                            />
                          </>
                        )}
                        {e.status === "attention" && suggestions.length === 0 && (
                          <Button
                            disabled={busy || !context.admin}
                            onClick={() => action("handled", e)}
                          >
                            {t("health.handled")}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                  {expanded === e.id && (
                    <tr>
                      <td colSpan={7}>
                        {e.transitions?.map((event, index) => (
                          <p key={index}>
                            {timestamp(event.time)} · {t(`health.reason.${event.resolution}`)}
                          </p>
                        ))}
                        <p>
                          {t("health.evidenceHint")} · {t("health.expires")}: {timestamp(e.expires)}
                        </p>
                        <table className="dataTable">
                          <thead>
                            <tr>
                              <th>{t("health.column.ports")}</th>
                              <th>{t("health.column.outbound")}</th>
                              <th>{t("common.source")}</th>
                              <th>{t("common.status")}</th>
                              <th>{t("health.stage")}</th>
                              <th>{t("health.elapsed")}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {results.map((r, index) => (
                              <tr key={index}>
                                <td className="mono">
                                  {r.protocol}/{r.port || "—"}
                                </td>
                                <td>{r.outbound || "—"}</td>
                                <td>
                                  {t(`health.source.${r.source}`, { defaultValue: r.source })}
                                </td>
                                <td>
                                  {t(`health.result.${r.status}`, { defaultValue: r.status })}
                                </td>
                                <td>
                                  {t(`stage.${r.stage}`, { defaultValue: r.stage })}
                                  {r.dns_code && <> · {r.dns_code}</>}
                                  {r.message && <pre>{r.message}</pre>}
                                </td>
                                <td className="mono">
                                  {r.status === "unknown" ? "—" : `${r.duration_ms} ms`}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
            {!rows.length && (
              <tr>
                <td colSpan={7} className="muted">
                  {t("health.empty")}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="tableFoot">
        <span>{t("health.loaded", { count: query.data?.total ?? 0 })}</span>
        <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>
          {t("health.previous")}
        </Button>
        <Button
          disabled={offset + 100 >= (query.data?.total ?? 0)}
          onClick={() => setOffset(offset + 100)}
        >
          {t("health.next")}
        </Button>
      </div>
    </section>
  );
}
