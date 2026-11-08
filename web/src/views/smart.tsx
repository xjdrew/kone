import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { request } from "../api/client";
import { Button, ErrorNotice, Field, Toggle } from "../components/ui";
import type { Document, Rule } from "../model";
import styles from "./smart.module.css";

interface Sample {
  ip: string;
  outbound: string;
  status: string;
  stage: string;
  duration_ms: number;
  time: string;
  verified_tls: boolean;
}
interface Suggestion {
  id: string;
  domain: string;
  status: string;
  suggested_action?: "direct" | "proxy";
  outbound?: string;
  config_version: number;
  network_generation: string;
  interface?: string;
  expires_at: string;
  candidates: string[];
  samples: Sample[];
}
interface SmartState {
  enabled: boolean;
  status: string;
  suggestions: Suggestion[];
  attempts: number;
  dropped: number;
}
interface Preview {
  suggestion: Suggestion;
  rule: Rule;
}

export function SmartPolicy({ global }: { global: boolean }) {
  const { t, i18n } = useTranslation();
  const context = useConsole();
  const document = context.document;
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [expanded, setExpanded] = useState<string>();
  const [preview, setPreview] = useState<Preview>();
  const [showHistory, setShowHistory] = useState(false);
  const state = useQuery({
    queryKey: ["smart", document?.version, context.state.state],
    queryFn: ({ signal }) => request<SmartState>("/smart", { signal }),
    enabled: !!document,
    refetchInterval: document?.config.policy?.smart?.enabled ? 5000 : false,
  });
  if (!document) return null;
  const enabled = document.config.policy?.smart?.enabled ?? false;
  const layered = document.config.policy?.["rule-version"] === 2;
  const editable = context.admin && !busy;
  const preferred = document.config.policy?.["preferred-proxy-id"] ?? "";
  const entries = state.data?.suggestions ?? [];
  const visible = showHistory
    ? entries
    : entries.filter((item) => !["ignored", "expired"].includes(item.status));
  const time = (value: string) =>
    new Date(value).toLocaleTimeString(i18n.language, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  async function configure(values: {
    smart?: { enabled: boolean };
    "preferred-proxy-id"?: string;
  }) {
    if (!document) return;
    setBusy(true);
    setError(undefined);
    setPreview(undefined);
    try {
      const config = structuredClone(document.config);
      config.policy = { mode: "direct-first", ...config.policy, ...values };
      await context.save(document, config);
      await state.refetch();
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  async function action(action: string, suggestion?: Suggestion) {
    setBusy(true);
    setError(undefined);
    try {
      const result = await request<Preview & Document>("/smart", {
        method: "POST",
        body: {
          action,
          id: suggestion?.id ?? "",
          version: suggestion?.config_version ?? document?.version,
        },
      });
      if (action === "preview") {
        setPreview(result);
        setExpanded(suggestion?.id);
      } else {
        setPreview(undefined);
        if (action === "accept") {
          await context.refresh();
          context.notify({
            key: result.apply_error ? "common.savedNotApplied" : "smart.accepted",
            details: result.apply_error,
          });
        }
        await state.refetch();
      }
    } catch (cause) {
      setError(cause);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className={styles.smart} aria-label={t("smart.title")}>
      <div className={styles.controls}>
        <div className={styles.title}>
          <Toggle
            label={t("smart.title")}
            checked={enabled}
            disabled={!editable || !layered}
            onChange={(value) => configure({ smart: { enabled: value } })}
          />
          <span className="pill">
            {t(`smart.state.${state.data?.status ?? (enabled ? "paused" : "disabled")}`)}
          </span>
        </div>
        <Field label={t("smart.preferred")}>
          <select
            value={preferred}
            disabled={!editable || global}
            onChange={(event) => configure({ "preferred-proxy-id": event.target.value })}
          >
            <option value="">{t("common.none")}</option>
            {document.config.outbounds
              .filter((outbound) => outbound.enabled !== false)
              .map((outbound) => (
                <option key={outbound.id} value={outbound.id}>
                  {outbound.name}
                </option>
              ))}
          </select>
        </Field>
      </div>
      <p className={styles.hint}>{t(layered ? "smart.consent" : "smart.upgrade")}</p>
      {global && <p className={styles.hint}>{t("smart.sharedProxy")}</p>}
      <ErrorNotice error={error ?? state.error} />
      {(enabled || entries.length > 0) && (
        <>
          <div className={styles.toolbar}>
            <span>
              {t("smart.summary", {
                count: visible.length,
                attempts: state.data?.attempts ?? 0,
                dropped: state.data?.dropped ?? 0,
              })}
            </span>
            <Button tone="quiet" onClick={() => setShowHistory(!showHistory)}>
              {t(showHistory ? "smart.hideHistory" : "smart.showHistory")}
            </Button>
            <Button
              tone="quiet"
              disabled={!editable || !entries.length}
              onClick={() => action("clear")}
            >
              {t("smart.clear")}
            </Button>
          </div>
          {!visible.length && (
            <p className={styles.empty}>
              {t(context.state.state === "running" ? "smart.empty" : "smart.pausedHint")}
            </p>
          )}
          <div className={styles.list}>
            {visible.map((item) => {
              const open = expanded === item.id;
              const current =
                item.config_version === document.version &&
                Date.parse(item.expires_at) > Date.now();
              const plan = preview?.suggestion.id === item.id && current ? preview : undefined;
              const working = ["pending", "queued", "rechecking", "testing"].includes(item.status);
              return (
                <article className={styles.entry} key={item.id}>
                  <button
                    className={styles.summary}
                    aria-expanded={open}
                    onClick={() => setExpanded(open ? undefined : item.id)}
                  >
                    <span
                      aria-hidden="true"
                      className={working ? styles.running : styles.disclosure}
                    >
                      {working ? "" : open ? "−" : "+"}
                    </span>
                    <code>{item.domain}</code>
                    <span>TCP/443 + TLS</span>
                    <span
                      className={item.status === "ready" && current ? styles.ready : styles.status}
                    >
                      {t(`smart.status.${current ? item.status : "expired"}`)}
                    </span>
                    <span>
                      {item.suggested_action && current
                        ? t(`smart.action.${item.suggested_action}`, { outbound: item.outbound })
                        : "—"}
                    </span>
                    <time dateTime={item.expires_at}>
                      {t("smart.until", { time: time(item.expires_at) })}
                    </time>
                  </button>
                  {open && (
                    <div className={styles.detail}>
                      <p>{t("smart.scope")}</p>
                      {item.suggested_action === "direct" &&
                        !item.samples.some((sample) => sample.outbound !== "direct") && (
                          <p>{t("smart.proxyNotCompared")}</p>
                        )}
                      <div className={styles.evidenceMeta}>
                        <span>
                          {t("smart.interface")}:{" "}
                          <code>{item.interface || t("smart.engineRoute")}</code>
                        </span>
                        <span>
                          {t("smart.version")}: <code>{item.config_version}</code>
                        </span>
                        <span>
                          {t("smart.network")}: <code>{item.network_generation.slice(0, 12)}</code>
                        </span>
                      </div>
                      <div className={styles.samples}>
                        {item.samples.map((sample, index) => (
                          <div key={`${sample.ip}:${sample.outbound}:${index}`}>
                            <time dateTime={sample.time}>{time(sample.time)}</time>
                            <code>{sample.ip}:443</code>
                            <span>
                              {sample.outbound === "direct"
                                ? t("outbounds.direct")
                                : sample.outbound}
                            </span>
                            <span>{sample.duration_ms === 0 ? "<1" : sample.duration_ms} ms</span>
                            <span>
                              {t(sample.verified_tls ? "smart.tlsVerified" : "smart.notVerified")}
                            </span>
                            <code>{sample.stage}</code>
                          </div>
                        ))}
                      </div>
                      {item.candidates.length >
                        new Set(item.samples.map((sample) => sample.ip)).size && (
                        <p>{t("smart.partial")}</p>
                      )}
                      {plan && (
                        <output className={styles.preview}>
                          <strong>{t("smart.rulePreview")}</strong>
                          <code>
                            DOMAIN {plan.rule.pattern} · TCP/443 → {plan.rule.outbound}
                          </code>
                          <p>{t("smart.ruleLifetime")}</p>
                          <p>{t("smart.cacheBoundary")}</p>
                        </output>
                      )}
                      <div className={styles.actions}>
                        {item.status === "ready" && current && (
                          <Button
                            tone="primary"
                            disabled={!editable}
                            onClick={() => action(plan ? "accept" : "preview", item)}
                          >
                            {t(plan ? "smart.accept" : "smart.preview")}
                          </Button>
                        )}
                        {current && (
                          <Button
                            disabled={!editable || working}
                            onClick={() => action("recheck", item)}
                          >
                            {t("smart.recheck")}
                          </Button>
                        )}
                        {item.status !== "ignored" && (
                          <Button
                            tone="quiet"
                            disabled={!editable}
                            onClick={() => action("ignore", item)}
                          >
                            {t("smart.ignore")}
                          </Button>
                        )}
                      </div>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}
