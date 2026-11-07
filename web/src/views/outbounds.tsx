import { newID } from "../browser";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { api } from "../api/endpoints";
import { request } from "../api/client";
import { renamedOutbound, timestamp } from "../domain";
import {
  Button,
  Details,
  Empty,
  ErrorNotice,
  Field,
  Modal,
  Status,
  Toggle,
} from "../components/ui";
import type { Credentials, Operation, Outbound } from "../model";

const schemes = {
  http: "HTTP CONNECT",
  https: "HTTPS CONNECT",
  socks5: "SOCKS5",
  ss: "Shadowsocks",
};
function fields(raw: string) {
  try {
    const url = new URL(raw);
    return {
      scheme: url.protocol.slice(0, -1),
      host: url.hostname.replace(/^\[|\]$/g, ""),
      port: raw.match(/:(\d+)(?:[/?#]|$)/)?.[1] || (url.protocol === "https:" ? "443" : "80"),
      suffix: raw.match(/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(.*)$/i)?.[1] || "",
    };
  } catch {
    return { scheme: "http", host: "", port: "8080", suffix: "" };
  }
}
export function OutboundsView() {
  const { t } = useTranslation();
  const context = useConsole();
  const [editor, setEditor] = useState<Outbound | null>(null);
  const [error, setError] = useState<unknown>();
  const health = useQuery({
    queryKey: ["health", context.document?.version],
    queryFn: api.health,
    refetchInterval: (query) =>
      query.state.data?.statuses.some((status) => status.status === "testing") ? 1000 : 5000,
  });
  const outbounds = context.document?.config.outbounds || [];
  async function test(outbound: Outbound) {
    if (!context.document) return;
    setError(null);
    try {
      context.track(
        await request<Operation>("/outbounds/test", {
          method: "POST",
          body: {
            base_version: context.document.version,
            outbound_id: outbound.id,
            target: outbound["check-target"] || "example.com:443",
            tls: outbound["check-tls"] !== false,
          },
        }),
      );
    } catch (caught) {
      setError(caught);
    }
  }
  async function remove(outbound: Outbound) {
    const doc = context.document;
    if (
      !doc ||
      doc.config.policy?.["preferred-proxy-id"] === outbound.id ||
      doc.config.rules.some((rule) => rule.outbound === outbound.name)
    )
      return;
    setError(null);
    try {
      await context.save(doc, {
        ...doc.config,
        outbounds: doc.config.outbounds.filter((item) => item.id !== outbound.id),
      });
    } catch (caught) {
      setError(caught);
    }
  }
  return (
    <section className="view">
      <header className="viewHeader">
        <div>
          <h1>{t("outbounds.title")}</h1>
          <p>{t("outbounds.subtitle")}</p>
        </div>
      </header>
      <div className="toolbar">
        <span className="muted">{t("outbounds.autoSummary")}</span>
        <span className="spacer" />
        <Button
          tone="primary"
          disabled={!context.admin}
          onClick={() =>
            setEditor({
              id: newID(),
              name: "",
              url: "",
              enabled: true,
              "udp-fallback": "direct",
            })
          }
        >
          {t("outbounds.add")}
        </Button>
      </div>
      <ErrorNotice error={error || health.error} />
      <div className="tableWrap">
        <table className="dataTable">
          <thead>
            <tr>
              <th>{t("common.name")}</th>
              <th>{t("outbounds.endpoint")}</th>
              <th>{t("outbounds.udpFallback")}</th>
              <th>{t("common.status")}</th>
              <th>{t("outbounds.latency")}</th>
              <th>{t("outbounds.checked")}</th>
              <th>{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {outbounds.map((outbound) => {
              const status = health.data?.statuses.find((item) => item.id === outbound.id);
              const refs = context.document!.config.rules.filter(
                (rule) => rule.outbound === outbound.name,
              ).length;
              const preferred =
                context.document!.config.policy?.["preferred-proxy-id"] === outbound.id;
              const endpoint = fields(outbound.url);
              return (
                <tr key={outbound.id}>
                  <td>
                    <button
                      className="textButton"
                      disabled={!context.admin}
                      onClick={() => setEditor(outbound)}
                    >
                      {outbound.name}
                    </button>
                    <small className="muted"> {t("rules.reference", { count: refs })}</small>
                    {preferred && <small className="muted"> {t("smart.preferred")}</small>}
                  </td>
                  <td className="mono">
                    {schemes[endpoint.scheme as keyof typeof schemes]}
                    <br />
                    <span className="muted">
                      {endpoint.host}:{endpoint.port}
                    </span>
                  </td>
                  <td>
                    {t(
                      ["socks5", "ss"].includes(endpoint.scheme)
                        ? "outbounds.nativeUDP"
                        : outbound["udp-fallback"] === "direct"
                          ? "outbounds.directUDP"
                          : "outbounds.rejectUDP",
                    )}
                  </td>
                  <td>
                    <Status
                      value={
                        outbound.enabled === false ? "disabled" : (status?.status ?? "notTested")
                      }
                    />
                    {status && <Details value={status} />}
                  </td>
                  <td className="numeric">
                    {status?.connect_latency_ms === undefined
                      ? "—"
                      : `${status.connect_latency_ms} ms`}
                  </td>
                  <td>
                    <time dateTime={status?.checked_at}>{timestamp(status?.checked_at)}</time>
                    <small className="muted mono" style={{ display: "block" }}>
                      {status?.target || outbound["check-target"] || "example.com:443"}
                    </small>
                  </td>
                  <td aria-label={t("common.actions")}>
                    <div className="actions">
                      <Button
                        onClick={() => {
                          void test(outbound);
                        }}
                        disabled={!context.admin || outbound.enabled === false}
                      >
                        {t("outbounds.test")}
                      </Button>
                      <Button
                        tone="quiet"
                        onClick={() => setEditor(outbound)}
                        disabled={!context.admin}
                      >
                        {t("common.edit")}
                      </Button>
                      <Button
                        tone="quiet"
                        disabled={!context.admin || preferred}
                        title={t(preferred ? "smart.preferredInUse" : "outbounds.disableHint")}
                        onClick={() => {
                          const doc = context.document!;
                          setError(null);
                          void context
                            .save(doc, {
                              ...doc.config,
                              outbounds: doc.config.outbounds.map((item) =>
                                item.id === outbound.id
                                  ? { ...item, enabled: outbound.enabled === false }
                                  : item,
                              ),
                            })
                            .catch(setError);
                        }}
                      >
                        {t(outbound.enabled === false ? "outbounds.enable" : "outbounds.disable")}
                      </Button>
                      <Button
                        tone="quiet"
                        disabled={!context.admin || refs > 0 || preferred}
                        title={
                          preferred
                            ? t("smart.preferredInUse")
                            : refs
                              ? t("rules.reference", { count: refs })
                              : undefined
                        }
                        onClick={() => {
                          void remove(outbound);
                        }}
                      >
                        {t("common.delete")}
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {!outbounds.length && (
          <Empty title={t("outbounds.add")} description={t("outbounds.testHint")}>
            <Button
              tone="primary"
              disabled={!context.admin}
              onClick={() =>
                setEditor({
                  id: newID(),
                  name: "",
                  url: "",
                  enabled: true,
                  "udp-fallback": "direct",
                })
              }
            >
              {t("outbounds.add")}
            </Button>
          </Empty>
        )}
        <div className="tableFoot">
          <span>
            {t("outbounds.builtin")}: {t("outbounds.direct")} / {t("outbounds.reject")}
          </span>
        </div>
      </div>
      {editor && <OutboundEditor initial={editor} onClose={() => setEditor(null)} />}
    </section>
  );
}
function OutboundEditor({ initial, onClose }: { initial: Outbound; onClose: () => void }) {
  const { t } = useTranslation();
  const context = useConsole();
  const [base] = useState(context.document!);
  const [draft, setDraft] = useState(initial);
  const [endpoint, setEndpoint] = useState(fields(initial.url));
  const [credentials, setCredentials] = useState<Credentials>({
    action: base.credential_state?.[initial.name]?.configured ? "preserve" : "clear",
    original_name: initial.name,
  });
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const dirty =
    JSON.stringify(draft) !== JSON.stringify(initial) ||
    JSON.stringify(endpoint) !== JSON.stringify(fields(initial.url)) ||
    credentials.action !==
      (base.credential_state?.[initial.name]?.configured ? "preserve" : "clear");
  function close() {
    if (!dirty || window.confirm(t("common.unsaved"))) onClose();
  }
  function build() {
    const host = endpoint.host.trim().replace(/^\[|\]$/g, "");
    if (!host || /[\s/@?#\\]/.test(host)) throw new Error(t("common.fieldError"));
    const port = Number(endpoint.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535)
      throw new Error(t("common.fieldError"));
    const url = `${endpoint.scheme}://${host.includes(":") ? `[${host}]` : host}:${port}${endpoint.suffix}`;
    return { ...draft, name: draft.name.trim(), url };
  }
  async function submit(test = false) {
    setBusy(true);
    setError(null);
    try {
      const outbound = build();
      if (test) {
        context.track(
          await request<Operation>("/outbounds/test", {
            method: "POST",
            body: {
              base_version: base.version,
              draft: outbound,
              credential_action: credentials,
              target: outbound["check-target"] || "example.com:443",
              tls: outbound["check-tls"] !== false,
            },
          }),
        );
      } else {
        const config = renamedOutbound(base.config, initial.name, outbound.name);
        const existing = config.outbounds.findIndex((item) => item.id === initial.id);
        if (existing >= 0) config.outbounds[existing] = outbound;
        else config.outbounds.push(outbound);
        const actions: Record<string, Credentials> = Object.fromEntries(
          config.outbounds.map((item) => [item.name, { action: "preserve" }]),
        );
        actions[outbound.name] = credentials;
        await context.save(base, config, actions);
        onClose();
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      open
      onClose={close}
      title={t(initial.url ? "common.edit" : "outbounds.add")}
      description={t("outbounds.renameHint")}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <div className="formGrid">
          <Field label={t("common.name")}>
            <input
              required
              value={draft.name}
              onChange={(event) => setDraft({ ...draft, name: event.target.value })}
            />
          </Field>
          <Field label={t("outbounds.scheme")}>
            <select
              value={endpoint.scheme}
              onChange={(event) => {
                setEndpoint({ ...endpoint, scheme: event.target.value });
                if (event.target.value === "ss")
                  setCredentials({ ...credentials, action: "replace", username: "aes-256-gcm" });
              }}
            >
              {Object.entries(schemes).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </Field>
          <Field label={t("common.address")}>
            <input
              required
              className="mono"
              value={endpoint.host}
              onChange={(event) => setEndpoint({ ...endpoint, host: event.target.value })}
            />
          </Field>
          <Field label={t("common.port")}>
            <input
              required
              inputMode="numeric"
              type="number"
              min="1"
              max="65535"
              value={endpoint.port}
              onChange={(event) => setEndpoint({ ...endpoint, port: event.target.value })}
            />
          </Field>
          <div className="wide">
            {base.credential_state?.[initial.name]?.configured ? (
              <div className="actions">
                <span className="muted">
                  {t(
                    credentials.action === "preserve"
                      ? "outbounds.authSaved"
                      : credentials.action === "clear"
                        ? "outbounds.authRemoved"
                        : "outbounds.authChanging",
                  )}
                </span>
                <Button
                  tone="quiet"
                  onClick={() =>
                    setCredentials({
                      original_name: initial.name,
                      action: credentials.action === "preserve" ? "replace" : "preserve",
                      ...(endpoint.scheme === "ss" ? { username: "aes-256-gcm" } : {}),
                    })
                  }
                >
                  {t(credentials.action === "preserve" ? "outbounds.changeAuth" : "common.cancel")}
                </Button>
                {endpoint.scheme !== "ss" && credentials.action === "preserve" && (
                  <Button
                    tone="quiet"
                    onClick={() => setCredentials({ original_name: initial.name, action: "clear" })}
                  >
                    {t("outbounds.removeAuth")}
                  </Button>
                )}
              </div>
            ) : (
              endpoint.scheme !== "ss" && (
                <Toggle
                  checked={credentials.action === "replace"}
                  label={t("outbounds.requiresAuth")}
                  onChange={(value) =>
                    setCredentials({
                      action: value ? "replace" : "clear",
                      original_name: initial.name,
                    })
                  }
                />
              )
            )}
          </div>
          {credentials.action === "replace" && (
            <>
              <Field
                label={t(endpoint.scheme === "ss" ? "outbounds.method" : "outbounds.username")}
              >
                {endpoint.scheme === "ss" ? (
                  <select
                    value={credentials.username ?? "aes-256-gcm"}
                    onChange={(event) =>
                      setCredentials({ ...credentials, username: event.target.value })
                    }
                  >
                    {["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"].map((method) => (
                      <option key={method}>{method}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    autoComplete="off"
                    value={credentials.username ?? ""}
                    onChange={(event) =>
                      setCredentials({ ...credentials, username: event.target.value })
                    }
                  />
                )}
              </Field>
              <Field label={t("outbounds.password")}>
                <input
                  type="password"
                  required={endpoint.scheme === "ss"}
                  autoComplete="new-password"
                  value={credentials.password ?? ""}
                  onChange={(event) =>
                    setCredentials({ ...credentials, password: event.target.value })
                  }
                />
              </Field>
            </>
          )}
          <Field label={t("outbounds.udpFallback")}>
            <select
              value={draft["udp-fallback"] || "reject"}
              onChange={(event) => setDraft({ ...draft, "udp-fallback": event.target.value })}
            >
              <option value="reject">{t("outbounds.rejectUDP")}</option>
              <option value="direct">{t("outbounds.directUDP")}</option>
            </select>
          </Field>
          <details className="wide">
            <summary>{t("outbounds.autoSettings")}</summary>
            <p className="inlineNote">{t("outbounds.autoHelp")}</p>
            <Toggle
              checked={draft["check-enabled"] !== false}
              onChange={(value) => setDraft({ ...draft, "check-enabled": value })}
              label={t("outbounds.autoEnabled")}
            />
            <Field label={t("outbounds.target")}>
              <input
                className="mono"
                placeholder="example.com:443"
                value={draft["check-target"] || ""}
                onChange={(event) => setDraft({ ...draft, "check-target": event.target.value })}
              />
            </Field>
            <Toggle
              checked={draft["check-tls"] !== false}
              onChange={(value) => setDraft({ ...draft, "check-tls": value })}
              label={t("diagnostics.tls")}
            />
          </details>
          <div className="wide inlineNote">{t("outbounds.testHint")}</div>
        </div>
        <ErrorNotice error={error} />
        <div className="formActions">
          <Button
            disabled={busy}
            onClick={() => {
              void submit(true);
            }}
          >
            {t("outbounds.test")}
          </Button>
          <Button onClick={close}>{t("common.cancel")}</Button>
          <Button type="submit" tone="primary" disabled={busy}>
            {t("common.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
