import { newID } from "../browser";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { api } from "../api/endpoints";
import { request } from "../api/client";
import { renamedOutbound } from "../domain";
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
  const [target, setTarget] = useState("www.google.com:443");
  const health = useQuery({
    queryKey: ["health", context.document?.version],
    queryFn: api.health,
    refetchInterval: context.operation?.status === "running" ? 1500 : false,
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
            target,
            tls: target !== "149.154.167.50:443",
          },
        }),
      );
    } catch (caught) {
      setError(caught);
    }
  }
  async function remove(outbound: Outbound) {
    const doc = context.document;
    if (!doc || doc.config.rules.some((rule) => rule.outbound === outbound.name)) return;
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
    <>
      <div className="toolbar">
        <span className="muted">{t("outbounds.subtitle")}</span>
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
      <div className="toolbar">
        <label htmlFor="outbound-target">{t("outbounds.target")}</label>
        <input
          id="outbound-target"
          className="mono"
          value={target}
          onChange={(event) => setTarget(event.target.value)}
        />
        <Button tone="quiet" onClick={() => setTarget("149.154.167.50:443")}>
          {t("diagnostics.telegram")}
        </Button>
        {target === "149.154.167.50:443" && (
          <small className="muted">{t("diagnostics.telegramHint")}</small>
        )}
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
              <th>{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {outbounds.map((outbound) => {
              const status = health.data?.statuses.find((item) => item.id === outbound.id);
              const refs = context.document!.config.rules.filter(
                (rule) => rule.outbound === outbound.name,
              ).length;
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
                        disabled={!context.admin || refs > 0}
                        title={refs ? t("rules.reference", { count: refs }) : undefined}
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
    </>
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
              target: "www.google.com:443",
              tls: true,
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
            <Field label={t("outbounds.credentials")}>
              <select
                value={credentials.action}
                onChange={(event) =>
                  setCredentials({
                    ...credentials,
                    action: event.target.value as Credentials["action"],
                  })
                }
              >
                {base.credential_state?.[initial.name]?.configured && (
                  <option value="preserve">{t("outbounds.preserve")}</option>
                )}
                <option value="replace">{t("outbounds.replace")}</option>
                {endpoint.scheme !== "ss" && <option value="clear">{t("outbounds.clear")}</option>}
              </select>
            </Field>
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
          <Toggle
            checked={draft.enabled !== false}
            onChange={(enabled) => setDraft({ ...draft, enabled })}
            label={t("common.enabled")}
          />
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
