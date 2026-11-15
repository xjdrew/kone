import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useBlocker } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { request } from "../api/client";
import { copyText } from "../browser";
import { timestamp } from "../domain";
import { Button, ErrorNotice, Field, Status, Toggle } from "../components/ui";
import type { RemoteAccess } from "../model";
import styles from "./access.module.css";

type ListenerDraft = { host: string; port: string; https: boolean };
function listenerDraft(value?: RemoteAccess): ListenerDraft {
  const address = value?.listen_address;
  const colon = address?.lastIndexOf(":") ?? -1;
  return {
    host: address
      ? address.slice(0, colon).replace(/^\[|\]$/g, "")
      : value?.interfaces[0]?.address || "0.0.0.0",
    port: address ? address.slice(colon + 1) : "9443",
    https: value?.https ?? true,
  };
}

export function AccessSettings() {
  const { t } = useTranslation();
  const context = useConsole();
  const [draft, setDraft] = useState<ListenerDraft>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordError, setPasswordError] = useState<unknown>();
  const [sessionError, setSessionError] = useState<unknown>();
  const lan = useQuery({ queryKey: ["lan"], queryFn: () => request<RemoteAccess>("/access/lan") });
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: () =>
      request<{
        sessions: {
          id: string;
          role: string;
          remote: boolean;
          expires: string;
          local_access?: boolean;
        }[];
      }>("/sessions"),
    enabled: context.admin,
  });
  const saved = listenerDraft(lan.data);
  const values = draft ?? saved;
  const dirty = !!draft && JSON.stringify(draft) !== JSON.stringify(saved);
  const editable = context.admin && context.state.local_access;
  const enabled = lan.data?.enabled ?? false;
  useBlocker({
    shouldBlockFn: () => dirty && !window.confirm(t("common.unsaved")),
    enableBeforeUnload: dirty,
  });
  function update<K extends keyof ListenerDraft>(key: K, value: ListenerDraft[K]) {
    setDraft({ ...values, [key]: value });
  }
  async function apply(enable: boolean) {
    setBusy(true);
    setError(null);
    try {
      const host = values.host.includes(":") ? `[${values.host}]` : values.host;
      await request<RemoteAccess>("/access/lan", {
        method: "POST",
        body: { enabled: enable, address: `${host}:${values.port}`, https: values.https },
      });
      setDraft(enable ? undefined : values);
      await Promise.all([lan.refetch(), sessions.refetch()]);
      context.notify({ key: enable ? "access.enabled" : "access.disabled" });
    } catch (caught) {
      setError(caught);
      await lan.refetch();
    } finally {
      setBusy(false);
    }
  }
  async function copy(value: string) {
    try {
      await copyText(value);
      context.notify({ key: "common.copied" });
    } catch {
      context.notify({ key: "access.copyFailed" });
    }
  }
  async function downloadCA() {
    setError(null);
    try {
      const certificate = await request<string>("/access/certificate", { text: true });
      const url = URL.createObjectURL(new Blob([certificate], { type: "application/x-pem-file" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "kone-ca.pem";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (caught) {
      setError(caught);
    }
  }
  return (
    <div className={styles.access}>
      <section className={styles.section}>
        <header className={styles.heading}>
          <div>
            <h2>{t("access.title")}</h2>
            <p>{t("access.subtitle")}</p>
          </div>
          <div className={styles.actions}>
            <Status value={enabled ? "enabled" : "disabled"} />
            {enabled ? (
              <Button
                disabled={!editable || busy || passwordBusy}
                onClick={() => void apply(false)}
              >
                {t("access.disable")}
              </Button>
            ) : (
              <Button
                tone="primary"
                type="submit"
                form={
                  context.state.password_configured ? "remote-listener" : "remote-access-password"
                }
                disabled={!editable || busy || passwordBusy || !lan.data}
              >
                {t(context.state.password_configured ? "access.enable" : "access.setupEnable")}
              </Button>
            )}
          </div>
        </header>
        {!editable && <p className="inlineNote">{t("access.localOnly")}</p>}
        <div className={styles.listener}>
          <form
            id="remote-listener"
            onSubmit={(event) => {
              event.preventDefault();
              if (context.state.password_configured) void apply(true);
              else
                document
                  .querySelector<HTMLInputElement>('#access-password input[name="password"]')
                  ?.focus();
            }}
          >
            <div className={styles.fields}>
              <Field label={t("access.interface")}>
                <select
                  disabled={!editable || busy || passwordBusy}
                  value={values.host}
                  onChange={(event) => update("host", event.target.value)}
                >
                  {lan.data?.interfaces.map((item) => (
                    <option key={`${item.interface}:${item.address}`} value={item.address}>
                      {item.interface} · {item.address}
                    </option>
                  ))}
                  <option value="0.0.0.0">{t("access.allIPv4")}</option>
                  {values.host !== "0.0.0.0" &&
                    !lan.data?.interfaces.some((item) => item.address === values.host) && (
                      <option value={values.host}>
                        {values.host} · {t("common.unavailable")}
                      </option>
                    )}
                </select>
              </Field>
              <Field label={t("common.port")}>
                <input
                  required
                  type="number"
                  min="1"
                  max="65535"
                  inputMode="numeric"
                  className="mono"
                  disabled={!editable || busy || passwordBusy}
                  value={values.port}
                  onChange={(event) => update("port", event.target.value)}
                />
              </Field>
            </div>
            <div className={styles.addressHelp}>
              <span>
                {t(values.host === "0.0.0.0" ? "access.allHint" : "access.interfaceHint")}
              </span>
              <Button tone="quiet" disabled={lan.isFetching} onClick={() => void lan.refetch()}>
                {t("access.refresh")}
              </Button>
            </div>
            {lan.data?.interfaces_unavailable && (
              <p role="alert">{t("access.interfacesUnavailable")}</p>
            )}
            <Toggle
              checked={values.https}
              onChange={(value) => update("https", value)}
              disabled={!editable || busy || passwordBusy}
              label={t("access.https")}
            />
            <p className={styles.hint}>
              {t(values.https ? "access.httpsHint" : "access.httpHint")}
            </p>
            {enabled && (
              <div className={styles.actions}>
                <Button type="submit" tone="primary" disabled={!editable || !dirty || busy}>
                  {t(busy ? "common.loading" : "access.apply")}
                </Button>
                {dirty && (
                  <Button disabled={busy} onClick={() => setDraft(undefined)}>
                    {t("common.cancel")}
                  </Button>
                )}
              </div>
            )}
          </form>
          <div className={styles.endpoints}>
            <h3>{t("access.urls")}</h3>
            {enabled ? (
              lan.data?.urls.map((url) => (
                <div className={styles.endpoint} key={url}>
                  <a className="mono" href={url} target="_blank" rel="noreferrer">
                    {url}
                  </a>
                  <Button
                    tone="quiet"
                    onClick={() => void copy(url)}
                    aria-label={t("access.copyURL", { url })}
                  >
                    {t("common.copy")}
                  </Button>
                </div>
              ))
            ) : (
              <p className={styles.hint}>{t("access.urlsPaused")}</p>
            )}
            {enabled && <p className={styles.hint}>{t("access.passwordLogin")}</p>}
            {!context.state.password_configured && (
              <p className="inlineNote">
                {t("access.passwordMissing")}{" "}
                <a
                  href="#access-password"
                  onClick={(event) => {
                    event.preventDefault();
                    document.getElementById("access-password")?.scrollIntoView({ block: "center" });
                    document
                      .querySelector<HTMLInputElement>('#access-password input[name="password"]')
                      ?.focus();
                  }}
                >
                  {t("auth.setup")}
                </a>
              </p>
            )}
          </div>
        </div>
        {values.https && (enabled || context.state.password_configured) && (
          <div className={styles.certificate}>
            <div className={styles.heading}>
              <h3>{t("access.ca")}</h3>
              <Button
                disabled={!editable || !enabled || !lan.data?.https}
                onClick={() => void downloadCA()}
              >
                {t("settings.certificate")}
              </Button>
            </div>
            <p className={styles.hint}>
              {t(enabled && lan.data?.https ? "access.caSteps" : "access.caPending")}
            </p>
            {enabled && lan.data?.https && lan.data.fingerprint && (
              <div className={styles.fingerprint}>
                <span>SHA-256</span>
                <code>{lan.data.fingerprint}</code>
                <Button tone="quiet" onClick={() => void copy(lan.data!.fingerprint!)}>
                  {t("common.copy")}
                </Button>
              </div>
            )}
            <details>
              <summary>{t("access.caHelp")}</summary>
              <p>{t("access.caHelpText")}</p>
              <ul>
                <li>{t("access.caWindows")}</li>
                <li>{t("access.caMac")}</li>
                <li>{t("access.caBrowser")}</li>
              </ul>
            </details>
          </div>
        )}
        <ErrorNotice error={error || lan.error} />
      </section>
      {context.admin && (
        <section id="access-password" className={styles.section}>
          <details open={!context.state.password_configured || undefined}>
            <summary className={styles.passwordSummary}>
              <span>{t("settings.password")}</span>
              <span className={styles.hint}>
                {t(
                  context.state.password_configured
                    ? "access.passwordConfigured"
                    : "access.passwordNotConfigured",
                )}
              </span>
            </summary>
            <p className={styles.hint}>{t("access.passwordHelp")}</p>
            <form
              id="remote-access-password"
              className="formStack"
              onSubmit={async (event) => {
                event.preventDefault();
                const form = event.currentTarget,
                  data = new FormData(form);
                const enableAfterSave = !context.state.password_configured;
                if (
                  enableAfterSave &&
                  !document.querySelector<HTMLFormElement>("#remote-listener")?.reportValidity()
                )
                  return;
                setPasswordError(null);
                setPasswordBusy(true);
                try {
                  await request("/auth/password", {
                    method: context.state.password_configured ? "PUT" : "POST",
                    body: {
                      password: data.get("password"),
                      confirm_password: data.get("confirm"),
                      ...(context.state.password_configured
                        ? { current_password: data.get("current") }
                        : {}),
                    },
                  });
                  form.reset();
                  await context.refresh();
                  await sessions.refetch();
                  context.notify({ key: "common.saved" });
                  if (enableAfterSave) await apply(true);
                } catch (caught) {
                  setPasswordError(caught);
                } finally {
                  setPasswordBusy(false);
                }
              }}
            >
              {context.state.password_configured && (
                <Field label={t("settings.currentPassword")}>
                  <input required name="current" type="password" autoComplete="current-password" />
                </Field>
              )}
              <div className="formGrid">
                <Field label={t("settings.newPassword")}>
                  <input
                    required
                    minLength={8}
                    name="password"
                    type="password"
                    autoComplete="new-password"
                  />
                </Field>
                <Field label={t("auth.confirmPassword")}>
                  <input
                    required
                    minLength={8}
                    name="confirm"
                    type="password"
                    autoComplete="new-password"
                  />
                </Field>
              </div>
              <div className={styles.actions}>
                <Button
                  type="submit"
                  disabled={
                    passwordBusy ||
                    busy ||
                    (!context.state.password_configured && (!editable || !lan.data))
                  }
                >
                  {t(
                    context.state.password_configured
                      ? "settings.changePassword"
                      : "access.setupEnable",
                  )}
                </Button>
              </div>
              <ErrorNotice error={passwordError} />
            </form>
          </details>
        </section>
      )}
      {context.admin && (
        <section className={styles.section}>
          <header className={styles.heading}>
            <h3>{t("settings.sessions")}</h3>
            <span className={styles.hint}>{sessions.data?.sessions.length ?? "—"}</span>
          </header>
          <div className={styles.sessions}>
            {sessions.data?.sessions.map((session) => (
              <div key={session.id} className={styles.session}>
                <div>
                  <strong>
                    {t(
                      session.local_access
                        ? "access.localSession"
                        : session.remote
                          ? "access.remoteSession"
                          : "access.passwordSession",
                    )}
                  </strong>
                  <code>{session.id}</code>
                </div>
                <span>{t(session.role === "admin" ? "common.admin" : "common.readonly")}</span>
                <time dateTime={session.expires}>{timestamp(session.expires)}</time>
                {session.id === context.state.session_id ? (
                  <span className={styles.hint}>{t("access.currentSession")}</span>
                ) : (
                  <Button
                    onClick={() => {
                      setSessionError(null);
                      void request(`/sessions/${encodeURIComponent(session.id)}/revoke`, {
                        method: "POST",
                        body: {},
                      })
                        .then(async () => {
                          await sessions.refetch();
                          context.notify({ key: "access.revoked" });
                        })
                        .catch(setSessionError);
                    }}
                  >
                    {t("settings.revoke")}
                  </Button>
                )}
              </div>
            ))}
            {sessions.data?.sessions.length === 0 && (
              <p className={styles.hint}>{t("access.noSessions")}</p>
            )}
          </div>
          <ErrorNotice error={sessionError || sessions.error} />
        </section>
      )}
      {!context.state.local_access && (
        <Button onClick={() => void context.logout().catch(setSessionError)}>
          {t("auth.signout")}
        </Button>
      )}
    </div>
  );
}
