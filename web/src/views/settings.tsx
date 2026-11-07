import { useEffect, useState } from "react";
import { Link, useBlocker, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { LanguageSelect, useConsole } from "../context";
import { api } from "../api/endpoints";
import { request } from "../api/client";
import { Button, Details, ErrorNotice, Field, KeyValues, Status, Toggle } from "../components/ui";
import { preference, saveAppearance } from "../startup";
import { timestamp } from "../domain";
import type { Document, Json } from "../model";
import styles from "./settings.module.css";

const sections = ["capture", "resolvers", "data", "access", "recovery", "interface", "about"];
export function SettingsView() {
  const { t } = useTranslation();
  const { section } = useSearch({ from: "/settings" });
  const navigate = useNavigate();
  const context = useConsole();
  return (
    <section className="view">
      <header className="viewHeader">
        <h1>{t("nav.settings")}</h1>
        <div className="actions">
          <Button
            tone="quiet"
            onClick={() => {
              void navigate({
                href: String(context.workspace.get("returnHref") || "/traffic?view=overview"),
              });
            }}
          >
            {t("nav.back")}
          </Button>
        </div>
      </header>
      <nav className="viewTabs">
        {sections.map((item) => (
          <Link
            key={item}
            to="/settings"
            search={{ section: item }}
            aria-current={section === item ? "page" : undefined}
          >
            {t(`settings.${item}`)}
          </Link>
        ))}
      </nav>
      <div className={styles.settings}>
        {["capture", "resolvers"].includes(section) ? (
          context.document ? (
            <Configuration initial={context.document} section={section} />
          ) : (
            <p>{t("common.loading")}</p>
          )
        ) : section === "data" ? (
          <DataSettings />
        ) : section === "access" ? (
          <AccessSettings />
        ) : section === "recovery" ? (
          <Recovery />
        ) : section === "interface" ? (
          <InterfaceSettings />
        ) : (
          <About />
        )}
      </div>
    </section>
  );
}
function Configuration({ initial, section }: { initial: Document; section: string }) {
  const { t } = useTranslation();
  const context = useConsole();
  const [base, setBase] = useState(initial);
  const [draft, setDraft] = useState(structuredClone(initial));
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [validation, setValidation] = useState<unknown>();
  const dirty =
    JSON.stringify(draft.config) !== JSON.stringify(base.config) ||
    JSON.stringify(draft.inbound) !== JSON.stringify(base.inbound);
  useBlocker({
    shouldBlockFn: ({ next }) => {
      if (
        next.pathname === "/settings" &&
        ["capture", "resolvers"].includes(String((next.search as Record<string, unknown>).section))
      )
        return false;
      return dirty && !window.confirm(t("common.unsaved"));
    },
    enableBeforeUnload: dirty,
  });
  useEffect(() => {
    if (!dirty && initial.version !== base.version) {
      // Adopt the external revision only while the form is pristine.
      // oxlint-disable-next-line react/set-state-in-effect
      setBase(initial);
      setDraft(structuredClone(initial));
    }
  }, [initial, dirty, base.version]);
  const core = draft.config.core,
    dns = draft.config.dns;
  const changeCore = (key: string, value: string | boolean) =>
    setDraft({ ...draft, config: { ...draft.config, core: { ...core, [key]: value } } });
  const changeDNS = (key: string, value: string | number | boolean | string[]) =>
    setDraft({ ...draft, config: { ...draft.config, dns: { ...dns, [key]: value } } });
  async function save() {
    setBusy(true);
    setError(null);
    try {
      const result = await context.save(
        base,
        {
          ...draft.config,
          dns: {
            ...draft.config.dns,
            servers: draft.config.dns.servers?.map((value) => value.trim()).filter(Boolean),
            rules: draft.config.dns.rules?.map((rule) => ({
              ...rule,
              servers: rule.servers.map((value) => value.trim()).filter(Boolean),
            })),
          },
        },
        undefined,
        draft.inbound,
      );
      setBase(result);
      setDraft(structuredClone(result));
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void save();
      }}
    >
      <div className={styles.sectionHeading}>
        <h2>{t(`settings.${section}`)}</h2>
        <span className="mono muted">v{base.version}</span>
      </div>
      <p className="inlineNote">{t("settings.captureHint")}</p>
      <fieldset disabled={!context.admin || busy} className={styles.fieldset}>
        {section === "capture" ? (
          <>
            <div className="formGrid">
              <Field label={t("common.name")}>
                <input
                  value={draft.inbound.name}
                  onChange={(event) =>
                    setDraft({ ...draft, inbound: { ...draft.inbound, name: event.target.value } })
                  }
                />
              </Field>
              <Toggle
                checked={draft.inbound.enabled}
                onChange={(enabled) =>
                  setDraft({ ...draft, inbound: { ...draft.inbound, enabled } })
                }
                label={t("common.enabled")}
              />
              <Field label={t("settings.tun")}>
                <input
                  className="mono"
                  value={core.tun}
                  onChange={(event) => changeCore("tun", event.target.value)}
                />
              </Field>
              <Field label={t("settings.stack")}>
                <select
                  value={core.stack}
                  onChange={(event) => changeCore("stack", event.target.value)}
                >
                  <option value="system">system</option>
                  <option value="gvisor">gVisor</option>
                  <option value="mixed">mixed</option>
                </select>
              </Field>
              <Field label={t("settings.network")}>
                <input
                  required
                  className="mono"
                  value={core.network}
                  onChange={(event) => changeCore("network", event.target.value)}
                />
              </Field>
              <Field label={t("settings.ipv6")}>
                <input
                  className="mono"
                  value={core["ipv6-network"]}
                  onChange={(event) => changeCore("ipv6-network", event.target.value)}
                />
              </Field>
              <div className="wide">
                <Field label={t("policy.interface")}>
                  <input
                    className="mono"
                    value={core["outbound-interface"]}
                    onChange={(event) => changeCore("outbound-interface", event.target.value)}
                  />
                </Field>
              </div>
              <Toggle
                checked={core["auto-route"]}
                onChange={(value) => changeCore("auto-route", value)}
                label={t("settings.capture4")}
              />
              <Toggle
                checked={core["auto-route6"]}
                onChange={(value) => changeCore("auto-route6", value)}
                label={t("settings.capture6")}
              />
            </div>
            <div className="actions subtlePanel">
              <Button
                onClick={() => {
                  void api
                    .lifecycle("preflight")
                    .then((operation) => {
                      context.track(operation);
                      setValidation(operation.id);
                    })
                    .catch(setError);
                }}
              >
                {t("proxy.preflight")}
              </Button>
              <Link to="/policy" search={{ view: "rules" }}>
                {t("policy.change")}
              </Link>
            </div>
            {validation !== undefined && context.operation?.id === validation && (
              <div>
                <Status value={context.operation.status} />
                <Details value={context.operation.result || context.operation.error} />
              </div>
            )}
          </>
        ) : (
          <div className="formStack">
            <Toggle
              checked={dns.system}
              onChange={(value) => changeDNS("system", value)}
              label={t("settings.systemDNS")}
            />
            <Field label={t("settings.servers")} help={t("settings.serversHint")}>
              <textarea
                className="mono"
                value={(dns.servers ?? []).join("\n")}
                onChange={(event) => changeDNS("servers", event.target.value.split("\n"))}
              />
            </Field>
            <div className="formGrid">
              {(
                [
                  "listen-port",
                  "read-timeout",
                  "write-timeout",
                  "ttl",
                  "packet-size",
                  "history-limit",
                  "history-retention",
                  "cache-limit",
                ] as const
              ).map((key) => (
                <Field key={key} label={t(`settings.dns.${key}`)}>
                  <input
                    type="number"
                    min="0"
                    value={dns[key]}
                    onChange={(event) => changeDNS(key, Number(event.target.value))}
                  />
                </Field>
              ))}
            </div>
            <h3>{t("settings.privateDNS")}</h3>
            {(dns.rules ?? []).map((rule, index) => (
              <div key={index} className={styles.dnsRule}>
                <Field label={t("rules.pattern")}>
                  <input
                    value={rule.suffix}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        config: {
                          ...draft.config,
                          dns: {
                            ...dns,
                            rules: dns.rules!.map((item, i) =>
                              i === index ? { ...item, suffix: event.target.value } : item,
                            ),
                          },
                        },
                      })
                    }
                  />
                </Field>
                <Field label={t("settings.servers")}>
                  <input
                    className="mono"
                    value={rule.servers.join(",")}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        config: {
                          ...draft.config,
                          dns: {
                            ...dns,
                            rules: dns.rules!.map((item, i) =>
                              i === index
                                ? {
                                    ...item,
                                    servers: event.target.value.split(","),
                                  }
                                : item,
                            ),
                          },
                        },
                      })
                    }
                  />
                </Field>
                <Field label={t("settings.interface")}>
                  <input
                    value={rule.interface ?? ""}
                    onChange={(event) =>
                      setDraft({
                        ...draft,
                        config: {
                          ...draft.config,
                          dns: {
                            ...dns,
                            rules: dns.rules!.map((item, i) =>
                              i === index ? { ...item, interface: event.target.value } : item,
                            ),
                          },
                        },
                      })
                    }
                  />
                </Field>
                <Button
                  tone="danger"
                  onClick={() =>
                    setDraft({
                      ...draft,
                      config: {
                        ...draft.config,
                        dns: { ...dns, rules: dns.rules!.filter((_, i) => i !== index) },
                      },
                    })
                  }
                >
                  {t("common.delete")}
                </Button>
              </div>
            ))}
            <Button
              onClick={() =>
                setDraft({
                  ...draft,
                  config: {
                    ...draft.config,
                    dns: { ...dns, rules: [...(dns.rules ?? []), { suffix: "", servers: [] }] },
                  },
                })
              }
            >
              {t("common.add")}
            </Button>
          </div>
        )}
      </fieldset>
      <ErrorNotice error={error} />
      <div className="formActions">
        {context.state.capture_locked && dirty && (
          <span className="inlineNote">{t("policy.pauseRequired")}</span>
        )}
        <Button
          onClick={() => {
            setDraft(structuredClone(base));
            setError(null);
          }}
          disabled={!dirty}
        >
          {t("common.cancel")}
        </Button>
        <Button
          type="submit"
          tone="primary"
          disabled={!dirty || busy || !context.admin || context.state.capture_locked}
        >
          {t("common.save")}
        </Button>
      </div>
    </form>
  );
}
function download(data: string, name: string, type: string) {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function DataSettings() {
  const { t } = useTranslation();
  const context = useConsole();
  const [text, setText] = useState("");
  const [base, setBase] = useState(context.document?.version);
  const [preview, setPreview] = useState<Record<string, Json> | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  useBlocker({
    shouldBlockFn: () => !!text && !window.confirm(t("common.unsaved")),
    enableBeforeUnload: !!text,
  });
  async function importConfig() {
    setBusy(true);
    setError(null);
    try {
      const result = await request<Record<string, Json>>(
        `/config/import${preview ? "" : "/validate"}`,
        { method: "POST", body: { base_version: base, toml: text } },
      );
      if (!preview) setPreview(result);
      else {
        setText("");
        setPreview(null);
        await context.refresh();
        context.notify({ key: "common.savedPaused" });
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  async function action(path: string) {
    setError(null);
    try {
      await request(path, { method: "POST", body: { base_version: context.document?.version } });
      await context.refresh();
      context.notify({ key: "common.savedPaused" });
    } catch (caught) {
      setError(caught);
    }
  }
  return (
    <>
      <div className={styles.sectionHeading}>
        <h2>{t("settings.data")}</h2>
        <Button
          onClick={() => {
            void request<string>("/export", { text: true })
              .then((value) => download(value, "kone-redacted.toml", "application/toml"))
              .catch(setError);
          }}
        >
          {t("settings.export")}
        </Button>
      </div>
      <p className="inlineNote">{t("settings.importHint")}</p>
      <div className="formStack">
        <Field label={t("settings.file")}>
          <input
            type="file"
            accept=".toml,text/plain"
            disabled={!context.admin}
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (file) {
                setText(await file.text());
                setBase(context.document?.version);
                setPreview(null);
              }
            }}
          />
        </Field>
        <Field label={t("settings.import")}>
          <textarea
            className="mono"
            spellCheck={false}
            value={text}
            onChange={(event) => {
              if (!text) setBase(context.document?.version);
              setText(event.target.value);
              setPreview(null);
            }}
          />
        </Field>
        <div className="actions">
          <Button
            tone="primary"
            disabled={
              !context.admin || !text || busy || (!!preview && context.state.capture_locked)
            }
            onClick={() => {
              void importConfig();
            }}
          >
            {t(preview ? "common.apply" : "settings.validate")}
          </Button>
          <Button
            onClick={() => {
              setText("");
              setPreview(null);
            }}
          >
            {t("common.cancel")}
          </Button>
        </div>
        {preview && (
          <div className="subtlePanel">
            <h3>{t("policy.preview")}</h3>
            <pre className="previewJSON">{JSON.stringify(preview, null, 2)}</pre>
          </div>
        )}
        <ErrorNotice error={error} />
      </div>
      <GeoIP />
      <Logging />
      <div className="subtlePanel">
        <h3>{t("settings.backup")}</h3>
        <div className="actions">
          <Button
            disabled={!context.admin}
            onClick={() => {
              if (window.confirm(t("settings.backup"))) void action("/config/undo");
            }}
          >
            {t("settings.backup")}
          </Button>
          <Button
            tone="danger"
            disabled={!context.admin || !context.state.local_access || context.state.capture_locked}
            onClick={() => {
              if (window.confirm(t("settings.resetHint"))) void action("/config/defaults");
            }}
          >
            {t("settings.reset")}
          </Button>
        </div>
      </div>
      <div className="subtlePanel">
        <p>{t("settings.retention")}</p>
        <Button
          disabled={!context.admin}
          onClick={() => {
            void request("/privacy/clear", { method: "POST", body: {} })
              .then(() => context.notify({ key: "common.success" }))
              .catch(setError);
          }}
        >
          {t("settings.clear")}
        </Button>
      </div>
    </>
  );
}
function GeoIP() {
  const { t } = useTranslation();
  const context = useConsole();
  const data = useQuery({
    queryKey: ["geoip"],
    queryFn: () =>
      request<{ saved: { sha256: string; provider: string; version: string }; previous?: Json }>(
        "/geoip",
      ),
  });
  const [file, setFile] = useState<File | null>(null);
  const [hash, setHash] = useState("");
  const [format, setFormat] = useState("kone-json");
  const [provider, setProvider] = useState("dbip-lite");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  async function apply(rollback = false) {
    setBusy(true);
    setError(null);
    try {
      if (rollback)
        await request("/geoip/rollback", {
          method: "POST",
          body: {
            base_version: context.document?.version,
            base_sha256: data.data?.saved.sha256 ?? "",
          },
        });
      else if (file)
        await request("/geoip", {
          method: "PUT",
          raw: true,
          body: file,
          headers: {
            "If-Match": String(context.document?.version),
            "X-GeoIP-Base-SHA256": data.data?.saved.sha256 ?? "",
            "X-Content-SHA256": hash,
            "X-GeoIP-Format": format,
            "X-GeoIP-Provider": provider,
          },
          timeout: 30000,
        });
      await data.refetch();
      await context.refresh();
      context.notify({ key: "common.saved" });
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="subtlePanel">
      <h3>{t("settings.geoip")}</h3>
      <KeyValues
        entries={[
          [t("settings.provider"), data.data?.saved.provider],
          [t("common.version"), data.data?.saved.version],
          ["SHA-256", <code key="sha256">{data.data?.saved.sha256}</code>],
        ]}
      />
      <details>
        <summary>{t("settings.upload")}</summary>
        <div className="formGrid">
          <Field label={t("settings.file")}>
            <input
              type="file"
              accept=".json,.mmdb"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            />
          </Field>
          <Field label={t("settings.provider")}>
            <select value={format} onChange={(event) => setFormat(event.target.value)}>
              <option value="kone-json">KONE JSON</option>
              <option value="mmdb">MMDB</option>
            </select>
          </Field>
          <Field label={t("settings.provider")}>
            <select value={provider} onChange={(event) => setProvider(event.target.value)}>
              <option value="dbip-lite">DB-IP</option>
              <option value="maxmind-geolite2">GeoLite2</option>
              <option value="ipinfo-lite">IPinfo Lite</option>
            </select>
          </Field>
          <Field label={t("settings.checksum")}>
            <input
              className="mono"
              value={hash}
              onChange={(event) => setHash(event.target.value)}
            />
          </Field>
        </div>
        <div className="formActions">
          <Button
            disabled={!file || !context.admin || context.state.capture_locked || busy}
            onClick={() => {
              void apply();
            }}
          >
            {t("settings.upload")}
          </Button>
          <Button
            disabled={
              !data.data?.previous || !context.admin || context.state.capture_locked || busy
            }
            onClick={() => {
              void apply(true);
            }}
          >
            {t("settings.rollback")}
          </Button>
        </div>
      </details>
      <ErrorNotice error={error || data.error} />
      <Details value={data.data} />
    </section>
  );
}
function Logging() {
  const { t } = useTranslation();
  const context = useConsole();
  const [edit, setEdit] = useState<{ base: Document; level: string; format: string } | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const doc = edit?.base ?? context.document;
  useBlocker({
    shouldBlockFn: () => !!edit && !window.confirm(t("common.unsaved")),
    enableBeforeUnload: !!edit,
  });
  if (!doc) return null;
  const values = edit ?? {
    base: doc,
    level: doc.config.general["log-level"],
    format: doc.config.general["log-format"],
  };
  return (
    <form
      className="subtlePanel"
      onSubmit={async (event) => {
        event.preventDefault();
        if (!edit) return;
        setBusy(true);
        setError(null);
        try {
          await context.save(edit.base, {
            ...edit.base.config,
            general: {
              ...edit.base.config.general,
              "log-level": edit.level,
              "log-format": edit.format,
            },
          });
          setEdit(null);
        } catch (caught) {
          setError(caught);
        } finally {
          setBusy(false);
        }
      }}
    >
      <h3>{t("settings.logSettings")}</h3>
      <div className="formGrid">
        <Field label={t("settings.logLevel")}>
          <select
            disabled={!context.admin}
            value={values.level}
            onChange={(event) => setEdit({ ...values, level: event.target.value })}
          >
            {["debug", "info", "warn", "error"].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </Field>
        <Field label={t("settings.logFormat")}>
          <select
            disabled={!context.admin}
            value={values.format}
            onChange={(event) => setEdit({ ...values, format: event.target.value })}
          >
            <option>text</option>
            <option>json</option>
          </select>
        </Field>
      </div>
      <div className="formActions">
        <Button onClick={() => setEdit(null)} disabled={!edit}>
          {t("common.cancel")}
        </Button>
        <Button
          type="submit"
          disabled={!edit || busy || !context.admin || context.state.capture_locked}
        >
          {t("common.save")}
        </Button>
      </div>
      <ErrorNotice error={error} />
    </form>
  );
}
function AccessSettings() {
  const { t } = useTranslation();
  const context = useConsole();
  const [error, setError] = useState<unknown>();
  const [pair, setPair] = useState<{ code: string; expires: string }>();
  const [role, setRole] = useState("read");
  const lan = useQuery({
    queryKey: ["lan"],
    queryFn: () =>
      request<{ enabled: boolean; address?: string; fingerprint?: string }>("/access/lan"),
  });
  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: () =>
      request<{
        sessions: { id: string; role: string; expires: string; local_access?: boolean }[];
      }>("/sessions"),
    enabled: context.admin,
  });
  return (
    <>
      <h2>{t("settings.access")}</h2>
      {context.admin && (
        <>
          <form
            className="formStack subtlePanel"
            onSubmit={async (event) => {
              event.preventDefault();
              const form = event.currentTarget,
                data = new FormData(form);
              setError(null);
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
                context.notify({ key: "common.saved" });
              } catch (caught) {
                setError(caught);
              }
            }}
          >
            <h3>{t("settings.password")}</h3>
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
            <div className="actions">
              <Button
                type="submit"
                disabled={!context.state.password_configured && !context.state.local_access}
              >
                {t(context.state.password_configured ? "settings.changePassword" : "auth.setup")}
              </Button>
            </div>
          </form>
          <form
            className="formStack subtlePanel"
            onSubmit={async (event) => {
              event.preventDefault();
              const values = new FormData(event.currentTarget);
              try {
                await request("/access/lan", {
                  method: "POST",
                  body: { enabled: values.get("enabled") === "on", address: values.get("address") },
                });
                await lan.refetch();
              } catch (caught) {
                setError(caught);
              }
            }}
          >
            <h3>{t("settings.lan")}</h3>
            <Status value={lan.data?.enabled ? "enabled" : "disabled"} />
            <p className="inlineNote">{t("settings.lanTrust")}</p>
            <KeyValues
              entries={[
                [t("common.address"), lan.data?.address],
                ["SHA-256", <code key="fingerprint">{lan.data?.fingerprint}</code>],
              ]}
            />
            <Field label={t("settings.listen")}>
              <input
                name="address"
                className="mono"
                placeholder="192.168.1.10:9443"
                defaultValue={lan.data?.address?.replace(/^https:\/\//, "")}
              />
            </Field>
            <label>
              <input type="checkbox" name="enabled" defaultChecked={lan.data?.enabled} />{" "}
              {t("common.enabled")}
            </label>
            <div className="actions">
              <Button type="submit" disabled={!context.state.local_access}>
                {t("common.save")}
              </Button>
              <Button
                disabled={!context.state.local_access}
                onClick={() => {
                  void request<string>("/access/certificate", { text: true })
                    .then((value) => download(value, "kone-ca.pem", "application/x-pem-file"))
                    .catch(setError);
                }}
              >
                {t("settings.certificate")}
              </Button>
            </div>
          </form>
          <div className="subtlePanel">
            <h3>{t("settings.pair")}</h3>
            <div className="actions">
              <select
                aria-label={t("common.admin")}
                value={role}
                onChange={(event) => setRole(event.target.value)}
              >
                <option value="read">{t("common.readonly")}</option>
                <option value="admin">{t("common.admin")}</option>
              </select>
              <Button
                disabled={!context.state.local_access}
                onClick={() => {
                  void request<{ code: string; expires: string }>("/pairing", {
                    method: "POST",
                    body: { role },
                  })
                    .then(setPair)
                    .catch(setError);
                }}
              >
                {t("settings.pair")}
              </Button>
            </div>
            {pair && (
              <p>
                <code>{pair.code}</code> <span className="muted">{timestamp(pair.expires)}</span>
              </p>
            )}
          </div>
          <div className="subtlePanel">
            <h3>{t("settings.sessions")}</h3>
            {sessions.data?.sessions.map((session) => (
              <div key={session.id} className={styles.session}>
                <span className="mono">{session.id}</span>
                <span>{t(session.role === "admin" ? "common.admin" : "common.readonly")}</span>
                <span className="muted">{timestamp(session.expires)}</span>
                <Button
                  disabled={session.id === context.state.session_id}
                  onClick={() => {
                    void request(`/sessions/${encodeURIComponent(session.id)}/revoke`, {
                      method: "POST",
                      body: {},
                    })
                      .then(() => sessions.refetch())
                      .catch(setError);
                  }}
                >
                  {t("settings.revoke")}
                </Button>
              </div>
            ))}
          </div>
        </>
      )}
      {!context.state.local_access && (
        <Button
          onClick={() => {
            void context.logout().catch(setError);
          }}
        >
          {t("auth.signout")}
        </Button>
      )}
      <ErrorNotice error={error || lan.error || sessions.error} />
    </>
  );
}
function Recovery() {
  const { t } = useTranslation();
  const context = useConsole();
  const [result, setResult] = useState<{
    required: boolean;
    ownership: string;
    can_clear: boolean;
    items: { kind: string; identity?: string; status: string; message: string }[];
  }>();
  const [error, setError] = useState<unknown>();
  return (
    <>
      <h2>{t("settings.recovery")}</h2>
      <p className="inlineNote">{t("settings.recoveryHint")}</p>
      <div className="actions">
        <Button
          onClick={() => {
            void request<NonNullable<typeof result>>("/recovery").then(setResult).catch(setError);
          }}
        >
          {t("settings.inspect")}
        </Button>
        <Button
          disabled={!context.admin || !context.state.local_access}
          onClick={() => {
            if (window.confirm(t("settings.recoveryHint")))
              void api.lifecycle("recover", { confirm: true }).then(context.track).catch(setError);
          }}
        >
          {t("settings.recover")}
        </Button>
      </div>
      <ErrorNotice error={error} />
      {result && (
        <div className="subtlePanel">
          <p>{t(result.required ? "recovery.required" : "recovery.clear")}</p>
          <p className="inlineNote">
            {t(`recovery.${result.ownership}`, { defaultValue: t("common.unknown") })}
          </p>
          {result.items.map((item, index) => (
            <div key={index} className={styles.session}>
              <strong>{t(`recovery.${item.kind}`, { defaultValue: t("common.details") })}</strong>
              <code>{item.identity}</code>
              <span>{t(`recovery.${item.status}`, { defaultValue: t("common.unknown") })}</span>
              <Details value={item} />
            </div>
          ))}
        </div>
      )}
    </>
  );
}
function InterfaceSettings() {
  const { t } = useTranslation();
  const [theme, setTheme] = useState(() => preference("theme", "dark"));
  const [density, setDensity] = useState(() => preference("density", "compact"));
  useEffect(() => {
    saveAppearance(theme, density);
  }, [theme, density]);
  return (
    <div className="formStack">
      <h2>{t("settings.interface")}</h2>
      <Field label={t("common.language")} help={t("settings.languageHint")}>
        <LanguageSelect />
      </Field>
      <Field label={t("common.theme")}>
        <select value={theme} onChange={(event) => setTheme(event.target.value)}>
          {["dark", "light", "system"].map((value) => (
            <option key={value} value={value}>
              {t(`common.${value}`)}
            </option>
          ))}
        </select>
      </Field>
      <Field label={t("common.density")}>
        <select value={density} onChange={(event) => setDensity(event.target.value)}>
          {["compact", "comfortable"].map((value) => (
            <option key={value} value={value}>
              {t(`common.${value}`)}
            </option>
          ))}
        </select>
      </Field>
    </div>
  );
}
function About() {
  const { t } = useTranslation();
  const { state } = useConsole();
  return (
    <>
      <h2>KONE</h2>
      <KeyValues
        entries={[
          [t("common.version"), state.version],
          [t("common.address"), state.host],
          [t("common.privacy"), t("settings.retention")],
        ]}
      />
      <p>{t("settings.offline")}</p>
      <p>GPL-3.0-or-later</p>
      <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">
        IP Geolocation by DB-IP
      </a>
      <Details value={state.capabilities} />
    </>
  );
}
