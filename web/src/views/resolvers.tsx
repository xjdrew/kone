import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole } from "../context";
import { api } from "../api/endpoints";
import { Button, Details, ErrorNotice, Field, KeyValues, Status } from "../components/ui";
import type { DNSConfig } from "../model";
import styles from "./resolvers.module.css";

export function ResolverFields({
  dns,
  onChange,
}: {
  dns: DNSConfig;
  onChange: (value: DNSConfig) => void;
}) {
  const { t } = useTranslation();
  const { state } = useConsole();
  const info = useQuery({
    queryKey: ["dns-configuration", state.state, state.running_version, state.saved_version],
    queryFn: ({ signal }) => api.dnsConfiguration(signal),
  });
  const mode = dns.mode || (dns.system ? "host" : "");
  const automatic = !dns.servers?.length;
  const interfaces = info.data?.interfaces ?? [];
  const current = info.data?.status;
  const set = (values: Partial<DNSConfig>) => onChange({ ...dns, ...values });
  const selectMode = (value: "host" | "gate") =>
    set({
      mode: value,
      system: value === "host",
      ...(value === "gate"
        ? {
            "listen-address": dns["listen-address"] || interfaces[0]?.address || "0.0.0.0",
            "listen-port": 53,
          }
        : { "listen-port": 53 }),
    });
  return (
    <div className={styles.resolvers}>
      <section className={styles.section}>
        <h3>{t("resolvers.mode")}</h3>
        <div>
          <fieldset className={styles.choices} aria-label={t("resolvers.mode")}>
            <button type="button" aria-pressed={mode === "host"} onClick={() => selectMode("host")}>
              {t("resolvers.host")}
            </button>
            <button type="button" aria-pressed={mode === "gate"} onClick={() => selectMode("gate")}>
              {t("resolvers.gate")}
            </button>
          </fieldset>
          <p className={styles.description}>
            {t(
              mode === "host"
                ? "resolvers.hostHint"
                : mode === "gate"
                  ? "resolvers.gateHint"
                  : "resolvers.legacyHint",
            )}
          </p>
          {mode === "host" && <p className={styles.path}>{t("resolvers.hostPath")}</p>}
          {mode === "gate" && (
            <>
              <div className={styles.listener}>
                <Field label={t("resolvers.listenAddress")}>
                  <select
                    value={dns["listen-address"] || ""}
                    onChange={(event) => set({ "listen-address": event.target.value })}
                  >
                    {!dns["listen-address"] && (
                      <option value="">{t("resolvers.chooseInterface")}</option>
                    )}
                    {interfaces.map((item) => (
                      <option key={item.address} value={item.address}>
                        {item.address} ({item.interface})
                      </option>
                    ))}
                    <option value="0.0.0.0">{t("resolvers.allIPv4")}</option>
                    <option value="::">{t("resolvers.allIPv6")}</option>
                    {dns["listen-address"] &&
                      !["0.0.0.0", "::", ...interfaces.map((item) => item.address)].includes(
                        dns["listen-address"]!,
                      ) && <option value={dns["listen-address"]}>{dns["listen-address"]}</option>}
                  </select>
                </Field>
                <Field label={t("resolvers.port")}>
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    required
                    value={dns["listen-port"]}
                    onChange={(event) => set({ "listen-port": Number(event.target.value) })}
                  />
                </Field>
                <span className="mono muted">UDP / TCP</span>
              </div>
              <p className={styles.description}>{t("resolvers.gateSetup")}</p>
            </>
          )}
        </div>
      </section>
      <section className={styles.section}>
        <h3>{t("resolvers.upstream")}</h3>
        <div>
          <fieldset className={styles.choices} aria-label={t("resolvers.upstream")}>
            <button type="button" aria-pressed={automatic} onClick={() => set({ servers: [] })}>
              {t("resolvers.automatic")}
            </button>
            <button
              type="button"
              aria-pressed={!automatic}
              onClick={() =>
                set({
                  servers: dns.servers?.length
                    ? dns.servers
                    : info.data?.defaults.servers.length
                      ? info.data.defaults.servers
                      : [""],
                })
              }
            >
              {t("resolvers.custom")}
            </button>
          </fieldset>
          {automatic ? (
            <>
              <p className={styles.description}>
                {t(
                  info.data?.running ? "resolvers.runningUpstreamHint" : "resolvers.automaticHint",
                )}
              </p>
              <div className={styles.addresses} aria-label={t("resolvers.discovered")}>
                {info.isPending ? (
                  <span className="muted">{t("common.loading")}</span>
                ) : (
                  info.data?.defaults.servers.map((server) => <code key={server}>{server}</code>)
                )}
              </div>
              {info.data?.defaults.public_fallback && (
                <p className={styles.warning} role="alert">
                  {t("resolvers.publicFallback")}
                </p>
              )}
              <Button tone="quiet" onClick={() => void info.refetch()} disabled={info.isFetching}>
                {t("resolvers.refresh")}
              </Button>
            </>
          ) : (
            <Field label={t("settings.servers")} help={t("resolvers.customHint")}>
              <textarea
                className="mono"
                required
                value={dns.servers?.join("\n") || ""}
                onChange={(event) => set({ servers: event.target.value.split("\n") })}
              />
            </Field>
          )}
          <ErrorNotice error={info.error} />
        </div>
      </section>
      <section className={styles.section}>
        <h3>{t("resolvers.status")}</h3>
        <div>
          <Status value={info.data?.running ? "running" : "paused"} />
          {info.data?.running ? (
            <KeyValues
              entries={[
                [
                  t("resolvers.mode"),
                  current?.mode === "gate"
                    ? t("resolvers.gate")
                    : current?.system_requested
                      ? t("resolvers.host")
                      : t("resolvers.legacy"),
                ],
                [t("resolvers.listener"), current?.listen_address || "—"],
                [
                  t("resolvers.systemDNS"),
                  current?.system_active ? t("resolvers.connected") : t("resolvers.unchanged"),
                ],
              ]}
            />
          ) : (
            <p className={styles.description}>{t("resolvers.pausedHint")}</p>
          )}
          {!!info.data?.defaults.warnings?.length && (
            <Details value={info.data.defaults.warnings} />
          )}
        </div>
      </section>
      <details className={styles.advanced}>
        <summary>{t("resolvers.advanced")}</summary>
        <h3>{t("settings.privateDNS")}</h3>
        {(dns.rules ?? []).map((rule, index) => (
          <div className={styles.rule} key={index}>
            <Field label={t("rules.pattern")}>
              <input
                value={rule.suffix}
                onChange={(event) =>
                  set({
                    rules: dns.rules!.map((item, i) =>
                      i === index ? { ...item, suffix: event.target.value } : item,
                    ),
                  })
                }
              />
            </Field>
            <Field label={t("settings.servers")}>
              <input
                className="mono"
                value={rule.servers.join(",")}
                onChange={(event) =>
                  set({
                    rules: dns.rules!.map((item, i) =>
                      i === index ? { ...item, servers: event.target.value.split(",") } : item,
                    ),
                  })
                }
              />
            </Field>
            <Field label={t("settings.interface")}>
              <input
                value={rule.interface || ""}
                onChange={(event) =>
                  set({
                    rules: dns.rules!.map((item, i) =>
                      i === index ? { ...item, interface: event.target.value } : item,
                    ),
                  })
                }
              />
            </Field>
            <Button
              tone="danger"
              onClick={() => set({ rules: dns.rules!.filter((_, i) => i !== index) })}
            >
              {t("common.delete")}
            </Button>
          </div>
        ))}
        <Button onClick={() => set({ rules: [...(dns.rules ?? []), { suffix: "", servers: [] }] })}>
          {t("common.add")}
        </Button>
        <div className={`formGrid ${styles.tuning}`}>
          {(
            [
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
                onChange={(event) => set({ [key]: Number(event.target.value) })}
              />
            </Field>
          ))}
        </div>
      </details>
    </div>
  );
}
