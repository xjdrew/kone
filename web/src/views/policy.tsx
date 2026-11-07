import { useState } from "react";
import { Link, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { useConsole, useWorkspaceState } from "../context";
import { api } from "../api/endpoints";
import { request } from "../api/client";
import { addPreciseRule, targetHost, saveRequest } from "../domain";
import {
  Button,
  Field,
  Modal,
  ErrorNotice,
  Toggle,
  KeyValues,
  Details,
  ActionMenu,
  Empty,
} from "../components/ui";
import { OutboundsView } from "./outbounds";
import type { Config, Document, PolicyPlan, PolicyRequest, Rule } from "../model";
import styles from "./policy.module.css";

export function OutboundSelect({
  value,
  onChange,
  proxiesOnly = false,
  disabled = false,
}: {
  value: string;
  onChange: (value: string) => void;
  proxiesOnly?: boolean;
  disabled?: boolean;
}) {
  const { t } = useTranslation();
  const { document } = useConsole();
  return (
    <select
      aria-label={t("common.outbound")}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      disabled={disabled}
    >
      {!proxiesOnly && value === "" && <option value="">{t("common.choose")}</option>}
      {proxiesOnly ? (
        <option value="">{t("common.choose")}</option>
      ) : (
        <>
          <option value="direct">{t("outbounds.direct")}</option>
          <option value="reject">{t("outbounds.reject")}</option>
        </>
      )}
      {document?.config.outbounds.map((outbound) => (
        <option
          key={outbound.id}
          value={outbound.name}
          disabled={proxiesOnly && outbound.enabled === false}
        >
          {outbound.name}
        </option>
      ))}
    </select>
  );
}
export function OutboundName({ name }: { name: string }) {
  const { t } = useTranslation();
  return <span>{["direct", "reject"].includes(name) ? t(`outbounds.${name}`) : name || "—"}</span>;
}

export function PolicyView() {
  const { t } = useTranslation();
  const { view } = useSearch({ from: "/policy" });
  const context = useConsole();
  const policy = useQuery({
    queryKey: ["policy", context.document?.version],
    queryFn: api.policy,
    enabled: !!context.document,
  });
  const [changePolicy, setChangePolicy] = useState(false);
  return (
    <section className="view">
      <header className="viewHeader">
        <div>
          <h1>{t("policy.title")}</h1>
          <p>{t("policy.subtitle")}</p>
        </div>
        <div className="actions">
          <span className="pill">{t(`policy.${policy.data?.mode ?? "custom"}`)}</span>
          {policy.data?.mode === "proxy-first" && policy.data.ipv4_only && (
            <span className="pill">IPv4</span>
          )}
          {policy.data?.mode === "proxy-first" && policy.data.udp_exception && (
            <span className="pill">{t("policy.direct_exception")}</span>
          )}
          <Button onClick={() => setChangePolicy(true)} disabled={!context.admin || !policy.data}>
            {t("policy.change")}
          </Button>
        </div>
      </header>
      <nav className="viewTabs">
        <Link
          to="/policy"
          search={{ view: "rules" }}
          aria-current={view === "rules" ? "page" : undefined}
        >
          {t("nav.rules")}
        </Link>
        <Link
          to="/policy"
          search={{ view: "outbounds" }}
          aria-current={view === "outbounds" ? "page" : undefined}
        >
          {t("nav.outbounds")}
        </Link>
      </nav>
      <ErrorNotice error={policy.error} />
      {view === "outbounds" ? (
        <OutboundsView />
      ) : (
        <>
          <details className={styles.protection}>
            <summary>
              {t("policy.protection")}
              <span>{t("policy.protectedHint")}</span>
            </summary>
            <div className={styles.protectionList}>
              {policy.data?.protection.map((item) => (
                <div key={`${item.prefix}:${item.interface}`}>
                  <code>{item.prefix}</code>
                  <span>{item.interface || t(`policy.${item.kind}`)}</span>
                </div>
              ))}
            </div>
            {!policy.data?.explicit && <p>{t("policy.legacyHint")}</p>}
          </details>
          <RulesView onPolicy={() => setChangePolicy(true)} />
        </>
      )}
      {changePolicy && policy.data && (
        <PolicyEditor
          initial={{
            base_version: policy.data.version,
            mode: policy.data.mode === "custom" ? "direct-first" : policy.data.mode,
            outbound: policy.data.outbound === "direct" ? "" : policy.data.outbound,
            interface: policy.data.interface,
            ipv4_only: policy.data.ipv4_only,
            udp_exception: policy.data.udp_exception,
            reject_udp: false,
            convert_custom: false,
          }}
          custom={policy.data.mode === "custom"}
          interfaces={policy.data.interfaces}
          onClose={() => setChangePolicy(false)}
        />
      )}
    </section>
  );
}
function PolicyEditor({
  initial,
  custom,
  interfaces,
  onClose,
}: {
  initial: PolicyRequest;
  custom: boolean;
  interfaces: string[];
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const context = useConsole();
  const [baseDocument] = useState(context.document);
  const [draft, setDraft] = useState(initial);
  const [plan, setPlan] = useState<PolicyPlan>();
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  function close() {
    if (JSON.stringify(draft) === JSON.stringify(initial) || window.confirm(t("common.unsaved")))
      onClose();
  }
  const update = (key: keyof PolicyRequest, value: string | boolean) => {
    setDraft({ ...draft, [key]: value });
    setPlan(undefined);
  };
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      if (!plan) setPlan(await api.policyPreview(draft));
      else {
        const result = await api.policyApply(draft);
        await context.refresh();
        context.notify({
          key: result.apply_error
            ? "common.savedNotApplied"
            : result.applied
              ? "common.applied"
              : "common.savedPaused",
          details: result.apply_error,
          undo: baseDocument
            ? async () => {
                await api.save(
                  saveRequest({ ...baseDocument, version: result.version }, baseDocument.config),
                );
                await context.refresh();
                context.notify({ key: "common.saved" });
              }
            : undefined,
        });
        onClose();
      }
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal open onClose={close} title={t("policy.change")} description={t("policy.retain")}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <div className="formStack">
          <Field label={t("policy.title")}>
            <select value={draft.mode} onChange={(event) => update("mode", event.target.value)}>
              <option value="direct-first">{t("policy.direct-first")}</option>
              <option value="proxy-first">{t("policy.proxy-first")}</option>
            </select>
          </Field>
          {draft.mode === "proxy-first" && (
            <>
              <Field label={t("policy.defaultOutbound")}>
                <OutboundSelect
                  value={draft.outbound}
                  proxiesOnly
                  onChange={(value) => update("outbound", value)}
                />
              </Field>
              <Field label={t("policy.interface")}>
                <select
                  required
                  value={draft.interface}
                  onChange={(event) => update("interface", event.target.value)}
                >
                  <option value="">{t("common.choose")}</option>
                  {interfaces.map((name) => (
                    <option key={name}>{name}</option>
                  ))}
                </select>
              </Field>
              <Toggle
                checked={draft.ipv4_only}
                onChange={(value) => update("ipv4_only", value)}
                label={t("policy.ipv4Only")}
              />
              <Toggle
                checked={draft.udp_exception}
                onChange={(value) => update("udp_exception", value)}
                label={t("policy.udpException")}
              />
              <Toggle
                checked={draft.reject_udp}
                onChange={(value) => update("reject_udp", value)}
                label={t("policy.rejectUDP")}
              />
              {draft.reject_udp && <p className="inlineNote">{t("policy.rejectImpact")}</p>}
            </>
          )}
          {custom && (
            <Toggle
              checked={draft.convert_custom}
              onChange={(value) => update("convert_custom", value)}
              label={t("policy.convertCustom")}
            />
          )}
          {plan && (
            <div className="subtlePanel">
              <KeyValues
                entries={[
                  [
                    t("policy.coverage"),
                    `${plan.config.core["auto-route"] ? "IPv4" : t("policy.direct-first")}${plan.config.core["auto-route6"] ? " + IPv6" : ""}`,
                  ],
                  [
                    t("policy.defaultOutbound"),
                    `${baseDocument?.config.rules.at(-1)?.outbound || "direct"} → ${plan.config.rules.at(-1)?.outbound}`,
                  ],
                  [t("policy.udp"), t(`policy.${plan.udp}`)],
                  [t("policy.preserved"), plan.preserved_rules],
                  [t("policy.protection"), plan.protection.length],
                ]}
              />
              {draft.reject_udp && (
                <p>
                  {t("policy.rejectImpact")}:{" "}
                  {baseDocument?.config.rules
                    .filter((rule) => rule.outbound === draft.outbound)
                    .map((rule) => `${rule.type} ${rule.pattern || ""}`)
                    .join(", ")}
                </p>
              )}
              {custom && (
                <div>
                  <strong>{t("policy.convertCustom")}</strong>
                  <pre>{JSON.stringify(baseDocument?.config.rules.at(-1), null, 2)}</pre>
                </div>
              )}
              {plan.restart_required && context.state.capture_locked && (
                <p className="dangerText">{t("policy.pauseRequired")}</p>
              )}
              <Details value={plan} />
            </div>
          )}
          <ErrorNotice error={error} />
        </div>
        <div className="formActions">
          <Button onClick={close}>{t("common.cancel")}</Button>
          <Button
            tone="primary"
            type="submit"
            disabled={busy || (plan?.restart_required && context.state.capture_locked)}
          >
            {t(busy ? "common.loading" : plan ? "common.apply" : "common.preview")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
function RulesView({ onPolicy }: { onPolicy: () => void }) {
  const { t } = useTranslation();
  const context = useConsole();
  const [search, setSearch] = useWorkspaceState("rules.search", "");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [simulate, setSimulate] = useState(false);
  const doc = context.document;
  if (!doc) return <div className="loading">{t("common.loading")}</div>;
  const rules = doc.config.rules.filter((rule) => rule.type !== "FINAL");
  const visible = rules.filter((rule) =>
    `${rule.type} ${rule.pattern} ${rule.outbound}`.toLowerCase().includes(search.toLowerCase()),
  );
  const final = doc.config.rules.find((rule) => rule.type === "FINAL");
  async function save(config: Config) {
    setBusy(true);
    setError(null);
    try {
      await context.save(doc!, config);
      setSelected(new Set());
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  function move(rule: Rule, delta: number) {
    const config = structuredClone(doc!.config);
    const index = config.rules.findIndex((item) => item.id === rule.id);
    if (index + delta < 0 || config.rules[index + delta]?.type === "FINAL") return;
    [config.rules[index], config.rules[index + delta]] = [
      config.rules[index + delta],
      config.rules[index],
    ];
    void save(config);
  }
  function remove(ids: Set<string>) {
    void save({ ...doc!.config, rules: doc!.config.rules.filter((rule) => !ids.has(rule.id)) });
  }
  const newRule = (type = "DOMAIN") =>
    context.setRuleDraft({
      id: crypto.randomUUID(),
      type,
      pattern: "",
      outbound: "direct",
      source: "user",
    });
  return (
    <>
      <div className="toolbar">
        <input
          type="search"
          data-search
          placeholder={t("common.search")}
          aria-label={t("common.search")}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <span className="spacer" />
        <Button onClick={() => setSimulate(true)} disabled={!context.admin}>
          {t("rules.simulate")}
        </Button>
        <Button onClick={() => newRule("GEOIP")} disabled={!context.admin}>
          {t("policy.country")}
        </Button>
        <Button tone="primary" onClick={() => newRule()} disabled={!context.admin}>
          {t("policy.addRule")}
        </Button>
      </div>
      <ErrorNotice error={error} />
      {!!selected.size && (
        <div className="toolbar">
          <span>{t("common.selected", { count: selected.size })}</span>
          <OutboundSelect
            value=""
            onChange={(outbound) => {
              void save({
                ...doc.config,
                rules: doc.config.rules.map((rule) =>
                  selected.has(rule.id) ? { ...rule, outbound } : rule,
                ),
              });
            }}
          />
          <Button tone="danger" disabled={busy} onClick={() => remove(selected)}>
            {t("common.delete")}
          </Button>
          <Button tone="quiet" onClick={() => setSelected(new Set())}>
            {t("common.cancel")}
          </Button>
        </div>
      )}
      <div className="tableWrap">
        <table className="dataTable">
          <thead>
            <tr>
              <th>
                <input
                  type="checkbox"
                  aria-label={t("common.selectAll")}
                  disabled={!context.admin}
                  checked={visible.length > 0 && visible.every((rule) => selected.has(rule.id))}
                  onChange={(event) =>
                    setSelected(
                      event.target.checked ? new Set(visible.map((rule) => rule.id)) : new Set(),
                    )
                  }
                />
              </th>
              <th>#</th>
              <th>{t("rules.type")}</th>
              <th>{t("rules.pattern")}</th>
              <th>{t("common.protocol")}</th>
              <th>{t("rules.ports")}</th>
              <th>{t("common.outbound")}</th>
              <th>{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((rule) => (
              <tr key={rule.id}>
                <td>
                  <input
                    type="checkbox"
                    disabled={!context.admin}
                    aria-label={`${t("common.edit")} ${rule.pattern}`}
                    checked={selected.has(rule.id)}
                    onChange={(event) =>
                      setSelected((previous) => {
                        const next = new Set(previous);
                        if (event.target.checked) next.add(rule.id);
                        else next.delete(rule.id);
                        return next;
                      })
                    }
                  />
                </td>
                <td className="muted mono">{rules.indexOf(rule) + 1}</td>
                <td className="mono muted">{rule.type}</td>
                <td className="targetCell mono">
                  <button
                    className="textButton"
                    disabled={!context.admin}
                    onClick={() => context.setRuleDraft(rule)}
                  >
                    {rule.pattern}
                  </button>
                  {rule["expires-at"] && (
                    <span className="pill">
                      {t("rules.expires")} {rule["expires-at"]}
                    </span>
                  )}
                </td>
                <td className="mono">{rule.protocol || t("common.all")}</td>
                <td className="mono">{rule.ports?.join(", ") || "*"}</td>
                <td>
                  <OutboundSelect
                    value={rule.outbound}
                    disabled={!context.admin || busy}
                    onChange={(outbound) => {
                      void save({
                        ...doc.config,
                        rules: doc.config.rules.map((item) =>
                          item.id === rule.id ? { ...item, outbound } : item,
                        ),
                      });
                    }}
                  />
                </td>
                <td>
                  <ActionMenu
                    actions={[
                      {
                        id: "edit",
                        label: t("common.edit"),
                        run: () => context.setRuleDraft(rule),
                        disabled: !context.admin,
                      },
                      {
                        id: "up",
                        label: t("rules.moveUp"),
                        run: () => move(rule, -1),
                        disabled: !context.admin || rules.indexOf(rule) === 0 || busy,
                      },
                      {
                        id: "down",
                        label: t("rules.moveDown"),
                        run: () => move(rule, 1),
                        disabled:
                          !context.admin || rules.indexOf(rule) === rules.length - 1 || busy,
                      },
                      {
                        id: "delete",
                        label: t("common.delete"),
                        danger: true,
                        run: () => remove(new Set([rule.id])),
                        disabled: !context.admin || busy,
                      },
                    ]}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length && (
          <Empty title={t("policy.empty")}>
            <Button onClick={() => newRule()} disabled={!context.admin}>
              {t("policy.addRule")}
            </Button>
          </Empty>
        )}
      </div>
      <div className={styles.fallback}>
        <span>{t("policy.fallback")}</span>
        <span className="mono">FINAL</span>
        <OutboundName name={final?.outbound ?? "direct"} />
        {final?.protocol && (
          <span>
            {final.protocol} {final.ports?.join(", ")}
          </span>
        )}
        <Button
          tone="quiet"
          onClick={() =>
            final && (final.protocol || final.ports?.length || final.outbound === "reject")
              ? context.setRuleDraft(final)
              : onPolicy()
          }
          disabled={!context.admin}
        >
          {t("common.edit")}
        </Button>
      </div>
      {simulate && <Simulation onClose={() => setSimulate(false)} />}
    </>
  );
}
export function RuleComposer({ initial, onClose }: { initial: Rule; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const context = useConsole();
  const countries = new Intl.DisplayNames([i18n.language], { type: "region", fallback: "none" });
  const countryCodes = Array.from({ length: 676 }, (_, index) =>
    String.fromCharCode(65 + Math.floor(index / 26), 65 + (index % 26)),
  ).filter((code) => countries.of(code));
  const geoip = useQuery({
    queryKey: ["geoip"],
    queryFn: () => request<{ saved: { provider: string; version: string } }>("/geoip"),
    enabled: initial.type === "GEOIP",
  });
  const [base] = useState<Document | undefined>(context.document);
  const [draft, setDraft] = useState<Rule>(structuredClone(initial));
  const [ports, setPorts] = useState(initial.ports?.join(", ") || "");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const dirty =
    JSON.stringify(draft) !== JSON.stringify(initial) ||
    ports !== (initial.ports?.join(", ") || "");
  function close() {
    if (!dirty || window.confirm(t("common.unsaved"))) onClose();
  }
  async function submit() {
    if (!base) return;
    setBusy(true);
    setError(null);
    try {
      const rule = {
        ...draft,
        ports: ports.trim() ? ports.split(/[,\s]+/).map(Number) : undefined,
      };
      if (rule.ports?.some((port) => !Number.isInteger(port) || port < 1 || port > 65535))
        throw new Error(t("common.fieldError"));
      const existing = base.config.rules.some((item) => item.id === rule.id);
      const config = existing
        ? {
            ...base.config,
            rules: base.config.rules.map((item) => (item.id === rule.id ? rule : item)),
          }
        : addPreciseRule(base.config, rule);
      await context.save(base, config);
      onClose();
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
      title={t("traffic.createRule")}
      description={initial.source === "one-click" ? t("rules.exactScope") : undefined}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <div className="formGrid">
          <Field label={t("rules.type")}>
            <select
              value={draft.type}
              onChange={(event) => setDraft({ ...draft, type: event.target.value })}
            >
              {(initial.type === "FINAL"
                ? ["FINAL"]
                : ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "GEOIP"]
              ).map((type) => (
                <option key={type}>{type}</option>
              ))}
            </select>
          </Field>
          <Field label={t("common.outbound")}>
            <OutboundSelect
              value={draft.outbound}
              onChange={(outbound) => setDraft({ ...draft, outbound })}
            />
          </Field>
          {draft.type !== "FINAL" && (
            <div className="wide">
              <Field label={t(draft.type === "GEOIP" ? "rules.countryCode" : "rules.pattern")}>
                <input
                  list={draft.type === "GEOIP" ? "country-codes" : undefined}
                  maxLength={draft.type === "GEOIP" ? 2 : undefined}
                  required
                  className="mono"
                  value={draft.pattern ?? ""}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      pattern:
                        draft.type === "GEOIP"
                          ? event.target.value.toUpperCase()
                          : event.target.value,
                    })
                  }
                />
              </Field>
              {draft.type === "GEOIP" && (
                <datalist id="country-codes">
                  {countryCodes.map((code) => (
                    <option key={code} value={code}>
                      {countries.of(code)}
                    </option>
                  ))}
                </datalist>
              )}
            </div>
          )}
          <Field label={t("common.protocol")}>
            <select
              value={draft.protocol ?? ""}
              onChange={(event) => setDraft({ ...draft, protocol: event.target.value })}
            >
              <option value="">{t("common.all")}</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </Field>
          <Field label={t("rules.ports")}>
            <input
              value={ports}
              onChange={(event) => setPorts(event.target.value)}
              placeholder={t("rules.allPorts")}
            />
          </Field>
          {draft.type.startsWith("DOMAIN") && (
            <div className="wide">
              <Field label={t("rules.expires")}>
                <input
                  value={draft["expires-at"] ?? ""}
                  placeholder="2026-12-01T12:00:00Z"
                  onChange={(event) =>
                    setDraft({ ...draft, "expires-at": event.target.value || undefined })
                  }
                />
              </Field>
            </div>
          )}
          {draft.type === "GEOIP" && (
            <div className="inlineNote wide">
              <p>{t("rules.geoipHint")}</p>
              <p>
                {t("settings.provider")}: {geoip.data?.saved.provider || "—"} ·{" "}
                {geoip.data?.saved.version || "—"} ·{" "}
                <Link to="/settings" search={{ section: "data" }} onClick={close}>
                  {t("settings.geoip")}
                </Link>
              </p>
              <ErrorNotice error={geoip.error} />
            </div>
          )}
        </div>
        <ErrorNotice error={error} />
        <div className="formActions">
          <Button onClick={close}>{t("common.cancel")}</Button>
          <Button type="submit" tone="primary" disabled={!context.admin || busy || !base}>
            {t(busy ? "common.loading" : "common.save")}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
function Simulation({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [target, setTarget] = useState("");
  const [protocol, setProtocol] = useState("tcp");
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState<unknown>();
  return (
    <Modal open onClose={onClose} title={t("rules.simulate")} description={t("rules.simulateHint")}>
      <form
        className="formStack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError(null);
          const parsed = targetHost(target);
          try {
            setResult(
              await request("/rules/simulate", {
                method: "POST",
                body: { target: parsed.host, port: parsed.port || 0, protocol },
              }),
            );
          } catch (caught) {
            setError(caught);
          }
        }}
      >
        <Field label={t("common.target")}>
          <input required value={target} onChange={(event) => setTarget(event.target.value)} />
        </Field>
        <Field label={t("common.protocol")}>
          <select value={protocol} onChange={(event) => setProtocol(event.target.value)}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </Field>
        <Button type="submit">{t("rules.simulate")}</Button>
        <ErrorNotice error={error} />
        {result !== undefined && <Details value={result} />}
      </form>
    </Modal>
  );
}
