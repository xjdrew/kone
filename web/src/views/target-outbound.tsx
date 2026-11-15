import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../api/endpoints";
import { Button, ErrorNotice, Field } from "../components/ui";
import {
  matchingTargetRules,
  normalizeMatchPattern,
  ruleCoversHost,
  type RuleMatch,
} from "../target-rule";
import type { Config, RuleTarget } from "../model";
import styles from "./connection-health.module.css";

export function TargetOutbound({
  target,
  config,
  busy,
  error,
  onSelect,
  onClose,
}: {
  target: string;
  config: Config;
  busy: boolean;
  error: unknown;
  onSelect: (match: RuleMatch, outbound: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const query = useQuery({
    queryKey: ["rule-target", target],
    queryFn: ({ signal }) => api.ruleTarget(target, signal),
    staleTime: Infinity,
  });
  const editor = useRef<HTMLFieldSetElement>(null);
  useEffect(() => {
    const node = editor.current;
    function escape(event: KeyboardEvent) {
      if (event.key === "Escape" && !busy) {
        event.stopPropagation();
        onClose();
      }
    }
    node?.addEventListener("keydown", escape);
    return () => node?.removeEventListener("keydown", escape);
  }, [busy, onClose]);
  return (
    <fieldset ref={editor} aria-label={t("health.chooseOutbound")} className={styles.ruleEditor}>
      <header>
        <strong className="mono">{target}</strong>
        <Button tone="quiet" onClick={onClose} disabled={busy} aria-label={t("common.close")}>
          ×
        </Button>
      </header>
      <ErrorNotice
        error={error ?? query.error}
        retry={query.error ? () => void query.refetch() : undefined}
      />
      {query.isPending && <output>{t("common.loading")}</output>}
      {query.data && (
        <TargetRuleFields template={query.data} config={config} busy={busy} onSelect={onSelect} />
      )}
    </fieldset>
  );
}

function TargetRuleFields({
  template,
  config,
  busy,
  onSelect,
}: {
  template: RuleTarget;
  config: Config;
  busy: boolean;
  onSelect: (match: RuleMatch, outbound: string) => void;
}) {
  const { t } = useTranslation();
  const [type, setType] = useState(template.type);
  const [value, setValue] = useState(template.pattern);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => input.current?.focus(), []);
  const domain = template.type.startsWith("DOMAIN");
  const match = { type, pattern: normalizeMatchPattern(type, value) };
  const valid = ruleCoversHost(template.host, match);
  const existing = matchingTargetRules(config, match);
  const scope =
    type === "DOMAIN-SUFFIX"
      ? "suffix"
      : type === "DOMAIN-KEYWORD"
        ? "keyword"
        : domain
          ? "exact"
          : "address";
  return (
    <>
      <div className={styles.ruleFields}>
        <Field label={t("rules.type")}>
          <select
            value={type}
            disabled={busy}
            onChange={(event) => {
              const next = event.target.value;
              setType(next);
              setValue(
                next === "DOMAIN"
                  ? template.host
                  : next === "DOMAIN-KEYWORD"
                    ? (template.keyword ?? template.host)
                    : template.pattern,
              );
            }}
          >
            {(domain ? ["DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD"] : [template.type]).map(
              (item) => (
                <option key={item}>{item}</option>
              ),
            )}
          </select>
        </Field>
        <Field
          label={t("health.matchValue")}
          error={valid ? undefined : t("health.targetMismatch")}
        >
          <input
            ref={input}
            className="mono"
            value={value}
            readOnly={!domain}
            disabled={busy}
            onChange={(event) => setValue(event.target.value)}
          />
        </Field>
      </div>
      <p className={styles.ruleScope} aria-live="polite">
        {valid ? t(`health.match.${scope}`, { pattern: match.pattern }) : ""}
      </p>
      <p className={styles.ruleScope}>
        {existing.length
          ? t("health.updateRules", { count: existing.length })
          : t("health.newRule")}
      </p>
      <div className={styles.ruleOutbounds} aria-label={t("common.outbound")}>
        <span>{t("health.selectToSave")}</span>
        {[{ name: "direct", enabled: true }, ...config.outbounds]
          .filter((outbound) => outbound.enabled !== false)
          .map((outbound) => (
            <Button
              key={outbound.name}
              disabled={busy || !valid}
              onClick={() => onSelect(match, outbound.name)}
            >
              {outbound.name}
            </Button>
          ))}
      </div>
    </>
  );
}
