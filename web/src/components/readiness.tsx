import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Button, ErrorNotice, Modal, Status } from "./ui";
import { canEnable } from "../readiness";
import type { Readiness, ReadinessCheck } from "../model";
import styles from "./readiness.module.css";

export function ReadinessDialog({
  report,
  busy,
  error,
  hasOutbounds,
  onClose,
  onCheck,
  onEnable,
}: {
  report: Readiness;
  busy: boolean;
  error: unknown;
  hasOutbounds: boolean;
  onClose: () => void;
  onCheck: () => void;
  onEnable: () => void;
}) {
  const { t, i18n } = useTranslation();
  const allowed = canEnable(report);
  const blockerIDs = new Set(report.blockers.map((check) => check.id));
  const warnings = report.checks.filter(
    (check) => !blockerIDs.has(check.id) && check.severity === "warning",
  );
  const passed = report.checks.filter(
    (check) => !blockerIDs.has(check.id) && check.severity !== "warning",
  );
  function entry(check: ReadinessCheck, blocked: boolean) {
    const titleKey = `check.${check.code}`;
    const detailKey =
      check.code === "outbound_health"
        ? `readiness.outbound_${check.status}`
        : `readiness.${check.code}`;
    const needsConsent = check.code === "direct_only_confirmation";
    const action = (() => {
      if (check.code === "privileges" || check.code === "canceled") return null;
      if (check.code === "configuration")
        return (
          <Link to="/settings" search={{ section: "data" }} onClick={onClose}>
            {t("readiness.repairConfig")}
          </Link>
        );
      if (["confirm_direct", "configure_rules"].includes(check.action || ""))
        return (
          <Link
            to="/policy"
            search={{ view: hasOutbounds ? "rules" : "outbounds" }}
            onClick={onClose}
          >
            {t(hasOutbounds ? "readiness.configureRules" : "outbounds.add")}
          </Link>
        );
      if (check.page === "outbounds")
        return (
          <Link to="/policy" search={{ view: "outbounds" }} onClick={onClose}>
            {t("readiness.openOutbounds")}
          </Link>
        );
      return (
        <Link
          to="/settings"
          search={{ section: check.page === "dns" ? "resolvers" : "capture" }}
          onClick={onClose}
        >
          {t(check.page === "dns" ? "readiness.openDNS" : "readiness.openCapture")}
        </Link>
      );
    })();
    return (
      <li key={check.id} className={styles.check} data-blocked={blocked}>
        <div className={styles.heading}>
          <strong>{t(titleKey, { defaultValue: t("check.preflight") })}</strong>
          <Status value={blocked ? "error" : check.severity === "warning" ? "warning" : "ready"}>
            {t(
              blocked
                ? needsConsent
                  ? "readiness.consent"
                  : "readiness.blocked"
                : check.severity === "warning"
                  ? "readiness.advisory"
                  : "common.ready",
            )}
          </Status>
        </div>
        {i18n.exists(detailKey) ? <p>{t(detailKey)}</p> : <p>{check.message}</p>}
        <div className={styles.actions}>
          <details className={styles.details}>
            <summary>{t("common.details")}</summary>
            <code>{check.code}</code>
            <pre>{check.message}</pre>
          </details>
          {(blocked || check.severity === "warning") && action}
        </div>
      </li>
    );
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={t("proxy.preflight")}
      description={t(
        report.blockers.length
          ? "readiness.remaining"
          : report.ready
            ? "readiness.ready"
            : "readiness.incomplete",
        {
          count: report.blockers.length,
        },
      )}
    >
      <div className={styles.content}>
        <ul className={styles.checks} aria-label={t("readiness.blockers")}>
          {[...report.blockers]
            .sort(
              (a, b) =>
                Number(a.code === "direct_only_confirmation") -
                Number(b.code === "direct_only_confirmation"),
            )
            .map((check) => entry(check, true))}
        </ul>
        {!allowed && !report.blockers.length && <p>{t("readiness.incomplete")}</p>}
        {warnings.length > 0 && (
          <details className={styles.group}>
            <summary>{t("readiness.warnings", { count: warnings.length })}</summary>
            <ul className={styles.checks}>{warnings.map((check) => entry(check, false))}</ul>
          </details>
        )}
        {passed.length > 0 && (
          <details className={styles.group}>
            <summary>{t("readiness.passed", { count: passed.length })}</summary>
            <ul className={styles.checks}>{passed.map((check) => entry(check, false))}</ul>
          </details>
        )}
        <ErrorNotice error={error} />
      </div>
      <div className={styles.footer}>
        <p id="readiness-start-hint">
          {t(
            !allowed
              ? "readiness.cannotEnable"
              : report.direct_only
                ? "proxy.directHint"
                : "readiness.ready",
          )}
        </p>
        <div className={styles.buttons}>
          <Button disabled={busy} onClick={onCheck}>
            {t(busy ? "common.loading" : "readiness.recheck")}
          </Button>
          <Button
            tone="primary"
            disabled={busy || !allowed}
            aria-describedby="readiness-start-hint"
            onClick={onEnable}
          >
            {t(report.direct_only ? "proxy.directConfirm" : "proxy.enable")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
