import {
  cloneElement,
  isValidElement,
  useId,
  type ComponentProps,
  type ReactElement,
  type ReactNode,
} from "react";
import { useTranslation } from "react-i18next";
import * as Dialog from "@radix-ui/react-dialog";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import * as ContextMenu from "@radix-ui/react-context-menu";
import { ApiError } from "../api/client";
import styles from "./ui.module.css";

export function Button({
  tone = "normal",
  className = "",
  ...props
}: ComponentProps<"button"> & { tone?: "normal" | "primary" | "danger" | "quiet" }) {
  return (
    <button type="button" className={`${styles.button} ${styles[tone]} ${className}`} {...props} />
  );
}
export function Field({
  label,
  help,
  error,
  children,
}: {
  label: string;
  help?: string;
  error?: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <div className={styles.field}>
      <label>
        <span className={styles.label}>{label}</span>
        {isValidElement(children) && typeof children.type === "string"
          ? cloneElement(children as ReactElement<Record<string, unknown>>, {
              "aria-label": label,
              "aria-describedby": help ? `${id}-help` : undefined,
              "aria-invalid": error ? true : undefined,
            })
          : children}
      </label>
      {help && <small id={`${id}-help`}>{help}</small>}
      {error && (
        <small className={styles.error} role="alert">
          {error}
        </small>
      )}
    </div>
  );
}
export function Status({ value, children }: { value: string; children?: ReactNode }) {
  const { t } = useTranslation();
  const tone = ["failed", "rejected", "error", "offline", "unhealthy"].includes(value)
    ? "danger"
    : ["running", "active", "succeeded", "ready", "success", "healthy", "reachable"].includes(value)
      ? "success"
      : ["starting", "pausing", "unknown", "warning", "unsupported", "stale"].includes(value)
        ? "warning"
        : "muted";
  const key = `common.${value}`;
  return (
    <span className={`${styles.status} ${styles[tone]}`}>
      <span className={styles.dot} />
      {children ??
        t(key, { defaultValue: t(`traffic.${value}`, { defaultValue: t("common.unknown") }) })}
    </span>
  );
}
export function ErrorNotice({ error, retry }: { error: unknown; retry?: () => void }) {
  const { t, i18n } = useTranslation();
  if (!error) return null;
  const key = error instanceof ApiError ? `api.${error.code}` : "api.request";
  const detail =
    error instanceof ApiError
      ? error.details.details || error.details.message
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    <div className={styles.notice} role="alert">
      <strong>
        {t(
          i18n.exists(key) ? key : "api.request",
          error instanceof ApiError ? error.details.params : {},
        )}
      </strong>
      {error instanceof ApiError && error.uncertain && <p>{t("common.uncertain")}</p>}
      {detail && (
        <details>
          <summary>{t("common.details")}</summary>
          <pre>{detail}</pre>
        </details>
      )}
      {retry && <Button onClick={retry}>{t("common.retry")}</Button>}
    </div>
  );
}
export function Empty({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <div className={styles.empty}>
      <span className={styles.emptyMark} aria-hidden="true">
        ∅
      </span>
      <h2>{title}</h2>
      {description && <p>{description}</p>}
      {children}
    </div>
  );
}
export function Modal({
  title,
  description,
  open,
  onClose,
  children,
}: {
  title: string;
  description?: string;
  open: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <Dialog.Root
      open={open}
      onOpenChange={(value) => {
        if (!value) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className={styles.overlay} />
        <Dialog.Content
          className={styles.modal}
          {...(description ? {} : { "aria-describedby": undefined })}
          onOpenAutoFocus={(event) => {
            const input = (event.currentTarget as HTMLElement).querySelector<HTMLInputElement>(
              "input,select,textarea",
            );
            if (input) {
              event.preventDefault();
              input.focus();
            }
          }}
        >
          <header>
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close asChild>
              <Button tone="quiet" aria-label={t("common.close")}>
                ×
              </Button>
            </Dialog.Close>
          </header>
          {description && <Dialog.Description>{description}</Dialog.Description>}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
export interface Action {
  id: string;
  label: string;
  run: () => void;
  disabled?: boolean;
  danger?: boolean;
  shortcut?: string;
}
export function ActionMenu({ actions, children }: { actions: Action[]; children?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <Dropdown.Root>
      <Dropdown.Trigger asChild>
        <Button tone="quiet" aria-label={t("common.more")}>
          {children ?? "⋯"}
        </Button>
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content className={styles.menu} align="end" sideOffset={4}>
          {actions.map((action) => (
            <Dropdown.Item
              key={action.id}
              className={styles.menuItem}
              disabled={action.disabled}
              onSelect={action.run}
              data-danger={action.danger}
            >
              {action.label}
              {action.shortcut && <kbd>{action.shortcut}</kbd>}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}
export function ContextActions({ actions, children }: { actions: Action[]; children: ReactNode }) {
  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content className={styles.menu}>
          {actions.map((action) => (
            <ContextMenu.Item
              key={action.id}
              className={styles.menuItem}
              disabled={action.disabled}
              onSelect={action.run}
              data-danger={action.danger}
            >
              {action.label}
            </ContextMenu.Item>
          ))}
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}
export function Details({ value }: { value: unknown }) {
  const { t } = useTranslation();
  return (
    <details className={styles.technical}>
      <summary>{t("common.details")}</summary>
      <pre>{JSON.stringify(value, null, 2)}</pre>
    </details>
  );
}
export function KeyValues({ entries }: { entries: [string, ReactNode][] }) {
  return (
    <dl className={styles.keyValues}>
      {entries.map(([label, value]) => (
        <div key={label}>
          <dt>{label}</dt>
          <dd>{value ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
export function Toggle({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className={styles.toggle}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        disabled={disabled}
      />
      <span>{label}</span>
    </label>
  );
}
