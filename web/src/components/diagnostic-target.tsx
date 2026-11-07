/* oxlint-disable jsx-a11y/prefer-tag-over-role -- An editable combobox needs a separate rich listbox; native select cannot accept typed targets. */
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { DiagnosticHistoryEntry } from "../diagnostic-history";
import styles from "../views/tools.module.css";

export function DiagnosticTarget({
  label,
  value,
  history,
  onChange,
  onSelect,
  onClear,
  placeholder,
}: {
  label: string;
  value: string;
  history: DiagnosticHistoryEntry[];
  onChange: (value: string) => void;
  onSelect: (entry: DiagnosticHistoryEntry) => void;
  onClear: () => void;
  placeholder: string;
}) {
  const { t } = useTranslation();
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [active, setActive] = useState(-1);
  const [anchor, setAnchor] = useState<{
    left: number;
    width: number;
    top?: number;
    bottom?: number;
  }>();
  useLayoutEffect(() => {
    if (!open) return;
    function position() {
      const rect = input.current?.parentElement?.getBoundingClientRect();
      if (!rect) return;
      const above =
        window.innerHeight - rect.bottom < 220 && rect.top > window.innerHeight - rect.bottom;
      setAnchor({
        left: rect.left,
        width: rect.width,
        ...(above ? { bottom: window.innerHeight - rect.top + 4 } : { top: rect.bottom + 4 }),
      });
    }
    position();
    window.addEventListener("resize", position);
    window.addEventListener("scroll", position, true);
    return () => {
      window.removeEventListener("resize", position);
      window.removeEventListener("scroll", position, true);
    };
  }, [open]);
  useEffect(() => {
    if (open && active >= 0)
      document.getElementById(`${id}-${active}`)?.scrollIntoView?.({ block: "nearest" });
  }, [open, active, id]);
  function description(entry: DiagnosticHistoryEntry) {
    if (entry.mode === "dns") return `${entry.dnsName} · ${entry.dnsType}`;
    if (entry.target === "www.google.com:443" && entry.tls) return t("diagnostics.google");
    if (entry.target === "149.154.167.50:443") return t("diagnostics.telegram");
    return entry.tls ? "TCP + TLS" : "TCP";
  }
  const choices = history.filter((entry) =>
    `${entry.target} ${description(entry)}`.toLowerCase().includes(filter.toLowerCase()),
  );
  function choose(entry: DiagnosticHistoryEntry) {
    onSelect(entry);
    setOpen(false);
    setActive(-1);
    input.current?.focus();
  }
  return (
    <div
      className={styles.targetPicker}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
    >
      <label htmlFor={id}>{label}</label>
      <div className={styles.targetInput}>
        <input
          id={id}
          ref={input}
          className="mono"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={open}
          aria-controls={open ? `${id}-history` : undefined}
          aria-activedescendant={open && active >= 0 ? `${id}-${active}` : undefined}
          autoComplete="off"
          spellCheck={false}
          value={value}
          required
          placeholder={placeholder}
          onFocus={() => {
            setFilter("");
            setActive(-1);
          }}
          onChange={(event) => {
            onChange(event.target.value);
            setFilter(event.target.value);
            setOpen(true);
            setActive(-1);
          }}
          onKeyDown={(event) => {
            if (event.key === "ArrowDown" || event.key === "ArrowUp") {
              event.preventDefault();
              setOpen(true);
              setActive((current) =>
                choices.length
                  ? current < 0
                    ? event.key === "ArrowDown"
                      ? 0
                      : choices.length - 1
                    : (current + (event.key === "ArrowDown" ? 1 : -1) + choices.length) %
                      choices.length
                  : -1,
              );
            } else if (event.key === "Enter" && open && choices[active]) {
              event.preventDefault();
              choose(choices[active]);
            } else if (event.key === "Escape" && open) {
              event.preventDefault();
              event.stopPropagation();
              setOpen(false);
            }
          }}
        />
        <button
          type="button"
          aria-label={t("diagnostics.history")}
          aria-expanded={open}
          onClick={() => {
            input.current?.focus();
            setFilter("");
            setActive(-1);
            setOpen(!open);
          }}
        >
          ▾
        </button>
      </div>
      {open && anchor && (
        <div className={styles.historyPopup} style={anchor}>
          <div className={styles.historyHeading}>
            <span>{t("diagnostics.history")}</span>
            {history.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  onClear();
                  setOpen(false);
                }}
              >
                {t("diagnostics.clearHistory")}
              </button>
            )}
          </div>
          <div
            id={`${id}-history`}
            className={styles.historyList}
            role="listbox"
            aria-label={t("diagnostics.history")}
          >
            {choices.map((entry, index) => (
              <div
                className={styles.historyOption}
                tabIndex={-1}
                onKeyDown={(event) => {
                  if (event.key === "Enter") choose(entry);
                }}
                key={index}
                id={`${id}-${index}`}
                role="option"
                aria-selected={active === index}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => choose(entry)}
              >
                <code>{entry.target}</code>
                <small>{description(entry)}</small>
              </div>
            ))}
          </div>
          {!choices.length && <p className="muted">{t("diagnostics.historyEmpty")}</p>}
        </div>
      )}
    </div>
  );
}
