import { toolTabs } from "./tool-panel";
import { ErrorToasts, NotificationCount } from "./components/error-history";
import { useEffect, useState, useRef } from "react";
import { Link, Outlet, useLocation, useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { useConsole } from "./context";
import { api } from "./api/endpoints";
import { ApiError } from "./api/client";
import { Button, ErrorNotice, Modal, Status } from "./components/ui";
import { ReadinessDialog } from "./components/readiness";
import { DNSFallbackNotice } from "./components/dns-fallback-notice";
import { canEnable } from "./readiness";
import { Tools } from "./views/tools";
import { RuleComposer } from "./views/policy";
import { changeLanguage, languages } from "./i18n";
import { formatBytes } from "./domain";
import type { Readiness } from "./model";

export function Shell() {
  const { t } = useTranslation();
  const context = useConsole();
  const statusbar = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!statusbar.current) return;
    const update = () =>
      document.documentElement.style.setProperty(
        "--statusbar-height",
        `${statusbar.current?.getBoundingClientRect().height ?? 36}px`,
      );
    const observer = new ResizeObserver(update);
    observer.observe(statusbar.current);
    update();
    return () => {
      observer.disconnect();
      document.documentElement.style.removeProperty("--statusbar-height");
    };
  }, []);
  const navigate = useNavigate();
  const location = useLocation();
  const { state, admin, connectionError, tool, setTool, toast, notify, operation, ruleDraft } =
    context;
  useEffect(() => {
    if (location.pathname !== "/settings") context.workspace.set("returnHref", location.href);
  }, [location.pathname, location.href, context.workspace]);
  const [commands, setCommands] = useState(false);
  const [search, setSearch] = useState("");
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [authorizationExpected, setAuthorizationExpected] = useState(false);
  const running = state.data_state === "running" || state.state === "running";
  const policyMode =
    context.document?.config.policy?.mode ||
    (context.document?.config.rules.at(-1)?.outbound === "direct" ? "direct-first" : "custom");
  async function checkReadiness() {
    setBusy(true);
    setError(null);
    try {
      setReadiness(await api.readiness());
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }
  async function lifecycle() {
    setBusy(true);
    setError(null);
    try {
      if (!running) {
        const result = await api.readiness();
        setAuthorizationExpected(
          result.checks.some((check) => check.code === "privileges" && check.severity === "info"),
        );
        if (!canEnable(result)) {
          setReadiness(result);
          return;
        }
      }
      const op = await api.lifecycle(running ? "pause" : "start");
      context.track(op);
      setReadiness(null);
    } catch (caught) {
      setError(caught);
      if (caught instanceof ApiError && caught.uncertain) await context.refresh();
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    function key(event: KeyboardEvent) {
      if (document.querySelector('[role="dialog"][data-state="open"]')) return;
      const editing =
        event.target instanceof HTMLElement &&
        (event.target.matches("input,textarea,select") || event.target.isContentEditable);
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommands((value) => !value);
      }
      if (event.key === "Escape") setTool(null);
      if (!editing && !event.metaKey && !event.ctrlKey && event.key === "/") {
        const input = document.querySelector<HTMLInputElement>("[data-search]");
        if (input) {
          event.preventDefault();
          input.focus();
        }
      }
    }
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [setTool]);
  const actions = [
    ...["overview", "connections", "dns"].map((view) => ({
      id: view,
      label: t(`nav.${view}`),
      run: () => {
        void navigate({
          to: "/traffic",
          search: {
            view,
            target: "",
            anchor: "",
            flow_ids: "",
            path_ids: "",
            window_start: undefined,
            window_end: undefined,
          },
        });
      },
    })),
    ...["rules", "outbounds"].map((view) => ({
      id: view,
      label: t(`nav.${view}`),
      run: () => {
        if (view === "outbounds") void navigate({ to: "/outbounds" });
        else void navigate({ to: "/policy", search: { view: "rules" } });
      },
    })),
    {
      id: "settings",
      label: t("nav.settings"),
      run: () => {
        void navigate({ to: "/settings", search: { section: "interface" } });
      },
    },
    { id: "diagnostics", label: t("nav.diagnostics"), run: () => setTool("diagnostics") },
    { id: "logs", label: t("nav.logs"), run: () => setTool("logs") },
    ...languages.map((language) => ({
      id: language.tag,
      label: language.name,
      run: () => {
        void changeLanguage(language.tag);
      },
    })),
    {
      id: "auto",
      label: t("common.auto"),
      run: () => {
        void changeLanguage("auto");
      },
    },
    ...(admin
      ? [
          {
            id: "lifecycle",
            label: t(running ? "proxy.pause" : "proxy.enable"),
            run: () => {
              void lifecycle();
            },
          },
        ]
      : []),
  ].filter((action) => action.label.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  return (
    <div className="console">
      <a
        className="skipLink"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        {t("common.skip")}
      </a>
      <header className="topbar">
        <Link
          className="brand"
          aria-label="KONE"
          to="/traffic"
          search={{
            view: "overview",
            target: "",
            anchor: "",
            path_ids: "",
            flow_ids: "",
            window_start: undefined,
            window_end: undefined,
          }}
        >
          <img src="/icon.svg" alt="" width="24" height="24" />
          <span>KONE</span>
        </Link>
        <nav className="workspaceNav" aria-label="KONE">
          <Link
            to="/traffic"
            search={{
              view: "overview",
              target: "",
              anchor: "",
              path_ids: "",
              flow_ids: "",
              window_start: undefined,
              window_end: undefined,
            }}
            aria-current={location.pathname === "/traffic" ? "page" : undefined}
          >
            {t("nav.traffic")}
          </Link>
          <Link
            to="/policy"
            search={{ view: "rules" }}
            aria-current={location.pathname === "/policy" ? "page" : undefined}
          >
            {t("nav.policy")}
          </Link>
          <Link
            to="/outbounds"
            aria-current={location.pathname === "/outbounds" ? "page" : undefined}
          >
            {t("nav.outbounds")}
          </Link>
        </nav>
        <div className="hostIdentity">
          <span className="mono">{state.host}</span>
          <small>{t(admin ? "common.admin" : "common.readonly")}</small>
        </div>
        <div className="topActions">
          <Button
            tone="quiet"
            onClick={() => {
              setCommands(true);
              setSearch("");
            }}
            aria-label={t("nav.commands")}
          >
            <span className="commandLabel">{t("nav.commands")}</span>
            <kbd>⌘ K</kbd>
          </Button>
          <Link
            className="iconLink"
            to="/settings"
            search={{ section: "capture" }}
            aria-label={t("nav.settings")}
            aria-current={location.pathname === "/settings" ? "page" : undefined}
          >
            <svg
              viewBox="0 0 24 24"
              width="18"
              height="18"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              aria-hidden="true"
            >
              <path d="M4 7h16M4 17h16M8 4v6m8 4v6" />
            </svg>
          </Link>
          {running && (
            <span className="rates mono" aria-label={t("traffic.rates")}>
              ↑ {formatBytes(connectionError ? undefined : state.totals?.upload_rate, true)}{" "}
              <span>
                ↓ {formatBytes(connectionError ? undefined : state.totals?.download_rate, true)}
              </span>
            </span>
          )}
          <Status value={connectionError ? "unknown" : state.data_state} />
          <Button
            role="switch"
            aria-checked={running}
            tone={running ? "normal" : "primary"}
            disabled={!admin || busy || !!connectionError || operation?.status === "running"}
            onClick={() => {
              void lifecycle();
            }}
          >
            {t(running ? "proxy.pause" : "proxy.enable")}
          </Button>
        </div>
      </header>
      <div className="runtimeStrip">
        <Link to="/policy" search={{ view: "rules" }}>
          {t(`policy.${policyMode}`)}
        </Link>
        <span className="version mono">
          v{state.running_version || "—"} / v{state.saved_version}
        </span>
        {running && state.running_version !== state.saved_version && (
          <Button
            tone="quiet"
            disabled={!admin || operation?.status === "running"}
            onClick={() => {
              void api.apply().then(context.track).catch(setError);
            }}
          >
            {t("common.applySaved")}
          </Button>
        )}
        <span className="scopeLabel">{t("common.scope")}</span>
      </div>
      {!!connectionError && (
        <ErrorNotice
          error={connectionError}
          retry={() => {
            void context.refresh();
          }}
        />
      )}
      {!!error && !readiness && <ErrorNotice error={error} />}
      <DNSFallbackNotice running={running} />
      <ErrorNotice
        error={context.configError}
        retry={() => {
          void context.refresh();
        }}
      />
      {state.config_error && (
        <div className="inlineNote">
          <span>{t("errors.config")}</span>{" "}
          <Link to="/settings" search={{ section: "data" }}>
            {t("nav.settings")}
          </Link>
          <details>
            <summary>{t("common.details")}</summary>
            <pre>{state.config_error}</pre>
          </details>
        </div>
      )}
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      {tool && <Tools />}
      <ErrorToasts />
      {toast && (
        <output className="toast">
          <div>
            {t(toast.key)}
            {toast.details && (
              <details>
                <summary>{t("common.details")}</summary>
                <pre>{toast.details}</pre>
              </details>
            )}
          </div>
          {toast.undo && (
            <Button
              onClick={() => {
                void toast.undo!().catch(setError);
              }}
            >
              {t("common.undo")}
            </Button>
          )}
          <Button tone="quiet" aria-label={t("common.close")} onClick={() => notify(null)}>
            ×
          </Button>
        </output>
      )}
      <footer ref={statusbar} className="statusbar">
        <div className="toolTabs">
          {toolTabs.map((tab) => (
            <button
              key={tab}
              data-tool={tab}
              aria-controls="tool-panel"
              aria-expanded={tool === tab}
              aria-pressed={tool === tab}
              onClick={() => setTool(tool === tab ? null : tab)}
            >
              {t(`nav.${tab}`)} {tab === "notifications" && <NotificationCount />}
            </button>
          ))}
        </div>
        {operation && (
          <span className="operation">
            <Status value={operation.status} />
            <span>
              {t(
                authorizationExpected &&
                  operation.kind === "start" &&
                  operation.status === "running"
                  ? "proxy.awaitingAuthorization"
                  : `stage.${operation.stage}`,
                { defaultValue: t("common.details") },
              )}
            </span>
            {operation.error && (
              <button
                onClick={() => {
                  setError(
                    new ApiError(operation.error_code ?? "request", 0, {
                      code: operation.error_code ?? "request",
                      details: operation.error,
                    }),
                  );
                }}
              >
                {t("common.details")}
              </button>
            )}
          </span>
        )}
        <span className="privacyLabel">{t("common.privacy")}</span>
      </footer>
      <Modal open={commands} onClose={() => setCommands(false)} title={t("nav.commands")}>
        <input
          className="commandSearch"
          placeholder={t("command.placeholder")}
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label={t("nav.commands")}
        />
        <div className="commandList">
          {actions.map((action) => (
            <button
              key={action.id}
              onClick={() => {
                setCommands(false);
                action.run();
              }}
            >
              {action.label}
            </button>
          ))}
          {!actions.length && <p>{t("command.noResults")}</p>}
        </div>
      </Modal>
      {readiness && (
        <ReadinessDialog
          report={readiness}
          busy={busy}
          error={error}
          hasOutbounds={!!context.document?.config.outbounds.length}
          onClose={() => setReadiness(null)}
          onCheck={() => void checkReadiness()}
          onEnable={() => void lifecycle()}
        />
      )}
      {ruleDraft && <RuleComposer initial={ruleDraft} onClose={() => context.setRuleDraft(null)} />}
    </div>
  );
}
