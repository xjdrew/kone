import {
  createContext,
  useContext,
  useEffect,
  useCallback,
  useState,
  type ReactNode,
  type SetStateAction,
} from "react";
import type { ToolTab } from "./tool-panel";
import { initialTool, takeLaunchToken } from "./startup";
import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "./api/endpoints";
import { ApiError, clearSession, request, setSession, onSessionExpired } from "./api/client";
import { setSystemLanguage, languages, changeLanguage, localeChoice } from "./i18n";
import { saveRequest } from "./domain";
import { Button, ErrorNotice, Field } from "./components/ui";
import type { Config, Credentials, Document, Operation, Rule, RuntimeState } from "./model";

interface Toast {
  key: string;
  details?: string;
  undo?: () => Promise<void>;
}
interface ConsoleContext {
  state: RuntimeState;
  document?: Document;
  admin: boolean;
  connectionError: unknown;
  configError: unknown;
  workspace: Map<string, unknown>;
  tool: ToolTab | null;
  setTool: (tool: ConsoleContext["tool"]) => void;
  diagnosticTarget: string;
  diagnose: (target: string) => void;
  ruleDraft: Rule | null;
  setRuleDraft: (rule: Rule | null) => void;
  toast: Toast | null;
  notify: (toast: Toast | null) => void;
  save: (
    base: Document,
    config: Config,
    credentials?: Record<string, Credentials>,
    inbound?: Document["inbound"],
  ) => Promise<Document>;
  operation: Operation | null;
  track: (operation: Operation) => void;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}
const Context = createContext<ConsoleContext | null>(null);
export function useConsole() {
  const value = useContext(Context);
  if (!value) throw new Error("Console context unavailable");
  return value;
}
export function useWorkspaceState<T>(key: string, initial: T | (() => T)) {
  const { workspace } = useConsole();
  const [value, setValue] = useState<T>(() =>
    workspace.has(key)
      ? (workspace.get(key) as T)
      : typeof initial === "function"
        ? (initial as () => T)()
        : initial,
  );
  const update = useCallback(
    (next: SetStateAction<T>) => {
      setValue((previous) => {
        const resolved = typeof next === "function" ? (next as (v: T) => T)(previous) : next;
        workspace.set(key, resolved);
        return resolved;
      });
    },
    [workspace, key],
  );
  return [value, update] as const;
}
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      staleTime: 5000,
      refetchOnWindowFocus: true,
      refetchIntervalInBackground: false,
    },
    mutations: { retry: false },
  },
});
export function Providers({ children }: { children: ReactNode }) {
  const [generation, setGeneration] = useState(0);
  function resetSession() {
    clearSession();
    queryClient.clear();
    setGeneration((value) => value + 1);
  }
  useEffect(() => onSessionExpired(resetSession), []);
  return (
    <QueryClientProvider client={queryClient}>
      <Session key={generation} resetSession={resetSession}>
        {children}
      </Session>
    </QueryClientProvider>
  );
}

export function LanguageSelect() {
  const { t } = useTranslation();
  return (
    <select
      aria-label={t("common.language")}
      value={localeChoice()}
      onChange={(event) => {
        void changeLanguage(event.target.value);
      }}
    >
      <option value="auto">{t("common.auto")}</option>
      {languages.map((language) => (
        <option key={language.tag} value={language.tag}>
          {language.name}
        </option>
      ))}
    </select>
  );
}
async function bootstrap(): Promise<RuntimeState> {
  const token = takeLaunchToken();
  const auth = await api.auth();
  setSession(auth);
  await setSystemLanguage(auth.local_access ? auth.locale : undefined);
  if (auth.local_access && !auth.local_session && !token) await api.session({});
  if (token) {
    const session = await api.session({ token });
    if (session.setup_required)
      throw new ApiError("setup_required", 403, {
        code: "setup_required",
        params: { authorized: 1 },
      });
  }
  if (auth.setup_authorized)
    throw new ApiError("setup_required", 403, {
      code: "setup_required",
      params: { authorized: 1 },
    });
  const state = await api.state();
  setSession(state);
  await setSystemLanguage(state.local_access ? state.locale : undefined);
  return state;
}
function Session({ children, resetSession }: { children: ReactNode; resetSession: () => void }) {
  const { t } = useTranslation();
  const [workspace] = useState(() => new Map<string, unknown>());
  const client = useQueryClient();
  const session = useQuery({ queryKey: ["session"], queryFn: bootstrap, staleTime: Infinity });
  const runtime = useQuery({
    queryKey: ["state"],
    queryFn: ({ signal }) => api.state(signal),
    enabled: !!session.data,
    initialData: session.data,
    refetchInterval: 2000,
  });
  const documentQuery = useQuery({
    queryKey: ["config"],
    queryFn: ({ signal }) => api.document(signal),
    enabled: !!session.data,
  });
  const [tool, setTool] = useState<ConsoleContext["tool"]>(initialTool);
  const [diagnosticTarget, setTarget] = useState("");
  const [ruleDraft, setRuleDraft] = useState<Rule | null>(null);
  const [toast, notify] = useState<Toast | null>(null);
  const [tracked, track] = useState<Operation | null>(null);
  const operationQuery = useQuery({
    queryKey: ["operation", tracked?.id],
    queryFn: () => api.operation(tracked!.id),
    enabled: !!tracked && !["succeeded", "failed", "canceled"].includes(tracked.status),
    refetchInterval: (query) =>
      ["succeeded", "failed", "canceled"].includes(query.state.data?.status ?? "") ? false : 500,
  });
  const operation = operationQuery.data ?? tracked;
  async function refresh() {
    await Promise.all([
      client.invalidateQueries({ queryKey: ["config"] }),
      client.invalidateQueries({ queryKey: ["state"] }),
      client.invalidateQueries({ queryKey: ["policy"] }),
      client.invalidateQueries({ queryKey: ["health"] }),
    ]);
  }
  useEffect(() => {
    if (operation && ["succeeded", "failed", "canceled"].includes(operation.status)) {
      void client.invalidateQueries({ queryKey: ["state"] });
      void client.invalidateQueries({ queryKey: ["config"] });
      void client.invalidateQueries({ queryKey: ["health"] });
    }
  }, [operation, client]);
  useEffect(() => {
    if (runtime.error instanceof ApiError && runtime.error.status === 401) {
      resetSession();
    }
  }, [runtime.error, resetSession]);
  useEffect(() => {
    if (runtime.data && runtime.data.saved_version !== documentQuery.data?.version)
      void client.invalidateQueries({ queryKey: ["config"] });
  }, [runtime.data, documentQuery.data?.version, client]);
  async function save(
    base: Document,
    config: Config,
    credentials?: Record<string, Credentials>,
    inbound = base.inbound,
  ) {
    const result = await api.save({ ...saveRequest(base, config, credentials), inbound });
    client.setQueryData(["config"], result);
    await refresh();
    notify({
      key: result.apply_error
        ? "common.savedNotApplied"
        : result.applied
          ? "common.applied"
          : "common.savedPaused",
      details: result.apply_error,
      undo:
        JSON.stringify(base.config.outbounds) !== JSON.stringify(config.outbounds) || credentials
          ? undefined
          : async () => {
              const current = await api.document();
              if (current.version !== result.version) throw new ApiError("version_conflict", 409);
              // Version precondition refuses to overwrite subsequent local or remote edits.
              await api.save(saveRequest({ ...base, version: current.version }, base.config));
              notify({ key: "common.saved" });
              await refresh();
            },
    });
    return result;
  }
  async function logout() {
    await request("/session/logout", { method: "POST", body: {} });
    resetSession();
  }
  const state = runtime.data ?? session.data;
  if (!state || (runtime.error instanceof ApiError && runtime.error.status === 401)) {
    if (session.isPending)
      return (
        <div className="auth">
          <img src="/icon.svg" alt="KONE" width="44" height="44" />
          <output>{t("auth.connecting")}</output>
        </div>
      );
    return (
      <Login
        onLogin={async () => {
          await client.resetQueries({ queryKey: ["session"] });
        }}
        error={
          session.error instanceof ApiError && session.error.status === 401 ? null : session.error
        }
      />
    );
  }
  return (
    <Context
      value={{
        state,
        document: documentQuery.data,
        admin: state.role === "admin",
        connectionError: runtime.error,
        configError: documentQuery.error,
        workspace,
        tool,
        setTool,
        diagnosticTarget,
        diagnose: (target) => {
          setTarget(target);
          setTool("diagnostics");
        },
        ruleDraft,
        setRuleDraft,
        toast,
        notify,
        save,
        operation,
        track,
        refresh,
        logout,
      }}
    >
      {children}
    </Context>
  );
}
function Login({
  onLogin,
  error: connectionError,
}: {
  onLogin: () => Promise<void>;
  error: unknown;
}) {
  const { t } = useTranslation();
  const setup =
    connectionError instanceof ApiError &&
    connectionError.code === "setup_required" &&
    connectionError.details.params?.authorized === 1;
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  return (
    <div className="auth">
      <form
        className="authForm"
        onSubmit={async (event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          setBusy(true);
          setError(null);
          try {
            if (setup)
              await request("/auth/password", {
                method: "POST",
                body: { password: data.get("credential"), confirm_password: data.get("confirm") },
              });
            else await api.session({ password: data.get("credential") });
            await onLogin();
          } catch (caught) {
            setError(caught);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="authBrand">
          <img src="/icon.svg" alt="" width="36" height="36" />
          <strong>KONE</strong>
          <LanguageSelect />
        </div>
        <h1>{t(setup ? "auth.setup" : "auth.title")}</h1>
        <p className="muted">{t("auth.subtitle")}</p>
        <ErrorNotice error={error || (setup ? null : connectionError)} />
        <Field label={t("auth.password")}>
          <input
            name="credential"
            type="password"
            autoComplete={setup ? "new-password" : "current-password"}
            required
          />
        </Field>
        {setup && (
          <Field label={t("auth.confirmPassword")}>
            <input
              name="confirm"
              type="password"
              required
              minLength={8}
              autoComplete="new-password"
            />
          </Field>
        )}
        <Button type="submit" tone="primary" disabled={busy}>
          {t(busy ? "common.loading" : setup ? "auth.setup" : "auth.signin")}
        </Button>
        <small className="muted">{t("proxy.manual")}</small>
      </form>
    </div>
  );
}
