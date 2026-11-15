import { GlobalErrorScope } from "./components/ui";
import "./startup";
import React, { useMemo } from "react";
import { createRoot } from "react-dom/client";
import {
  createRootRoute,
  createRoute,
  createRouter,
  createHashHistory,
  RouterProvider,
  Navigate,
  useSearch,
  type ErrorComponentProps,
} from "@tanstack/react-router";
import i18n from "./i18n";
import "./theme.css";
import { Providers, queryClient } from "./context";
import type { RuntimeState } from "./model";
import { scriptErrorReport } from "./script-errors";
import uiStyles from "./components/ui.module.css";
import { Shell } from "./shell";
import { TrafficView } from "./views/traffic";
import { OutboundsView } from "./views/outbounds";
import { PolicyView } from "./views/policy";
import { SettingsView } from "./views/settings";

function errorReport(error: unknown, componentStack?: string) {
  const state =
    queryClient.getQueryData<RuntimeState>(["state"]) ??
    queryClient.getQueryData<RuntimeState>(["session"]);
  return scriptErrorReport(
    error,
    state && {
      version: state.version,
      data_state: state.data_state,
      control_state: state.control_state,
      saved_version: state.saved_version,
      running_version: state.running_version,
    },
    componentStack,
  );
}
function ScriptError({ error }: ErrorComponentProps) {
  const report = useMemo(() => errorReport(error), [error]);
  return (
    <section role="alert" className={uiStyles.notice}>
      <strong>{i18n.t("common.error")}</strong>
      <pre>{report}</pre>
    </section>
  );
}
window.addEventListener("error", (event) => {
  console.error(errorReport(event.error ?? new Error(event.message)));
});
window.addEventListener("unhandledrejection", (event) => {
  console.error(errorReport(event.reason));
});

const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      <GlobalErrorScope.Provider value={true}>
        <Shell />
      </GlobalErrorScope.Provider>
    </Providers>
  ),
});
const home = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: () => (
    <Navigate
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
      replace
    />
  ),
});
const traffic = createRoute({
  getParentRoute: () => rootRoute,
  path: "/traffic",
  validateSearch: (search: Record<string, unknown>) => ({
    view: ["overview", "connections", "dns"].includes(String(search.view))
      ? String(search.view)
      : "overview",
    target: String(search.target ?? ""),
    anchor: String(search.anchor ?? ""),
    path_ids: String(search.path_ids ?? ""),
    flow_ids: String(search.flow_ids ?? ""),
    window_start: typeof search.window_start === "string" ? search.window_start : undefined,
    window_end: typeof search.window_end === "string" ? search.window_end : undefined,
  }),
  component: TrafficView,
});
const policy = createRoute({
  getParentRoute: () => rootRoute,
  path: "/policy",
  validateSearch: (search: Record<string, unknown>) => ({
    view: search.view === "outbounds" ? "outbounds" : "rules",
  }),
  component: function PolicyRoute() {
    return useSearch({ from: "/policy" }).view === "outbounds" ? (
      <Navigate to="/outbounds" replace />
    ) : (
      <PolicyView />
    );
  },
});
const outbounds = createRoute({
  getParentRoute: () => rootRoute,
  path: "/outbounds",
  component: OutboundsView,
});
const settings = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  validateSearch: (search: Record<string, unknown>) => ({
    section: ["capture", "resolvers", "data", "access", "recovery", "interface", "about"].includes(
      String(search.section),
    )
      ? String(search.section)
      : "capture",
  }),
  component: SettingsView,
});
const router = createRouter({
  routeTree: rootRoute.addChildren([home, traffic, policy, outbounds, settings]),
  history: createHashHistory(),
  defaultPreload: "intent",
  defaultErrorComponent: ScriptError,
  defaultOnCatch: (error, info) =>
    console.error(errorReport(error, info.componentStack ?? undefined)),
});
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
);
