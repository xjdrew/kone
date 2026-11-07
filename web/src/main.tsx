import "./startup";
import React from "react";
import { createRoot } from "react-dom/client";
import {
  createRootRoute,
  createRoute,
  createRouter,
  createHashHistory,
  RouterProvider,
  Navigate,
} from "@tanstack/react-router";
import "./i18n";
import "./theme.css";
import { Providers } from "./context";
import { Shell } from "./shell";
import { TrafficView } from "./views/traffic";
import { PolicyView } from "./views/policy";
import { SettingsView } from "./views/settings";

const rootRoute = createRootRoute({
  component: () => (
    <Providers>
      <Shell />
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
  component: PolicyView,
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
  routeTree: rootRoute.addChildren([home, traffic, policy, settings]),
  history: createHashHistory(),
  defaultPreload: "intent",
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
