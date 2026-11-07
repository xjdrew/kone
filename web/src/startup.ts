// Remove one-use launch credentials before the router, analytics-free UI or any
// asynchronous request can observe the URL. Never persist a launch token.
const launch = new URLSearchParams(location.hash.slice(1));
let token = launch.get("token");
const legacy: Record<string, string> = {
  home: "/traffic?view=overview",
  traffic: "/traffic?view=connections",
  dns: "/traffic?view=dns",
  rules: "/policy?view=rules",
  outbounds: "/policy?view=outbounds",
  settings: "/settings?section=capture",
  diagnostics: "/traffic?view=overview",
  logs: "/traffic?view=overview",
};
const initial = location.hash.slice(1);
export const initialTool = initial === "diagnostics" || initial === "logs" ? initial : null;
if (token || legacy[initial]) {
  history.replaceState(
    null,
    "",
    `${location.pathname}${location.search}#${legacy[initial] || "/"}`,
  );
}
export function takeLaunchToken() {
  const value = token;
  token = null;
  return value;
}

export function preference(name: string, fallback: string) {
  try {
    return localStorage.getItem(`kone.${name}`) || fallback;
  } catch {
    return fallback;
  }
}
export function applyAppearance(
  theme = preference("theme", "dark"),
  density = preference("density", "compact"),
) {
  document.documentElement.dataset.theme =
    theme === "system"
      ? matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark"
      : theme;
  document.documentElement.dataset.density = density;
}
export function saveAppearance(theme: string, density: string) {
  try {
    localStorage.setItem("kone.theme", theme);
    localStorage.setItem("kone.density", density);
  } catch {
    /* Storage can be disabled. */
  }
  applyAppearance(theme, density);
}
applyAppearance();
matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => applyAppearance());
