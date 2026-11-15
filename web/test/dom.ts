import { Window } from "happy-dom";
const window = new Window({ url: "http://localhost" });
for (const key of [
  "window",
  "document",
  "navigator",
  "HTMLElement",
  "HTMLInputElement",
  "Element",
  "Node",
  "MutationObserver",
  "Event",
  "KeyboardEvent",
  "MouseEvent",
] as const) {
  const value = key === "window" ? window : window[key];
  Object.defineProperty(globalThis, key, { value: value, configurable: true, writable: true });
}
Object.defineProperty(globalThis, "IS_REACT_ACT_ENVIRONMENT", {
  value: true,
  writable: true,
  configurable: true,
});

Object.assign(globalThis, {
  getComputedStyle: window.getComputedStyle.bind(window),
  requestAnimationFrame: window.requestAnimationFrame.bind(window),
  cancelAnimationFrame: window.cancelAnimationFrame.bind(window),
});
