import "./dom";
import { afterEach, expect, test } from "bun:test";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import english from "../../pkg/locale/catalog/en.json";
import chinese from "../../pkg/locale/catalog/zh.json";
import { DiagnosticTarget } from "../src/components/diagnostic-target";
import { readDiagnosticHistory } from "../src/diagnostic-history";
import { FlowGraph } from "../src/components/flow-graph";
import { ErrorNotice, Status } from "../src/components/ui";
import { ApiError } from "../src/api/client";
import { graphFixture } from "./factories";

await i18next.use(initReactI18next).init({
  lng: "en",
  keySeparator: false,
  resources: { en: { translation: english.messages }, zh: { translation: chinese.messages } },
  interpolation: { escapeValue: false },
  initAsync: false,
});
afterEach(() => {
  cleanup();
  void i18next.changeLanguage("en");
});
test("an error status has an explicit label in both supported languages", async () => {
  render(<Status value="error" />);
  expect(screen.getByText("Error")).toBeTruthy();
  await act(async () => {
    await i18next.changeLanguage("zh");
  });
  expect(screen.getByText("错误")).toBeTruthy();
  expect(screen.queryByText("未知")).toBeNull();
});
test("keyboard activation uses the original complete-path IDs", () => {
  let selected: string[] = [];
  render(
    <FlowGraph
      graph={graphFixture()}
      onSelect={(value) => {
        selected = value;
      }}
    />,
  );
  const node = screen.getByRole("button", { name: /www.google.com/ });
  fireEvent.keyDown(node, { key: "Enter" });
  expect(selected).toEqual(["path-1"]);
});
test("error codes translate without matching raw technical prose", async () => {
  await i18next.changeLanguage("zh");
  render(
    <ErrorNotice
      error={
        new ApiError("version_conflict", 409, {
          code: "version_conflict",
          details: "disk revision changed",
        })
      }
    />,
  );
  expect(screen.getByRole("alert").textContent).toContain(chinese.messages["api.version_conflict"]);
  expect(screen.getByText("disk revision changed").closest("details")).not.toBeNull();
});

test("target history supports keyboard selection and Escape without submitting", () => {
  const selected: string[] = [];
  render(
    <DiagnosticTarget
      label="Target"
      value=""
      history={readDiagnosticHistory(null)}
      onChange={() => {}}
      onClear={() => {}}
      onSelect={(entry) => selected.push(entry.target)}
      placeholder="host:port"
    />,
  );
  const input = screen.getByRole("combobox", { name: "Target" });
  fireEvent.keyDown(input, { key: "ArrowDown" });
  fireEvent.keyDown(input, { key: "ArrowDown" });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(selected).toEqual(["149.154.167.50:443"]);
  expect(screen.queryByRole("listbox")).toBeNull();
  fireEvent.keyDown(input, { key: "ArrowDown" });
  fireEvent.keyDown(input, { key: "Escape" });
  expect(screen.queryByRole("listbox")).toBeNull();
  expect(selected).toHaveLength(1);
});
