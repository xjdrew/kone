import "./dom";
import { afterEach, expect, test } from "bun:test";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import english from "../../pkg/locale/catalog/en.json";
import chinese from "../../pkg/locale/catalog/zh.json";
import { FlowGraph } from "../src/components/flow-graph";
import { ErrorNotice } from "../src/components/ui";
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
