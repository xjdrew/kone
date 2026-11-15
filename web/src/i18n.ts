import i18next from "i18next";
import { initReactI18next } from "react-i18next";
import { setFormattingLocale } from "./domain";

interface Catalog {
  metadata: { tag: string; name: string; dir: "ltr" | "rtl" };
  messages: Record<string, string>;
}
const catalogs = Object.values(
  import.meta.glob<Catalog>("../../pkg/locale/catalog/*.json", { eager: true, import: "default" }),
);
export const languages = catalogs.map((catalog) => catalog.metadata);
const resources = Object.fromEntries(
  catalogs.map((catalog) => [
    catalog.metadata.tag.toLowerCase(),
    { translation: catalog.messages },
  ]),
);
function preference() {
  try {
    return localStorage.getItem("kone.locale") || "auto";
  } catch {
    return "auto";
  }
}
export function detectLanguage(candidates: readonly string[]): string {
  for (const candidate of candidates) {
    let value = candidate.toLowerCase().replaceAll("_", "-");
    while (value) {
      if (resources[value]) return value;
      const end = value.lastIndexOf("-");
      if (end < 0) break;
      value = value.slice(0, end);
    }
  }
  return "en";
}
let systemHint: string | undefined;
export function localeChoice() {
  return preference();
}
export async function changeLanguage(choice: string) {
  try {
    localStorage.setItem("kone.locale", choice);
  } catch {
    /* Private browsing may disallow storage. */
  }
  await i18next.changeLanguage(
    choice === "auto"
      ? detectLanguage(systemHint ? [systemHint, ...navigator.languages] : navigator.languages)
      : detectLanguage([choice]),
  );
}
export async function setSystemLanguage(hint?: string) {
  systemHint = hint;
  if (preference() === "auto") await changeLanguage("auto");
}
void i18next.use(initReactI18next).init({
  resources,
  lng:
    preference() === "auto" ? detectLanguage(navigator.languages) : detectLanguage([preference()]),
  fallbackLng: "en",
  keySeparator: false,
  interpolation: { escapeValue: false },
  returnEmptyString: false,
  initAsync: false,
});
function applyLanguage() {
  setFormattingLocale(i18next.language);
  document.documentElement.lang = i18next.language;
  document.documentElement.dir =
    languages.find((item) => item.tag.toLowerCase() === i18next.language.toLowerCase())?.dir ??
    "ltr";
  document.title = `KONE · ${i18next.t("nav.traffic")}`;
}
i18next.on("languageChanged", applyLanguage);
window.addEventListener("languagechange", () => {
  if (preference() === "auto") void changeLanguage("auto");
});
applyLanguage();
export default i18next;
