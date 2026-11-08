// Every status-bar tool uses the same floating panel and tab registry.
export const toolTabs = ["notifications", "diagnostics", "logs"] as const;
export type ToolTab = (typeof toolTabs)[number];
