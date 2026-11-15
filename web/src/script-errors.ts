interface ResponseContext {
  method: string;
  path: string;
  status: number;
  request_id?: string;
  shape: Record<string, string>;
}
const responses: ResponseContext[] = [];

function responseShape(value: unknown, prefix = "", depth = 0): Record<string, string> {
  const kind =
    value === null ? "null" : Array.isArray(value) ? `array(${value.length})` : typeof value;
  const shape: Record<string, string> = { [prefix || "$"]: kind };
  if (kind === "object" && depth < 2)
    for (const [key, child] of Object.entries(value as Record<string, unknown>).slice(0, 30)) {
      if (/password|token|credential|secret|authorization/i.test(key)) continue;
      Object.assign(shape, responseShape(child, prefix ? `${prefix}.${key}` : key, depth + 1));
    }
  return shape;
}

export function recordResponseContext(
  method: string,
  path: string,
  status: number,
  value: unknown,
  requestID?: string,
) {
  responses.push({
    method,
    path: path.split("?")[0]!,
    status,
    request_id: requestID,
    shape: responseShape(value),
  });
  if (responses.length > 8) responses.shift();
}
export function clearResponseContext() {
  responses.length = 0;
}

export function scriptErrorReport(
  error: unknown,
  runtime: object | undefined,
  componentStack?: string,
) {
  const [route, search] = location.hash.slice(1).split("?");
  const view = new URLSearchParams(search).get("view") ?? "";
  const message =
    error instanceof Error
      ? `${error.name}: ${error.message}`
      : typeof error === "string"
        ? error
        : `Thrown ${typeof error}`;
  return [
    `[KONE Web] Script error: ${message}`,
    error instanceof Error ? error.stack : "",
    componentStack ? `Component stack:\n${componentStack}` : "",
    "Context:\n" +
      JSON.stringify(
        {
          time: new Date().toISOString(),
          page: `${location.pathname}#${route?.startsWith("/") ? route : "/"}${["overview", "connections", "dns"].includes(view) ? `?view=${view}` : ""}`,
          asset: document
            .querySelector<HTMLScriptElement>('script[type="module"][src]')
            ?.getAttribute("src"),
          browser: navigator.userAgent,
          runtime,
          responses,
        },
        null,
        2,
      ),
  ]
    .filter(Boolean)
    .join("\n\n");
}
