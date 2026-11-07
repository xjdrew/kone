import type { Notice } from "../model";

export class ApiError extends Error {
  constructor(
    public code: string,
    public status = 0,
    public details: Notice = { code },
    public uncertain = false,
  ) {
    super(code);
  }
}
let csrf = "";
let epoch = 0;
let expired: (() => void) | undefined;
export function onSessionExpired(handler: () => void) {
  expired = handler;
  return () => {
    if (expired === handler) expired = undefined;
  };
}
export function clearSession() {
  csrf = "";
  epoch++;
}
export function setSession(value: { csrf_token?: string }) {
  if (value.csrf_token) csrf = value.csrf_token;
}
export function sessionEpoch() {
  return epoch;
}

export async function request<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    signal?: AbortSignal;
    raw?: boolean;
    text?: boolean;
    requestId?: string;
    timeout?: number;
    headers?: Record<string, string>;
  } = {},
): Promise<T> {
  const started = epoch;
  const method = options.method ?? "GET";
  const controller = new AbortController();
  const abort = () => controller.abort();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();
  const timer = setTimeout(abort, options.timeout ?? 15000);
  const headers = new Headers({ Accept: "application/json", ...options.headers });
  if (options.body !== undefined && !options.raw) headers.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    headers.set("X-CSRF-Token", csrf);
    headers.set("Idempotency-Key", options.requestId ?? crypto.randomUUID());
  }
  try {
    const response = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
      body:
        options.body === undefined
          ? undefined
          : options.raw
            ? (options.body as BodyInit)
            : JSON.stringify(options.body),
    });
    let data: unknown;
    try {
      data =
        response.status === 204
          ? {}
          : response.ok && options.text
            ? await response.text()
            : await response.json();
    } catch {
      throw new ApiError(
        "invalid_response",
        response.status,
        { code: "invalid_response" },
        response.ok && method !== "GET",
      );
    }
    if (started !== epoch) throw new ApiError("session_changed");
    if (!response.ok) {
      if (
        response.status === 401 &&
        csrf &&
        !path.startsWith("/session") &&
        !path.startsWith("/auth")
      )
        expired?.();
      const error =
        typeof data === "object" && data !== null && "error" in data
          ? (data as { error: Notice }).error
          : { code: "request" };
      throw new ApiError(error.code || "request", response.status, error);
    }
    if (typeof data === "object" && data !== null && "csrf_token" in data)
      setSession(data as { csrf_token: string });
    return data as T;
  } catch (error) {
    if (started !== epoch) throw new ApiError("session_changed");
    if (error instanceof ApiError) throw error;
    if (controller.signal.aborted)
      throw new ApiError("timeout", 0, { code: "timeout" }, method !== "GET");
    throw new ApiError("offline", 0, { code: "offline" }, method !== "GET");
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener("abort", abort);
  }
}
export function query(values: Record<string, string | undefined>) {
  return new URLSearchParams(
    Object.entries(values).filter(
      (pair): pair is [string, string] => pair[1] !== undefined && pair[1] !== "",
    ),
  ).toString();
}
