import { spawn } from "node:child_process";
import { access, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";
async function within(promise, milliseconds) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((resolve) => {
        timer = setTimeout(() => resolve(null), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
const redact = (value) =>
  String(value)
    .replace(/(#token=)[^\s&]+/g, "$1REDACTED")
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/g, "$1REDACTED@");

async function startManager(binary, directory) {
  const child = spawn(
    binary,
    ["-manage", "-no-browser", "-no-tray", "-listen", "127.0.0.1:0", "-data-dir", directory],
    {
      cwd: directory,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "",
    diagnostics = "",
    settled = false;
  let accept, reject;
  const ready = new Promise((resolve, fail) => {
    accept = resolve;
    reject = fail;
  });
  const timer = setTimeout(
    () => reject(new Error(`Real manager startup timed out: ${redact(diagnostics)}`)),
    12000,
  );
  const done = new Promise((resolve) => {
    child.once("error", () => {
      settled = true;
      reject(new Error("Cannot launch the real management test binary"));
      resolve({ code: null, signal: "spawn-error" });
    });
    child.once("exit", (code, signal) => {
      settled = true;
      reject(new Error(`Real manager stopped before readiness (${code ?? signal})`));
      resolve({ code, signal });
    });
  });
  child.stderr.on("data", (chunk) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-8192);
  });
  child.stdout.on("data", (chunk) => {
    output = (output + chunk.toString()).slice(-16384);
    const match = output.match(
      /KONE management \(capture paused\): (http:\/\/127\.0\.0\.1:\d+\/(?:#token=[a-f0-9]{64})?)\r?\n/,
    );
    if (match) accept(match[1]);
  });
  let stopping;
  const stop = () =>
    (stopping ||= (async () => {
      if (!settled) child.kill("SIGTERM");
      const outcome = await within(done, 8000);
      if (!outcome) {
        child.kill("SIGKILL"); // Only this owned child; forced cleanup remains a test failure.
        await within(done, 2000);
        throw new Error("Real manager did not stop gracefully after SIGTERM");
      }
      if (outcome.code !== 0 || outcome.signal)
        throw new Error(
          `Real manager did not exit cleanly (${outcome.code ?? outcome.signal}): ${redact(diagnostics)}`,
        );
    })());
  try {
    const url = new URL(await ready);
    return { url, stop, pid: child.pid, done };
  } catch (error) {
    await stop().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function networkFingerprint() {
  const digest = (value) => createHash("sha256").update(value).digest("hex");
  return {
    interfaces: (await readdir("/sys/class/net")).sort(),
    routes: digest(await readFile("/proc/net/route")),
    dns: digest(await readFile("/etc/resolv.conf")),
  };
}

async function assertNoCaptureJournal(directory) {
  try {
    await access(join(directory, "capture.json"));
    throw new Error("Management-only browser journey unexpectedly created a capture journal");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

export { startManager, networkFingerprint, assertNoCaptureJournal };
