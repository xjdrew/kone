import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function context(options = {}) {
  const ctx = {
    cwd: process.cwd(),
    taskRoot: process.env.KONE_TASK_ROOT || fileURLToPath(new URL("../../", import.meta.url)),
    env: process.env,
    platform: process.platform,
    arch: process.arch,
    log: console.log,
    ...options,
  };
  ctx.run ||= (command, args, settings = {}) => {
    const result = spawnSync(command, args, {
      cwd: ctx.cwd,
      env: ctx.env,
      stdio: settings.capture ? "pipe" : "inherit",
      encoding: "utf8",
      ...settings,
    });
    if (result.error) throw result.error;
    if (result.status !== 0)
      throw new Error(`${command} failed (exit ${result.status ?? result.signal})${settings.capture ? `: ${result.stderr?.trim() || ""}` : ""}`);
    return result.stdout?.trim() || "";
  };
  return ctx;
}

export function npm(ctx, args, settings = {}) {
  // npm.cmd needs a shell on Windows; pass arguments positionally, never as code.
  return ctx.run("bash", ["-euo", "pipefail", "-c", 'exec npm "$@"', "kone-npm", ...args], settings);
}

export async function readJSON(file) {
  try { return JSON.parse(await readFile(file, "utf8")); }
  catch (error) {
    if (error.code === "ENOENT" || error instanceof SyntaxError) return null;
    throw error;
  }
}

export async function writeJSON(file, value) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, JSON.stringify(value) + "\n");
}

export async function fingerprint(root, names) {
  const hash = createHash("sha256");
  const visit = async (name) => {
    const path = join(root, name);
    let entries;
    try { entries = await readdir(path, { withFileTypes: true }); }
    catch (error) {
      if (error.code === "ENOENT") { hash.update(`missing:${name}\0`); return; }
      if (error.code !== "ENOTDIR") throw error;
      hash.update(`${name}\0`).update(await readFile(path)).update("\0");
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory() || entry.isFile()) await visit(join(name, entry.name));
    }
  };
  for (const name of names) await visit(name);
  return hash.digest("hex");
}

export async function ensureWebDependencies(ctx) {
  const web = join(ctx.cwd, "web");
  const expected = `${ctx.platform}/${ctx.arch}/${process.versions.node}:${await fingerprint(web, ["package.json", "package-lock.json"])}`;
  const stamp = join(web, "node_modules/.kone-dependencies.json");
  const ready = await readJSON(stamp);
  // Also detect removed dependencies instead of trusting the stamp alone.
  const vite = await readJSON(join(web, "node_modules/vite/package.json"));
  const playwright = await readJSON(join(web, "node_modules/@playwright/test/package.json"));
  if (ready?.fingerprint === expected && vite && playwright) {
    ctx.log("  Web dependencies: ready");
    return;
  }
  ctx.log("  Installing locked Web dependencies…");
  npm(ctx, ["ci"], { cwd: web });
  await writeJSON(stamp, { fingerprint: expected });
}

const webInputs = ["src", "public", "index.html", "vite.config.js", "package.json", "package-lock.json"];

export async function ensureFrontend(ctx) {
  const web = join(ctx.cwd, "web");
  const input = await fingerprint(web, webInputs);
  const output = await fingerprint(web, ["dist"]);
  const stamp = join(ctx.cwd, "dist/.tasks/frontend.json");
  const previous = await readJSON(stamp);
  if (previous?.input === input && previous?.output === output) {
    ctx.log("  Web assets: unchanged, skipped");
    return;
  }
  await ensureWebDependencies(ctx);
  ctx.log("  Building embedded Web assets…");
  npm(ctx, ["run", "build"], { cwd: web });
  await writeJSON(stamp, { input, output: await fingerprint(web, ["dist"]) });
}

export async function main(url, action) {
  if (!process.argv[1] || resolve(process.argv[1]) !== fileURLToPath(url)) return;
  try { await action(context()); }
  catch (error) { console.error(`KONE: ${error.message}`); process.exitCode = 1; }
}
