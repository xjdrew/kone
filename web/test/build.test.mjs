import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "vite";
import config from "../vite.config.js";

const project = fileURLToPath(new URL("../../", import.meta.url));

async function contents(directory, prefix = "") {
  const result = {};
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) Object.assign(result, await contents(directory, path));
    else result[path] = await readFile(join(directory, path));
  }
  return result;
}

test("Windows CRLF checkouts rebuild identical tracked assets without rewriting source or binary icons", async (t) => {
  const temporary = await mkdtemp(join(tmpdir(), "kone web line endings "));
  t.after(async () => {
    assert.equal(dirname(resolve(temporary)), resolve(tmpdir()));
    await rm(temporary, { recursive: true, force: true });
  });
  const source = join(temporary, "source"), checkout = join(temporary, "Windows checkout");
  const git = (cwd, ...args) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  const buildWeb = cwd => build({ ...config, root: join(cwd, "web"), configFile: false, logLevel: "silent" });
  await mkdir(join(source, "web"), { recursive: true });
  await cp(join(project, ".gitattributes"), join(source, ".gitattributes"));
  for (const name of ["src", "public", "index.html", "package.json"])
    await cp(join(project, "web", name), join(source, "web", name), { recursive: true });
  await writeFile(join(source, "windows-default.txt"), "ordinary text\n");
  git(source, "init", "-q", "-b", "main");
  git(source, "config", "core.autocrlf", "false");
  await buildWeb(source);
  const original = await contents(join(source, "web/dist"));
  const icon = await readFile(join(source, "web/public/icon-32.png"));
  assert.equal(original["index.html"].includes(13), false);
  git(source, "add", ".");
  git(source, "-c", "user.name=KONE Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "test fixture");
  git(temporary, "clone", "-q", "--no-local", "-c", "core.autocrlf=true", source, checkout);
  assert.equal(git(checkout, "config", "--get", "core.autocrlf"), "true");
  assert.match(await readFile(join(checkout, "windows-default.txt"), "utf8"), /\r\n$/, "fixture must exercise a real autocrlf checkout");
  const html = await readFile(join(checkout, "web/index.html"), "utf8");
  assert.equal(html.includes("\r"), false, "frontend attributes override core.autocrlf");
  assert.deepEqual(await readFile(join(checkout, "web/public/icon-32.png")), icon);
  await buildWeb(checkout);
  assert.deepEqual(await contents(join(checkout, "web/dist")), original);
  assert.equal(git(checkout, "status", "--porcelain", "--", "web/dist"), "");

  // Pulling new attributes does not rewrite an existing user's HTML checkout.
  // Cover that old CRLF input before Vite can introduce repeated/mixed CRs.
  const oldHTML = html.replaceAll("\n", "\r\n");
  const oldSVG = (await readFile(join(checkout, "web/public/icon.svg"), "utf8")).replaceAll("\n", "\r\n");
  await writeFile(join(checkout, "web/index.html"), oldHTML);
  await writeFile(join(checkout, "web/public/icon.svg"), oldSVG);
  await buildWeb(checkout);
  assert.equal(await readFile(join(checkout, "web/index.html"), "utf8"), oldHTML, "building must not rewrite developer source");
  assert.equal(await readFile(join(checkout, "web/public/icon.svg"), "utf8"), oldSVG, "copied SVG source must not be rewritten");
  assert.deepEqual(await contents(join(checkout, "web/dist")), original);
  assert.equal(git(checkout, "status", "--porcelain", "--", "web/dist"), "");
  assert.deepEqual(await readFile(join(checkout, "web/dist/icon-32.png")), icon, "binary assets must remain byte-identical");

  await writeFile(join(checkout, "web/index.html"), oldHTML.replace("KONE ·", "KONE changed ·"));
  await buildWeb(checkout);
  const changed = spawnSync("git", ["diff", "--exit-code", "--", "web/dist"], { cwd: checkout, encoding: "utf8" });
  assert.equal(changed.status, 1, "real source changes must still produce a reviewable tracked diff");
  assert.match(changed.stdout, /KONE changed/);
});
