import { cp, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fingerprint, main, npm, readJSON, writeJSON } from "./common.mjs";

export async function maintainIcons(ctx, mode = "check") {
  if (!["check", "generate"].includes(mode)) throw new Error("Icon mode must be generate or check");
  const assets = join(ctx.cwd, "scripts/assets");
  const expected = `${ctx.platform}/${ctx.arch}/${process.versions.node}:${await fingerprint(assets, ["package.json", "package-lock.json"])}`;
  const stamp = join(assets, "node_modules/.kone-icons.json");
  const ready = await readJSON(stamp);
  if (ready?.fingerprint !== expected || !(await readJSON(join(assets, "node_modules/sharp/package.json")))) {
    npm(ctx, ["--prefix", "scripts/assets", "ci"]);
    await writeJSON(stamp, { fingerprint: expected });
  }
  ctx.run(process.execPath, [join(assets, "icons.mjs"), ...(mode === "check" ? ["--check"] : [])]);
  const scratch = await mkdtemp(join(tmpdir(), "kone-icons-"));
  try {
    ctx.run("go", ["run", "github.com/tc-hib/go-winres@v0.3.3", "make", "--in", "winres.json", "--out", join(scratch, "rsrc"), "--arch", "amd64,arm64"], { cwd: join(ctx.cwd, "web/native") });
    for (const arch of ["amd64", "arm64"]) {
      const name = `rsrc_windows_${arch}.syso`;
      const generated = join(scratch, name);
      for (const command of ["kone", "kone-cli"]) {
        const destination = join(ctx.cwd, "cmd", command, name);
        if (mode === "generate") {
          await mkdir(dirname(destination), { recursive: true });
          await cp(generated, destination);
        } else if (!(await readFile(destination)).equals(await readFile(generated))) {
          throw new Error(`${command}/${name} is stale; run just ci icons generate`);
        }
      }
    }
    ctx.log(`${mode === "check" ? "Verified" : "Generated"} desktop image and Windows resource assets.`);
  } finally {
    if (dirname(resolve(scratch)) !== resolve(tmpdir()) || !basename(scratch).startsWith("kone-icons-")) throw new Error("Unexpected icon temporary directory");
    await rm(scratch, { recursive: true, force: true });
  }
}

await main(import.meta.url, (ctx) => {
  const args = process.argv.slice(2);
  if (args.length > 1) throw new Error("Usage: just ci icons [generate|check]");
  return maintainIcons(ctx, ...args);
});
