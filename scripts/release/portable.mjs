import { execFileSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

async function removeTemporary(directory, parent, prefix) {
  if (dirname(resolve(directory)) !== resolve(parent) || !basename(directory).startsWith(prefix))
    throw new Error("Unexpected portable archive temporary directory");
  await rm(directory, { recursive: true, force: true });
}

// Git records Unix file modes on Windows and supplies mature ZIP/tar codecs.
// Hash raw bytes into a private bare repository; never touch the caller's index,
// run filters, normalize line endings, or use attributes from user configuration.
export async function createPortableArchive({ stage, base, destination, unix }) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(base)) throw new Error("Invalid archive root");
  const format = destination.endsWith(".tar.gz") ? "tar.gz" : destination.endsWith(".zip") ? "zip" : "";
  if (!format) throw new Error("Unsupported portable archive format");
  destination = resolve(destination);
  await mkdir(dirname(destination), { recursive: true });
  const repository = await mkdtemp(join(tmpdir(), "kone-archive-git-"));
  let output;
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^GIT_/i.test(name)));
  Object.assign(env, { GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null", GIT_ATTR_NOSYSTEM: "1" });
  const git = (args, input) => execFileSync("git", ["--git-dir", repository, "-c", "core.autocrlf=false", "-c", "tar.umask=0022", ...args], {
    env, input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"],
  }).trim();
  try {
    output = await mkdtemp(join(dirname(destination), ".kone-archive-"));
    git(["init", "--bare", "--quiet", "--template=", repository]);
    // info/attributes outranks .gitattributes carried as ordinary payload files.
    await mkdir(join(repository, "info"), { recursive: true });
    await writeFile(join(repository, "info/attributes"), "* -export-ignore -export-subst -filter -text\n");
    async function add(directory, relative = "") {
      for (const name of (await readdir(directory)).sort()) {
        const path = join(directory, name);
        const entry = relative ? `${relative}/${name}` : name;
        const stat = await lstat(path);
        if (stat.isDirectory()) await add(path, entry);
        else if (stat.isFile()) {
          const mode = unix && ["kone", "install.sh"].includes(entry) ? "100755" : "100644";
          const object = git(["hash-object", "-w", "--no-filters", "--stdin"], await readFile(path));
          git(["update-index", "--add", "--cacheinfo", mode, object, entry]);
        } else throw new Error("Portable archives require regular files and directories");
      }
    }
    await add(resolve(stage));
    const tree = git(["write-tree"]);
    const archive = join(output, `artifact.${format}`);
    git(["archive", `--format=${format}`, `--prefix=${base}/`, `--output=${archive}`, tree]);
    await rename(archive, destination);
  } finally {
    try {
      if (output) await removeTemporary(output, dirname(destination), ".kone-archive-");
    } finally {
      await removeTemporary(repository, tmpdir(), "kone-archive-git-");
    }
  }
}
