import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { createHash } from "node:crypto";

export function windowsImageRole(bytes) {
  if (bytes.length < 64 || bytes.toString("ascii", 0, 2) !== "MZ") throw new Error("Invalid Windows executable");
  const pe = bytes.readUInt32LE(60);
  if (pe + 24 + 112 + 24 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550) throw new Error("Invalid Windows PE header");
  const optional = pe + 24;
  const magic = bytes.readUInt16LE(optional);
  if (![0x10b, 0x20b].includes(magic)) throw new Error("Invalid Windows optional header");
  const directory = optional + (magic === 0x20b ? 112 : 96);
  const resourceRVA = bytes.readUInt32LE(directory + 16);
  const resourceSize = bytes.readUInt32LE(directory + 20);
  let icon = false;
  const sectionStart = optional + bytes.readUInt16LE(pe + 20);
  for (let index = 0; index < bytes.readUInt16LE(pe + 6); index++) {
    const section = sectionStart + index * 40;
    if (section + 40 > bytes.length) throw new Error("Invalid Windows section table");
    const address = bytes.readUInt32LE(section + 12);
    const size = Math.max(bytes.readUInt32LE(section + 8), bytes.readUInt32LE(section + 16));
    if (resourceRVA < address || resourceRVA >= address + size) continue;
    const start = bytes.readUInt32LE(section + 20) + resourceRVA - address;
    const entries = (offset) => {
      if (offset < start || offset + 16 > bytes.length) throw new Error("Invalid Windows resource directory");
      const count = bytes.readUInt16LE(offset + 12) + bytes.readUInt16LE(offset + 14);
      if (offset + 16 + count * 8 > bytes.length) throw new Error("Invalid Windows resource entries");
      return Array.from({ length: count }, (_, item) => ({ id: bytes.readUInt32LE(offset + 16 + item * 8), value: bytes.readUInt32LE(offset + 20 + item * 8) }));
    };
    const group = entries(start).find(entry => entry.id === 14 && (entry.value & 0x80000000));
    icon = Boolean(group && entries(start + (group.value & 0x7fffffff)).some(entry => entry.id === 101));
  }
  return { subsystem: bytes.readUInt16LE(optional + 68), resourceSize, icon };
}

export function verifyWindowsRole(bytes, role) {
  const image = windowsImageRole(bytes);
  if (image.subsystem !== (role === "gui" ? 2 : 3)) throw new Error(`Windows ${role} executable has the wrong subsystem`);
  if (role === "gui" && (!image.resourceSize || !image.icon)) throw new Error("Windows GUI executable has no application icon resource 101");
}

const xml = value => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
export async function createMacApplication({ binary, output, version, sha, icon }) {
  output = resolve(output);
  if (basename(output) !== "Kone.app" || dirname(output) === output) throw new Error("Unexpected application bundle output");
  await rm(output, { recursive: true, force: true });
  await mkdir(join(output, "Contents/MacOS"), { recursive: true });
  await mkdir(join(output, "Contents/Resources"));
  await cp(binary, join(output, "Contents/MacOS/kone"));
  await cp(icon, join(output, "Contents/Resources/Kone.icns"));
  const short = version.split("-")[0].split("+")[0];
  await writeFile(join(output, "Contents/Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>io.github.xjdrew.kone</string>
<key>CFBundleName</key><string>Kone</string>
<key>CFBundleDisplayName</key><string>Kone</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleExecutable</key><string>kone</string>
<key>CFBundleIconFile</key><string>Kone.icns</string>
<key>CFBundleShortVersionString</key><string>${xml(short)}</string>
<key>CFBundleVersion</key><string>${xml(short)}</string>
<key>LSUIElement</key><true/>
<key>KONEVersion</key><string>${xml(version)}</string>
<key>KONESourceSHA</key><string>${xml(sha)}</string>
</dict></plist>\n`);
}

export async function verifyMacApplication(directory, { version, sha, binarySHA, iconSHA }) {
  const plist = await readFile(join(directory, "Contents/Info.plist"), "utf8");
  for (const expected of ["<key>LSUIElement</key><true/>", "<key>CFBundlePackageType</key><string>APPL</string>", "<key>CFBundleIconFile</key><string>Kone.icns</string>", "<key>CFBundleExecutable</key><string>kone</string>", `<key>KONEVersion</key><string>${xml(version)}</string>`, `<key>KONESourceSHA</key><string>${xml(sha)}</string>`])
    if (!plist.includes(expected)) throw new Error("macOS application identity/role mismatch");
  const icon = await readFile(join(directory, "Contents/Resources/Kone.icns"));
  if (icon.toString("ascii", 0, 4) !== "icns") throw new Error("Invalid macOS application icon");
  const binary = await readFile(join(directory, "Contents/MacOS/kone"));
  if ((binarySHA && createHash("sha256").update(binary).digest("hex") !== binarySHA) || (iconSHA && createHash("sha256").update(icon).digest("hex") !== iconSHA))
    throw new Error("macOS application contents do not match build metadata");
}
