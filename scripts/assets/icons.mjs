import sharp from "sharp";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = fileURLToPath(new URL("../../", import.meta.url));
const check = process.argv.includes("--check");
if (process.argv.slice(2).some((arg) => arg !== "--check")) throw new Error("Usage: icons.mjs [--check]");
const svg = await readFile(join(root, "web/public/icon.svg"));
const template = await readFile(join(root, "web/native/tray.svg"));
const sizes = [16, 24, 32, 48, 64, 128, 256, 512, 1024];
const pngs = new Map();
const files = new Map();
for (const size of sizes) {
  const png = await sharp(svg).resize(size, size).png({ compressionLevel: 9 }).toBuffer();
  pngs.set(size, png);
  if ([32, 256, 512].includes(size)) files.set(`web/public/icon-${size}.png`, png);
}
files.set("web/public/apple-touch-icon.png", await sharp(svg).resize(180, 180).png({ compressionLevel: 9 }).toBuffer());
files.set("web/native/tray.png", await sharp(template).resize(44, 44).png({ compressionLevel: 9 }).toBuffer());
files.set("web/native/tray-windows.png", pngs.get(32));

const icoSizes = sizes.filter((size) => size <= 256);
const directory = Buffer.alloc(6 + icoSizes.length * 16);
directory.writeUInt16LE(1, 2);
directory.writeUInt16LE(icoSizes.length, 4);
let offset = directory.length;
for (const [index, size] of icoSizes.entries()) {
  const entry = 6 + index * 16;
  const png = pngs.get(size);
  directory[entry] = directory[entry + 1] = size === 256 ? 0 : size;
  directory.writeUInt16LE(1, entry + 4);
  directory.writeUInt16LE(32, entry + 6);
  directory.writeUInt32LE(png.length, entry + 8);
  directory.writeUInt32LE(offset, entry + 12);
  offset += png.length;
}
files.set("web/native/kone.ico", Buffer.concat([directory, ...icoSizes.map((size) => pngs.get(size))]));
const chunks = [];
for (const [type, size] of [["icp4", 16], ["icp5", 32], ["icp6", 64], ["ic07", 128], ["ic08", 256], ["ic09", 512], ["ic10", 1024]]) {
  const png = pngs.get(size);
  const header = Buffer.alloc(8);
  header.write(type, 0, 4, "ascii");
  header.writeUInt32BE(png.length + 8, 4);
  chunks.push(header, png);
}
const icns = Buffer.alloc(8);
icns.write("icns", 0);
icns.writeUInt32BE(8 + chunks.reduce((sum, chunk) => sum + chunk.length, 0), 4);
files.set("web/native/kone.icns", Buffer.concat([icns, ...chunks]));
for (const [path, contents] of files) {
  const destination = join(root, path);
  if (check) {
    if (!(await readFile(destination)).equals(contents)) throw new Error(`${path} is stale; regenerate Kone icons`);
  } else {
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, contents);
  }
}
console.log(`${check ? "Verified" : "Generated"} ${files.size} Kone icon assets from the canonical SVG.`);
