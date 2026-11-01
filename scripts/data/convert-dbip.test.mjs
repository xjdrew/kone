import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";
import { convertDBIP, sha256 } from "./convert-dbip.mjs";

const settings = { release: "2026-10", retrievedAt: "2026-10-31T18:04:18Z" };
const root = fileURLToPath(new URL("../../", import.meta.url));
function convert(text, options = {}) {
  const data = gzipSync(Buffer.isBuffer(text) ? text : Buffer.from(text));
  return convertDBIP(data, { ...settings, expectedSHA256: sha256(data), ...options });
}

test("lossless IPv4 extraction, quoted CSV, adjacent merging and explicit IPv6 boundary", () => {
  const csv = '"0.0.0.0","0.0.0.255","ZZ"\r\n"1.0.0.0","1.0.0.127","CN"\r\n1.0.0.128,1.0.0.255,CN\r\n2001:db8::,2001:db8::ffff,US\r\n';
  const converted = convert(csv);
  assert.equal(converted.manifest.source_rows, 4);
  assert.equal(converted.manifest.source_ipv4_rows, 3);
  assert.equal(converted.manifest.excluded_ipv6_rows, 1);
  assert.equal(converted.manifest.ranges, 2);
  assert.equal(converted.manifest.source_csv_sha256, sha256(Buffer.from(csv)));
  assert.equal(converted.manifest.license, "CC-BY-4.0");
  assert.equal(converted.manifest.attribution_url, "https://db-ip.com");
  const json = JSON.parse(converted.json);
  assert.deepEqual(json.ranges, [{ start: "0.0.0.0", end: "0.0.0.255", country: "ZZ" }, { start: "1.0.0.0", end: "1.0.0.255", country: "CN" }]);
  const packed = gunzipSync(converted.gzip);
  assert.equal(packed.length, 20);
  assert.equal(packed.readUInt32BE(10), 0x01000000);
  assert.equal(packed.readUInt32BE(14), 0x010000ff);
  assert.equal(packed.subarray(18, 20).toString(), "CN");
  assert.equal(converted.manifest.packed_sha256, sha256(packed));
  assert.equal(converted.manifest.gzip_sha256, sha256(converted.gzip));
  assert.equal(converted.manifest.json_sha256, sha256(converted.json));
  assert.deepEqual(convert(csv).gzip, converted.gzip);
  assert.deepEqual(convert(csv, { retrievedAt: "2026-11-01T00:00:00Z" }).gzip, converted.gzip, "retrieval metadata does not change the deterministic packed bytes");
});

test("malformed, reversed, overlapping and unauthenticated sources are refused", () => {
  for (const csv of [
    '"1.0.0.0,1.0.0.255,CN\n',
    '1.0.0.0,"1.0.0.255"trailing,CN\n',
    '1.0.0.0,1.0.0.255,CN,extra\n',
    '1.0.0.0,1.0.0.255,cn\n',
    '1.0.0.255,1.0.0.0,CN\n',
    '1.0.0.0,1.0.0.255,CN\n1.0.0.255,1.0.1.0,US\n',
    '01.0.0.0,1.0.0.255,CN\n',
    '1.0.0.0,2001:db8::1,CN\n',
    '2001:db8::,2001:db8::ffff,US\n',
  ]) assert.throws(() => convert(csv));
  assert.throws(() => convert(Buffer.from([255, 254, 253])));
  assert.throws(() => convert("1.0.0.0,1.0.0.255,CN\n", { expectedSHA256: "0".repeat(64) }), /SHA256 mismatch/);
  assert.throws(() => convert("1.0.0.0,1.0.0.255,CN\n", { release: "2026-13" }), /YYYY-MM/);
  assert.throws(() => convert("1.0.0.0,1.0.0.255,CN\n", { retrievedAt: "today" }), /UTC/);
  const damaged = gzipSync(Buffer.from("1.0.0.0,1.0.0.255,CN\n"));
  damaged[damaged.length - 1] ^= 1;
  assert.throws(() => convertDBIP(damaged, { ...settings, expectedSHA256: sha256(damaged) }));
});

test("CLI produces reproducible assets and a separately checked import file without network access", () => {
  const directory = mkdtempSync(join(tmpdir(), "kone-geoip-convert-"));
  try {
    const input = join(directory, "fixture.csv.gz");
    const data = gzipSync(Buffer.from("8.8.8.0,8.8.8.255,US\n"));
    writeFileSync(input, data);
    const output = join(directory, "output");
    const jsonFile = join(directory, "import.json");
    const result = JSON.parse(execFileSync(process.execPath, ["scripts/data/convert-dbip.mjs", "--input", input, "--sha256", sha256(data), "--release", settings.release, "--retrieved-at", settings.retrievedAt, "--output-dir", output, "--json", jsonFile], { cwd: root, encoding: "utf8", timeout: 10000 }));
    assert.equal(result.json_sha256, sha256(readFileSync(jsonFile)));
    assert.equal(result.gzip_sha256, sha256(readFileSync(join(output, "dbip-country-lite-2026-10.ipv4.bin.gz"))));
    assert.equal(JSON.parse(readFileSync(join(output, "dbip-country-lite-2026-10.ipv4.json"))).source_sha256, sha256(data));
    assert.throws(() => execFileSync(process.execPath, ["scripts/data/convert-dbip.mjs", "--input", "https://example.com/database.gz", "--output-dir", output], { cwd: root, stdio: "pipe", timeout: 10000 }));
  } finally {
    const checked = resolve(directory);
    assert.equal(dirname(checked), resolve(tmpdir()));
    assert.match(basename(checked), /^kone-geoip-convert-/);
    rmSync(checked, { recursive: true, force: true });
  }
});

test("untrusted source conversion keeps explicit input and IPv4 range budgets", () => {
  const oversized = Buffer.alloc((16 << 20) + 1);
  assert.throws(() => convertDBIP(oversized, { ...settings, expectedSHA256: sha256(oversized) }), /16 MiB/);
  const dotted = (value) => [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
  const rows = Array.from({ length: 500001 }, (_, index) => {
    const address = dotted(index * 2);
    return `${address},${address},CN`;
  }).join("\n");
  assert.throws(() => convert(rows), /500000 entry budget/, "gaps prevent lossless adjacent merging from reducing the fixture");
});

test("bundled packed artifact matches its complete official-source manifest", () => {
  const path = join(root, "pkg/geoip/data/dbip-country-lite-2026-10.ipv4");
  const manifest = JSON.parse(readFileSync(path + ".json"));
  const gzip = readFileSync(path + ".bin.gz");
  const packed = gunzipSync(gzip, { maxOutputLength: 500000 * 10 });
  assert.equal(manifest.source_sha256, "097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80");
  assert.equal(manifest.source_csv_sha256, "53864a68fbfef02c27c717d08d431a6d453e9e00e77d9e8da841d382267fca88");
  assert.equal(manifest.source_ipv4_rows, 362122);
  assert.equal(manifest.ranges, 362122);
  assert.equal(manifest.source_rows, manifest.source_ipv4_rows + manifest.excluded_ipv6_rows);
  assert.equal(gzip.length, manifest.gzip_bytes);
  assert.equal(packed.length, manifest.ranges * 10);
  assert.equal(sha256(gzip), manifest.gzip_sha256);
  assert.equal(sha256(packed), manifest.packed_sha256);
  let previous = -1;
  for (let offset = 0; offset < packed.length; offset += 10) {
    const start = packed.readUInt32BE(offset), end = packed.readUInt32BE(offset + 4);
    assert.ok(start > previous && end >= start);
    assert.match(packed.subarray(offset + 8, offset + 10).toString("ascii"), /^[A-Z]{2}$/);
    previous = end;
  }
});
