import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

const maxRanges = 500000;
const maxJSONBytes = 32 << 20;
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

function fields(line) {
  const result = [];
  let position = 0;
  while (position <= line.length) {
    let value = "";
    if (line[position] === '"') {
      position++;
      let closed = false;
      while (position < line.length) {
        if (line[position] !== '"') value += line[position++];
        else if (line[position + 1] === '"') {
          value += '"';
          position += 2;
        } else {
          position++;
          closed = true;
          break;
        }
      }
      if (!closed) throw new Error("Unterminated CSV field");
    } else {
      while (position < line.length && line[position] !== ",") {
        if (line[position] === '"') throw new Error("Quote in an unquoted CSV field");
        value += line[position++];
      }
    }
    result.push(value);
    if (position === line.length) break;
    if (line[position++] !== ",") throw new Error("Invalid CSV separator");
    if (result.length >= 3) throw new Error("Expected exactly three CSV fields");
  }
  if (result.length !== 3) throw new Error("Expected exactly three CSV fields");
  return result;
}

function ipv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255))
    throw new Error("IPv4 address must be canonical");
  return parts.reduce((result, part) => result * 256 + Number(part), 0);
}
const dotted = (value) => [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");

export function convertDBIP(compressed, { expectedSHA256, release, retrievedAt }) {
  if (!/^[a-f0-9]{64}$/.test(expectedSHA256 || "") || sha256(compressed) !== expectedSHA256)
    throw new Error("Official source SHA256 mismatch");
  if (!/^[0-9]{4}-(0[1-9]|1[0-2])$/.test(release || "")) throw new Error("Release must be YYYY-MM");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(retrievedAt || "") || !Number.isFinite(Date.parse(retrievedAt)))
    throw new Error("Record the UTC retrieval time explicitly");
  if (compressed.length > 16 << 20) throw new Error("Compressed source exceeds 16 MiB");
  const csv = gunzipSync(compressed, { maxOutputLength: 64 << 20 });
  const text = new TextDecoder("utf-8", { fatal: true }).decode(csv);
  const ranges = [];
  let rows = 0, ipv4Rows = 0, ipv6Rows = 0, previous;
  for (let line of text.split("\n")) {
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line === "") continue;
    if (++rows > 1000000) throw new Error("CSV exceeds one million rows");
    const [first, last, country] = fields(line);
    const family = isIP(first);
    if (!family || isIP(last) !== family || !/^[A-Z]{2}$/.test(country)) throw new Error(`Invalid CSV range at row ${rows}`);
    if (family === 6) {
      ipv6Rows++;
      continue;
    }
    ipv4Rows++;
    const start = ipv4(first), end = ipv4(last);
    if (start > end || previous && start <= previous.end) throw new Error(`Unsorted or overlapping IPv4 range at row ${rows}`);
    if (previous && previous.country === country && previous.end + 1 === start) previous.end = end;
    else {
      previous = { start, end, country };
      ranges.push(previous);
      if (ranges.length > maxRanges) throw new Error("IPv4 ranges exceed the 500000 entry budget");
    }
  }
  if (!ranges.length) throw new Error("Source contains no IPv4 ranges");
  const publishedAt = `${release}-01T00:00:00Z`;
  const source = `https://download.db-ip.com/free/dbip-country-lite-${release}.csv.gz`;
  const metadata = { format: 1, version: `db-ip-country-lite-${release}`, source, license: "CC-BY-4.0", license_url: "https://creativecommons.org/licenses/by/4.0/", published_at: publishedAt };
  const json = Buffer.from(JSON.stringify({ ...metadata, ranges: ranges.map((range) => ({ start: dotted(range.start), end: dotted(range.end), country: range.country })) }) + "\n");
  if (json.length > maxJSONBytes) throw new Error("Converted JSON exceeds the 32 MiB import budget");
  const packed = Buffer.alloc(ranges.length * 10);
  ranges.forEach((range, index) => {
    packed.writeUInt32BE(range.start, index * 10);
    packed.writeUInt32BE(range.end, index * 10 + 4);
    packed.write(range.country, index * 10 + 8, 2, "ascii");
  });
  const gzip = gzipSync(packed, { level: 9, mtime: 0 });
  const manifest = {
    ...metadata,
    provider: "DB-IP",
    attribution: "IP Geolocation by DB-IP",
    attribution_url: "https://db-ip.com",
    retrieved_at: retrievedAt,
    source_sha256: expectedSHA256,
    source_compressed_bytes: compressed.length,
    source_csv_bytes: csv.length,
    source_csv_sha256: sha256(csv),
    source_rows: rows,
    source_ipv4_rows: ipv4Rows,
    excluded_ipv6_rows: ipv6Rows,
    ranges: ranges.length,
    packed_bytes: packed.length,
    packed_sha256: sha256(packed),
    gzip_bytes: gzip.length,
    gzip_sha256: sha256(gzip),
    json_bytes: json.length,
    json_sha256: sha256(json),
    changes: "IPv4 extracted; adjacent identical-country ranges merged without changing their meaning; packed as big-endian start/end uint32 plus two ASCII country bytes. IPv6 omitted. ZZ remains unknown.",
  };
  return { gzip, manifest, json };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {};
    for (let index = 2; index < process.argv.length; index += 2) {
      const key = process.argv[index];
      if (!["--input", "--sha256", "--release", "--retrieved-at", "--output-dir", "--json"].includes(key) || options[key] || !process.argv[index + 1])
        throw new Error("Use --input file.csv.gz --sha256 digest --release YYYY-MM --retrieved-at UTC --output-dir directory [--json import.json]");
      options[key] = process.argv[index + 1];
    }
    if (!options["--input"] || !options["--output-dir"]) throw new Error("Explicit local input and output directory are required; this tool never downloads data");
    const input = statSync(options["--input"]);
    if (!input.isFile() || input.size > 16 << 20) throw new Error("Input must be a regular file of at most 16 MiB");
    const converted = convertDBIP(readFileSync(options["--input"]), { expectedSHA256: options["--sha256"], release: options["--release"], retrievedAt: options["--retrieved-at"] });
    mkdirSync(options["--output-dir"], { recursive: true });
    const basename = `dbip-country-lite-${options["--release"]}.ipv4`;
    writeFileSync(join(options["--output-dir"], basename + ".bin.gz"), converted.gzip);
    writeFileSync(join(options["--output-dir"], basename + ".json"), JSON.stringify(converted.manifest, null, 2) + "\n");
    if (options["--json"]) {
      mkdirSync(dirname(resolve(options["--json"])), { recursive: true });
      writeFileSync(options["--json"], converted.json);
    }
    console.log(JSON.stringify(converted.manifest));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
