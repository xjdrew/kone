// Parse a CIDR without allocating its address space. Keep explicit host addresses
// compatible with saved profiles; a network prefix uses its first host as gateway.
export function ipv6Subnet(value: string): { subnet: string; gateway: string } | undefined {
  const match = /^([^/]+)\/(\d{1,3})$/.exec(value.trim());
  if (!match) return undefined;
  const bits = Number(match[2]);
  if (bits < 7 || bits > 126) return undefined;
  try {
    const canonical = new URL(`http://[${match[1]}]/`).hostname.slice(1, -1);
    const [left, right] = canonical.split("::");
    const start = left ? left.split(":") : [];
    const end = right ? right.split(":") : [];
    const words =
      right === undefined
        ? start
        : [...start, ...Array(8 - start.length - end.length).fill("0"), ...end];
    const address = words.reduce(
      (total: bigint, word: string) => (total << 16n) | BigInt(`0x${word}`),
      0n,
    );
    if (address >> 121n !== 0x7en) return undefined;
    const size = 1n << BigInt(128 - bits);
    const base = address & ~(size - 1n);
    const gateway = address === base ? base + 1n : address;
    if (gateway + 1n >= base + size) return undefined;
    const format = (ip: bigint) =>
      new URL(
        `http://[${Array.from({ length: 8 }, (_, index) => ((ip >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)).join(":")}]/`,
      ).hostname.slice(1, -1);
    return { subnet: `${format(base)}/${bits}`, gateway: `${format(gateway)}/${bits}` };
  } catch {
    return undefined;
  }
}
