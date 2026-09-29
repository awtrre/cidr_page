const fs = require('node:fs');
const path = require('node:path');
const kv = require('./kv');

const GROUPS = {
  meta: ['AS32934', 'AS54115', 'AS63293'],
  cf: ['AS13335', 'AS209242', 'AS132892']
};
const KV_KEY = 'cidr_ranges';
const ECH_KV_KEY = 'meta_ech';
const MIN_KEEP_RATIO = 0.5;
const HEADERS = [
  '/data.json',
  '  Access-Control-Allow-Origin: *',
  '  Cache-Control: public, max-age=3600, stale-while-revalidate=86400',
  '  Content-Type: application/json;charset=UTF-8'
].join('\n');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

const fetchJson = async (url, retries = 3) => {
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (e) {
      if (attempt >= retries) throw new Error(`${url} 抓取失败: ${e.message}`);
      await sleep(500 * attempt);
    }
  }
};

const fetchPrefixes = async asns => {
  const lists = await Promise.all(
    asns.map(async asn => {
      const json = await fetchJson(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}`);
      return json.data.prefixes.map(p => p.prefix);
    })
  );
  return [...new Set(lists.flat())];
};

const parseV4 = ip => ip.split('.').reduce((acc, octet) => (acc << 8n) | BigInt(octet), 0n);

const parseV6 = ip => {
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const gap = tail === undefined ? [] : Array(8 - h.length - t.length).fill('0');
  return [...h, ...gap, ...t].reduce((acc, group) => (acc << 16n) | BigInt(`0x${group || '0'}`), 0n);
};

const parse = cidr => {
  const [ip, bits] = cidr.split('/');
  const v6 = ip.includes(':');
  const span = (1n << ((v6 ? 128n : 32n) - BigInt(bits))) - 1n;
  const start = (v6 ? parseV6(ip) : parseV4(ip)) & ~span;
  return { cidr, v6, len: Number(bits), start, end: start | span };
};

const prune = entries => {
  const sorted = [...entries].sort((a, b) => cmp(a.start, b.start) || a.len - b.len);
  const kept = [];
  let covered = -1n;
  for (const entry of sorted) {
    if (entry.start <= covered) continue;
    kept.push(entry);
    covered = entry.end;
  }
  return kept;
};

const compile = prefixes => {
  const parsed = prefixes.map(parse);
  const [v4, v6] = [false, true].map(isV6 => prune(parsed.filter(e => e.v6 === isV6)));
  return { v4, v6 };
};

const merge = ranges => {
  const out = [];
  for (const [start, end] of ranges) {
    const last = out.at(-1);
    if (last && start <= last[1] + 1n) {
      if (end > last[1]) last[1] = end;
    } else {
      out.push([start, end]);
    }
  }
  return out;
};

const toRanges = ({ v4, v6 }) => ({
  v4: merge(v4.map(e => [e.start, e.end])),
  v6: merge(v6.map(e => [e.start >> 64n, e.end >> 64n]))
});

const encode = sections => {
  const head = Uint32Array.from(sections.flatMap(s => [s.v4.length, s.v6.length]));
  const arrays = sections.flatMap(({ v4, v6 }) => [
    Uint32Array.from(v4, r => Number(r[0])),
    Uint32Array.from(v4, r => Number(r[1])),
    BigUint64Array.from(v6, r => r[0]),
    BigUint64Array.from(v6, r => r[1])
  ]);
  return Buffer.concat([head, ...arrays].map(a => Buffer.from(a.buffer, a.byteOffset, a.byteLength)));
};

const assertNotShrunk = async counts => {
  const previous = await kv.read(KV_KEY);
  if (!previous || previous.byteLength < 16) return;
  const old = new Uint32Array(previous, 0, 4);
  counts.forEach((count, i) => {
    if (count < old[i] * MIN_KEEP_RATIO) {
      throw new Error(`数据异常缩水，已中止写入: 第 ${i} 段 ${old[i]} -> ${count}`);
    }
  });
};

const readMetaEch = async () => {
  const raw = await kv.read(ECH_KV_KEY);
  return raw && JSON.parse(Buffer.from(raw).toString());
};

const publish = (meta, cf, ech) => {
  const dir = path.join(__dirname, 'public');
  const list = ({ v4, v6 }) => [...v4, ...v6].map(e => e.cidr);
  const [metaList, cfList] = [meta, cf].map(list);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'data.json'),
    JSON.stringify({
      meta: metaList,
      cf: cfList,
      meta_count: metaList.length,
      cf_count: cfList.length,
      meta_ech: ech?.config ?? null,
      meta_ech_updated_at: ech?.updated_at ?? null,
      updated_at: new Date().toISOString()
    })
  );
  fs.writeFileSync(path.join(dir, '_headers'), HEADERS);
  fs.writeFileSync(path.join(dir, '_redirects'), '/ /data.json 301');
};

const main = async () => {
  const [meta, cf] = await Promise.all(
    [GROUPS.meta, GROUPS.cf].map(async asns => compile(await fetchPrefixes(asns)))
  );
  const sections = [meta, cf].map(toRanges);
  const counts = sections.flatMap(s => [s.v4.length, s.v6.length]);

  if (!counts[0] || !counts[2]) throw new Error(`IPv4 网段为空，已中止写入: ${counts}`);
  await assertNotShrunk(counts);
  const ech = await readMetaEch();

  await kv.write([{ key: KV_KEY, value: encode(sections).toString('base64'), base64: true }]);
  publish(meta, cf, ech);

  console.log(`meta v4/v6: ${counts[0]}/${counts[1]}, cf v4/v6: ${counts[2]}/${counts[3]}`);
};

if (require.main === module) {
  main().catch(e => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { compile, toRanges, encode };
