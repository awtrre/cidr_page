const fs = require('fs');
const path = require('path');

const metaASNs = ['AS32934', 'AS54115', 'AS63293'];
const cfASNs = ['AS13335', 'AS209242', 'AS132892'];

const FETCH_TIMEOUT_MS = 10000;
const MAX_RETRIES = 3;

async function fetchWithRetry(url, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (res.ok) return res;
      throw new Error(`HTTP ${res.status}`);
    } catch (e) {
      if (attempt === retries) throw e;
      const backoff = 500 * attempt;
      console.warn(`  请求失败 (第 ${attempt} 次): ${e.message}，${backoff}ms 后重试...`);
      await new Promise(r => setTimeout(r, backoff));
    }
  }
}

const fetchAsnPrefixes = async (asns) => {
  const reqs = asns.map(asn =>
    fetchWithRetry(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}`)
      .catch(e => {
        console.error(`  ASN ${asn} 抓取彻底失败: ${e.message}`);
        return null;
      })
  );
  const responses = await Promise.all(reqs);

  let ips = [];
  for (const res of responses) {
    if (res && res.ok) {
      const data = await res.json();
      const prefixes = data.data.prefixes.map(p => p.prefix);
      ips.push(...prefixes);
    }
  }
  return [...new Set(ips)];
};

function ipToLong(ip) {
  return ip.split('.').reduce((a, b) => (a << 8) + parseInt(b, 10), 0) >>> 0;
}

function ipv6ToBigInt(ip) {
  let p = ip.split(':');
  if (ip.includes('::')) {
    const [f, s] = ip.split('::'), fP = f ? f.split(':') : [], sP = s ? s.split(':') : [];
    p = [...fP, ...Array(8 - fP.length - sP.length).fill('0'), ...sP];
  }
  return p.reduce((a, b) => (a << 16n) + BigInt(parseInt(b || '0', 16)), 0n);
}

function prefixSortKey(cidr) {
  const [ip] = cidr.split('/');
  if (ip.includes(':')) {
    try { return ipv6ToBigInt(ip); } catch (e) { return -1n; }
  }
  try { return BigInt(ipToLong(ip)); } catch (e) { return -1n; }
}

function sortPrefixes(list) {
  const v4 = list.filter(c => !c.includes(':'));
  const v6 = list.filter(c => c.includes(':'));

  v4.sort((a, b) => {
    const ka = prefixSortKey(a), kb = prefixSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  v6.sort((a, b) => {
    const ka = prefixSortKey(a), kb = prefixSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });

  // v4 在前，v6 在后，和之前的输出习惯保持一致
  return [...v4, ...v6];
}

async function main() {
  console.log('开始抓取 ASN 数据...');
  try {
    const [metaIps, cfIps] = await Promise.all([
      fetchAsnPrefixes(metaASNs),
      fetchAsnPrefixes(cfASNs)
    ]);

    if (metaIps.length === 0 || cfIps.length === 0) {
      throw new Error(`抓取结果异常：meta=${metaIps.length} 条，cf=${cfIps.length} 条，为避免覆盖线上数据，构建中止`);
    }

    const sortedMeta = sortPrefixes(metaIps);
    const sortedCf = sortPrefixes(cfIps);

    const resultData = {
      meta: sortedMeta,
      cf: sortedCf,
      meta_count: sortedMeta.length,
      cf_count: sortedCf.length,
      updated_at: new Date().toISOString()
    };

    const outputDir = path.join(__dirname, 'public');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir);
    }

    fs.writeFileSync(
      path.join(outputDir, 'data.json'),
      JSON.stringify(resultData)
    );
    const headersContent = `
/data.json
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=3600, stale-while-revalidate=86400
  Content-Type: application/json;charset=UTF-8
`;
    fs.writeFileSync(path.join(outputDir, '_headers'), headersContent.trim());

    fs.writeFileSync(path.join(outputDir, '_redirects'), '/ /data.json 301');

    console.log(`数据抓取及 CF Pages 配置文件生成完成！(meta: ${sortedMeta.length} 条, cf: ${sortedCf.length} 条)`);
  } catch (error) {
    console.error('抓取失败:', error);
    process.exit(1);
  }
}

main();
