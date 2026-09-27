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

function sortPrefixes(list) {
  return [...list].sort((a, b) => {
    const aIsV6 = a.includes(':');
    const bIsV6 = b.includes(':');
    if (aIsV6 !== bIsV6) return aIsV6 ? 1 : -1;
    return a.localeCompare(b);
  });
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
