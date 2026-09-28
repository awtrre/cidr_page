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

// ==========================================
// IP <-> 数值 转换（和 Worker 端保持完全一致的算法）
// ==========================================
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

function parseCidr(cidr) {
  const isV6 = cidr.includes(':');
  const [ip, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  if (isV6) {
    const mask = ~((1n << (128n - BigInt(bits))) - 1n);
    const ipBn = ipv6ToBigInt(ip);
    const start = ipBn & mask;
    const end = start | ((1n << (128n - BigInt(bits))) - 1n);
    return { cidr, isV6, start, end, prefixLen: bits };
  } else {
    const mask = ~((1 << (32 - bits)) - 1);
    const ipNum = ipToLong(ip);
    const start = (ipNum & mask) >>> 0;
    const end = ((ipNum & mask) | ((1 << (32 - bits)) - 1)) >>> 0;
    return { cidr, isV6, start, end, prefixLen: bits };
  }
}

// ==========================================
// 去掉被更大网段完全覆盖的冗余 CIDR。
// 原理：两个合法的 CIDR 区间要么完全不相交，要么一个完全包含另一个，
// 不可能出现"部分重叠"，所以排序后一次线性扫描即可清理干净。
// 这一步同时解决了两个问题：
//   1) 减小 data.json 体积（去掉冗余的更具体前缀）
//   2) 让 Worker 端的二分查找结果正确 —— 如果留着嵌套的区间，
//      二分查找只会检查"起始地址最靠后的那一个"，可能漏判被大网段
//      覆盖、但不在任何具体子网段里的 IP。
// ==========================================
function removeContainedCidrs(cidrList) {
  // v4 / v6 分开处理，避免 Number 与 BigInt 混合比较
  const dedupeFamily = (list) => {
    const parsed = list.map(parseCidr);
    // 起始地址升序；起始地址相同则网段更大（prefixLen 更小）的排前面
    parsed.sort((a, b) => {
      if (a.start < b.start) return -1;
      if (a.start > b.start) return 1;
      return a.prefixLen - b.prefixLen;
    });
    const kept = [];
    let coveredUntil = null;
    for (const item of parsed) {
      if (coveredUntil !== null && item.start <= coveredUntil) continue; // 已被更大网段覆盖
      kept.push(item.cidr);
      if (coveredUntil === null || item.end > coveredUntil) coveredUntil = item.end;
    }
    return kept;
  };
  const v4 = cidrList.filter(c => !c.includes(':'));
  const v6 = cidrList.filter(c => c.includes(':'));
  return [...dedupeFamily(v4), ...dedupeFamily(v6)];
}

// 最终排序输出（v4 在前，v6 在后，且各自按数值升序）
function sortPrefixes(list) {
  const v4 = list.filter(c => !c.includes(':'));
  const v6 = list.filter(c => c.includes(':'));

  const byStart = (a, b) => {
    const ka = parseCidr(a).start, kb = parseCidr(b).start;
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  };
  v4.sort(byStart);
  v6.sort(byStart);

  return [...v4, ...v6];
}

async function main() {
  console.log('开始抓取 ASN 数据...');
  try {
    const [metaIpsRaw, cfIpsRaw] = await Promise.all([
      fetchAsnPrefixes(metaASNs),
      fetchAsnPrefixes(cfASNs)
    ]);

    if (metaIpsRaw.length === 0 || cfIpsRaw.length === 0) {
      throw new Error(`抓取结果异常：meta=${metaIpsRaw.length} 条，cf=${cfIpsRaw.length} 条，为避免覆盖线上数据，构建中止`);
    }

    const metaDeduped = removeContainedCidrs(metaIpsRaw);
    const cfDeduped = removeContainedCidrs(cfIpsRaw);

    console.log(`meta: 抓取 ${metaIpsRaw.length} 条 -> 去重后 ${metaDeduped.length} 条`);
    console.log(`cf:   抓取 ${cfIpsRaw.length} 条 -> 去重后 ${cfDeduped.length} 条`);

    const sortedMeta = sortPrefixes(metaDeduped);
    const sortedCf = sortPrefixes(cfDeduped);

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
