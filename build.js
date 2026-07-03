const fs = require('fs');
const path = require('path');

const metaASNs = ['AS32934', 'AS54115', 'AS63293'];
const cfASNs = ['AS13335', 'AS209242', 'AS132892'];

const fetchAsnPrefixes = async (asns) => {
  const reqs = asns.map(asn => 
    fetch(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}`)
  );
  const responses = await Promise.all(reqs);
  
  let ips = [];
  for (const res of responses) {
    if (res.ok) {
      const data = await res.json();
      const prefixes = data.data.prefixes.map(p => p.prefix);
      ips.push(...prefixes);
    }
  }
  return [...new Set(ips)]; 
};

async function main() {
  console.log('开始抓取 ASN 数据...');
  try {
    const [metaIps, cfIps] = await Promise.all([
      fetchAsnPrefixes(metaASNs),
      fetchAsnPrefixes(cfASNs)
    ]);

    const resultData = {
      meta: metaIps,
      cf: cfIps,
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
    
    console.log('数据抓取完成，已保存至 public/data.json');
  } catch (error) {
    console.error('抓取失败:', error);
    process.exit(1); 
  }
}

main();
