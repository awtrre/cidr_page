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
  return [...new Set(ips)]; // 去重
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

    // 确保存放静态文件的 public 目录存在
    const outputDir = path.join(__dirname, 'public');
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir);
    }

    // 1. 写入 JSON 数据
    fs.writeFileSync(
      path.join(outputDir, 'data.json'), 
      JSON.stringify(resultData)
    );

    // 2. 写入跨域和缓存头 (_headers)
    // 完美复刻你之前 Worker 的 Header 设置，防止前端调用出现 CORS 跨域拦截
    const headersContent = `
/data.json
  Access-Control-Allow-Origin: *
  Cache-Control: public, max-age=3600
  Content-Type: application/json;charset=UTF-8
`;
    fs.writeFileSync(path.join(outputDir, '_headers'), headersContent.trim());

    // 3. 写入重定向规则 (_redirects)
    // 当用户或代码访问根目录 (/) 时，自动 301 重定向到真正的 /data.json
    fs.writeFileSync(path.join(outputDir, '_redirects'), '/ /data.json 301');
    
    console.log('数据抓取及 CF Pages 配置文件生成完成！');
  } catch (error) {
    console.error('抓取失败:', error);
    process.exit(1);
  }
}

main();
