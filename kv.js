const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CF_KV_NAMESPACE_ID } = process.env;

for (const [name, value] of Object.entries({ CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CF_KV_NAMESPACE_ID })) {
  if (!value) throw new Error(`缺少环境变量 ${name}`);
}

const base = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}`;

const request = async (path, init = {}) => {
  const res = await fetch(base + path, {
    ...init,
    headers: { Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`, ...init.headers },
    signal: AbortSignal.timeout(30000)
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`KV ${res.status}: ${await res.text()}`);
  return res;
};

exports.read = async key => (await request(`/values/${encodeURIComponent(key)}`))?.arrayBuffer() ?? null;

exports.write = entries =>
  request('/bulk', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(entries)
  });
