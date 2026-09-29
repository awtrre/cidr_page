const net = require('net');
const crypto = require('crypto');

const TARGETS = [{ key: 'meta_ech', host: 'www.facebook.com', port: 443 }];
const ATTEMPTS = 3;
const TIMEOUT_MS = 10000;
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const EMPTY = Buffer.alloc(0);

const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CF_KV_NAMESPACE_ID } = process.env;
if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ACCOUNT_ID || !CF_KV_NAMESPACE_ID) {
  throw new Error('缺少 CLOUDFLARE_API_TOKEN / CLOUDFLARE_ACCOUNT_ID / CF_KV_NAMESPACE_ID');
}

const kvBase = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}`;

const kv = async (path, init = {}) => {
  const res = await fetch(kvBase + path, {
    ...init,
    headers: { Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`, ...init.headers },
    signal: AbortSignal.timeout(20000)
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`KV ${res.status}: ${await res.text()}`);
  return res;
};

const kvGet = async key => (await kv(`/values/${encodeURIComponent(key)}`))?.text() ?? null;

const kvPut = entries =>
  kv('/bulk', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(entries)
  });

const u8 = n => Buffer.from([n]);
const u16 = n => Buffer.from([n >> 8, n & 255]);
const u24 = n => Buffer.from([n >> 16, (n >> 8) & 255, n & 255]);
const vec = (size, ...parts) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([size(body.length), body]);
};
const ext = (type, ...parts) => Buffer.concat([u16(type), vec(u16, ...parts)]);

const hash = data => crypto.createHash('sha256').update(data).digest();
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();

const expandLabel = (secret, label, context, length) => {
  const info = Buffer.concat([u16(length), vec(u8, Buffer.from(`tls13 ${label}`)), vec(u8, context)]);
  return hmac(secret, Buffer.concat([info, u8(1)])).subarray(0, length);
};

const buildClientHello = (host, pub) => {
  const extensions = Buffer.concat([
    ext(0, vec(u16, u8(0), vec(u16, Buffer.from(host)))),
    ext(10, vec(u16, u16(0x001d))),
    ext(13, vec(u16, u16(0x0403), u16(0x0804), u16(0x0401))),
    ext(43, vec(u8, u16(0x0304))),
    ext(51, vec(u16, u16(0x001d), vec(u16, pub))),
    ext(
      0xfe0d,
      u8(0),
      u16(1),
      u16(1),
      u8(crypto.randomInt(256)),
      vec(u16, crypto.randomBytes(32)),
      vec(u16, crypto.randomBytes(224))
    )
  ]);
  const body = Buffer.concat([
    u16(0x0303),
    crypto.randomBytes(32),
    vec(u8, crypto.randomBytes(32)),
    vec(u16, u16(0x1301)),
    vec(u8, u8(0)),
    vec(u16, extensions)
  ]);
  return Buffer.concat([u8(1), vec(u24, body)]);
};

const serverShare = message => {
  let o = 38;
  o += 1 + message[o] + 3;
  const end = o + 2 + message.readUInt16BE(o);
  o += 2;
  while (o < end) {
    const type = message.readUInt16BE(o);
    const len = message.readUInt16BE(o + 2);
    if (type === 51) return message.subarray(o + 8, o + 4 + len);
    o += 4 + len;
  }
  throw new Error('ServerHello 缺少 key_share');
};

const handshakeKeys = (shared, transcript) => {
  const zeros = Buffer.alloc(32);
  const derived = expandLabel(hmac(zeros, zeros), 'derived', hash(EMPTY), 32);
  const secret = expandLabel(hmac(derived, shared), 's hs traffic', hash(transcript), 32);
  return {
    key: expandLabel(secret, 'key', EMPTY, 16),
    iv: expandLabel(secret, 'iv', EMPTY, 12)
  };
};

const decrypt = ({ key, iv }, header, body) => {
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAAD(header);
  decipher.setAuthTag(body.subarray(-16));
  const plain = Buffer.concat([decipher.update(body.subarray(0, -16)), decipher.final()]);
  let end = plain.length;
  while (end > 0 && plain[end - 1] === 0) end--;
  return { type: plain[end - 1], data: plain.subarray(0, end - 1) };
};

const findEch = data => {
  if (data[0] !== 8) return null;
  const body = data.subarray(4, 4 + data.readUIntBE(1, 3));
  for (let p = 2; p + 4 <= body.length; ) {
    const type = body.readUInt16BE(p);
    const len = body.readUInt16BE(p + 2);
    if (type === 0xfe0d) return body.subarray(p + 4, p + 4 + len);
    p += 4 + len;
  }
  return null;
};

const probeOnce = (host, port) =>
  new Promise((resolve, reject) => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const hello = buildClientHello(host, pub);
    const socket = net.connect(port, host);
    let buf = EMPTY;
    let keys = null;

    const done = (fn, value) => {
      socket.destroy();
      fn(value);
    };

    socket.setTimeout(TIMEOUT_MS, () => done(reject, new Error('超时')));
    socket.on('error', reject);
    socket.on('close', () => reject(new Error('连接被关闭')));
    socket.on('connect', () => socket.write(Buffer.concat([u8(22), u16(0x0301), vec(u16, hello)])));
    socket.on('data', chunk => {
      buf = Buffer.concat([buf, chunk]);
      try {
        while (buf.length >= 5 && buf.length >= 5 + buf.readUInt16BE(3)) {
          const header = buf.subarray(0, 5);
          const body = buf.subarray(5, 5 + header.readUInt16BE(3));
          buf = buf.subarray(5 + body.length);

          if (header[0] === 21) throw new Error('收到 TLS Alert');

          if (header[0] === 22 && !keys) {
            const shared = crypto.diffieHellman({
              privateKey,
              publicKey: crypto.createPublicKey({
                key: Buffer.concat([SPKI_PREFIX, serverShare(body)]),
                format: 'der',
                type: 'spki'
              })
            });
            keys = handshakeKeys(shared, Buffer.concat([hello, body]));
          } else if (header[0] === 23 && keys) {
            const { type, data } = decrypt(keys, header, body);
            if (type === 22) return done(resolve, findEch(data));
          }
        }
      } catch (e) {
        done(reject, e);
      }
    });
  });

const probe = async (host, port) => {
  for (let i = 1; ; i++) {
    try {
      return await probeOnce(host, port);
    } catch (e) {
      if (i >= ATTEMPTS) throw e;
      await new Promise(r => setTimeout(r, 1000 * i));
    }
  }
};

const isValid = cfg => {
  if (!cfg || cfg.length < 6 || cfg.readUInt16BE(0) !== cfg.length - 2) return false;
  let o = 2;
  while (o + 4 <= cfg.length && cfg.readUInt16BE(o) === 0xfe0d) o += 4 + cfg.readUInt16BE(o + 2);
  return o === cfg.length;
};

const sync = async ({ key, host, port }) => {
  const cfg = await probe(host, port);
  if (!isValid(cfg)) throw new Error(`${host} 未返回有效的 ECH 配置`);
  const config = cfg.toString('base64');
  const current = JSON.parse((await kvGet(key)) ?? 'null');
  if (current?.config === config) return null;
  return { key, value: JSON.stringify({ host, config, updated_at: new Date().toISOString() }) };
};

(async () => {
  const results = await Promise.allSettled(TARGETS.map(sync));
  results.forEach((r, i) => r.status === 'rejected' && console.error(`${TARGETS[i].key}: ${r.reason.message}`));
  const updates = results.flatMap(r => (r.status === 'fulfilled' && r.value ? [r.value] : []));
  if (updates.length) await kvPut(updates);
  console.log(`已更新 ${updates.length} 项`);
  if (results.some(r => r.status === 'rejected')) process.exitCode = 1;
})().catch(e => {
  console.error(e);
  process.exit(1);
});
