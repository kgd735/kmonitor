// ==========================================
// KUI Serverless 聚合网关后端 - 精简核心版
// (包含：自动建表升级 + 极速8合1协议生成 + 探针管理 + Clash订阅 + 动态云端测速/主题)
// ==========================================

async function sha256(text) {
    const buffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret, message) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
    return Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, '0')).join('');
}

function bytesEqual(left, right) { if (left.length !== right.length) return false; let diff = 0; for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i]; return diff === 0; }
// 恒定时间字符串比较：先哈希再比较，避免长度/内容泄露给计时攻击。
// 空值一律返回 false（fail-closed）。
async function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || !a.length || !b.length) return false;
    const ah = new TextEncoder().encode(await sha256(a));
    const bh = new TextEncoder().encode(await sha256(b));
    return bytesEqual(ah, bh);
}
function base64Bytes(bytes) { let output = ''; for (const byte of bytes) output += String.fromCharCode(byte); return btoa(output); }
function decodeBase64Bytes(value) { const binary = atob(value); return Uint8Array.from(binary, char => char.charCodeAt(0)); }
async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16)), iterations = 100000) { const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256); return `pbkdf2$${iterations}$${base64Bytes(salt)}$${base64Bytes(new Uint8Array(bits))}`; }
async function passwordMatches(password, stored) { try { if (/^[0-9a-f]{64}$/i.test(stored || '')) return bytesEqual(new TextEncoder().encode(await sha256(password)), new TextEncoder().encode(stored.toLowerCase())); const [kind, rawIterations, rawSalt, rawHash] = String(stored || '').split('$'); if (kind !== 'pbkdf2') return false; const iterations = Number(rawIterations); if (!Number.isInteger(iterations) || iterations < 100000 || iterations > 1000000) return false; const salt = decodeBase64Bytes(rawSalt); const expected = decodeBase64Bytes(rawHash); const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, expected.byteLength * 8); return bytesEqual(new Uint8Array(bits), expected); } catch { return false; } }
async function sessionToken() { const bytes = crypto.getRandomValues(new Uint8Array(32)); return base64Bytes(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''); }

function updateManifest(component, sha, length) { return `v1\n${component}\n${sha}\n${length}\n`; }

async function protectedSubscriptionResponse(request) {
    // Serve the exact ordinary site landing page instead of any subscription
    // profile, error, redirect, or endpoint-specific marker.
    const landing = await fetch(new URL('/', request.url), { headers: { Accept: 'text/html' } });
    return new Response(landing.body, { status: landing.status, headers: landing.headers });
}

const MAX_REPORT_BYTES = 256 * 1024;
const MAX_PROXY_REPORT_BYTES = 32 * 1024;
const MAX_SUBSCRIPTION_BYTES = 2 * 1024 * 1024;
const MAX_NODE_DELTA_BYTES = 1024 * 1024 * 1024 * 1024;
const MAX_REPORT_DELTA_BYTES = MAX_NODE_DELTA_BYTES * 10;

async function readJsonBody(request, maxBytes) {
    const declared = Number(request.headers.get('Content-Length') || 0);
    if (declared && (!Number.isSafeInteger(declared) || declared > maxBytes)) throw new Error('Request body too large');
    const reader = request.body?.getReader();
    if (!reader) return {};
    const chunks = []; let size = 0;
    while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) { await reader.cancel(); throw new Error('Request body too large'); }
        chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JSON object required');
    return parsed;
}

function validIp(value) { return typeof value === 'string' && /^[0-9A-Fa-f:.]{2,64}$/.test(value); }

function validateTrafficReport(data) {
    if (!validIp(data.ip) || typeof data.report_id !== 'string' || data.report_id.length > 160 || !data.report_id.startsWith(`${data.ip}:`)) throw new Error('Invalid report identity');
    const entries = data.node_traffic === undefined ? [] : data.node_traffic;
    if (!Array.isArray(entries) || entries.length > 200) throw new Error('Invalid traffic entries');
    const ids = new Set(); let total = 0;
    for (const entry of entries) {
        if (!entry || !/^[A-Za-z0-9_-]{1,64}$/.test(entry.id || '') || !Number.isSafeInteger(entry.delta_bytes) || entry.delta_bytes <= 0 || entry.delta_bytes > MAX_NODE_DELTA_BYTES || ids.has(entry.id)) throw new Error('Invalid traffic entry');
        ids.add(entry.id); total += entry.delta_bytes;
        if (!Number.isSafeInteger(total) || total > MAX_REPORT_DELTA_BYTES) throw new Error('Traffic report exceeds limit');
    }
    return { ...data, node_traffic: entries, total_delta: total };
}

async function realtimeAdminHeader(env) {
    if (!env.ADMIN_PASSWORD) return null;
    const username = env.ADMIN_USERNAME || 'admin';
    const timestamp = Date.now().toString();
    const keyHex = await sha256(env.ADMIN_PASSWORD);
    const keyBytes = new Uint8Array(keyHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const nonce = crypto.randomUUID();
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${username}\n${timestamp}\n${nonce}\nPOST\n/api/realtime_auth`));
    const signatureHex = Array.from(new Uint8Array(signature), byte => byte.toString(16).padStart(2, '0')).join('');
    return `${btoa(username)}.${timestamp}.${nonce}.${signatureHex}`;
}

async function notifyRealtimePublicPolicy(env, db, enabled, pagesOrigin = '') {
    const authorization = await realtimeAdminHeader(env);
    if (!authorization) return;
    const configured = await getRealtimeUrl(env, db);
    if (!configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/public-policy`, {
        method: 'POST',
        headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-KUI-Pages-Origin': pagesOrigin },
        body: JSON.stringify({ public: enabled }),
    });
}

function realtimeFrequencyPolicy(settings = {}) {
    const admin = Number(settings.realtime_admin_interval || 5);
    const publicInterval = Number(settings.realtime_public_interval || 10);
    const idle = Number(settings.realtime_idle_interval || 30);
    if (!Number.isInteger(admin) || !Number.isInteger(publicInterval) || !Number.isInteger(idle) || admin < 5 || admin > 60 || publicInterval < 10 || publicInterval > 120 || idle < 30 || idle > 600 || publicInterval < admin || idle < publicInterval) return null;
    return { admin, public: publicInterval, idle };
}

async function notifyRealtimeFrequencyPolicy(env, db, settings, pagesOrigin = '') {
    const policy = realtimeFrequencyPolicy(settings);
    const authorization = await realtimeAdminHeader(env);
    const configured = await getRealtimeUrl(env, db);
    if (!policy || !authorization || !configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/frequency-policy`, {
        method: 'POST',
        headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-KUI-Pages-Origin': pagesOrigin },
        body: JSON.stringify(policy),
    });
}

async function notifyRealtimeVps(env, db, ip, pagesOrigin = '') {
    const authorization = await realtimeAdminHeader(env);
    const configured = await getRealtimeUrl(env, db);
    if (!authorization || !configured || !/^https:\/\//i.test(configured)) return;
    await fetch(`${configured.replace(/\/$/, '')}/notify`, { method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json', 'X-KUI-Pages-Origin': pagesOrigin }, body: JSON.stringify({ ip }) });
}

async function chunkBatch(db, statements, size = 100) {
    for (let i = 0; i < statements.length; i += size) {
        await db.batch(statements.slice(i, i + size));
    }
}

function yamlString(value) {
    return `"${String(value ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n')}"`;
}

function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function isPrivateSubscriptionHost(hostname) {
    const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
    if (host === '::1' || host === '::' || host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe8') || host.startsWith('fe9') || host.startsWith('fea') || host.startsWith('feb')) return true;
    const parts = host.split('.');
    if (parts.length !== 4 || parts.some(part => !/^\d+$/.test(part) || Number(part) > 255)) return false;
    const [a, b] = parts.map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

function validateSubscriptionUrl(value) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash || (url.port && url.port !== '443') || isPrivateSubscriptionHost(url.hostname)) throw new Error('订阅地址不安全');
    return url;
}

async function readBoundedText(response) {
    const declared = Number(response.headers.get('Content-Length') || 0);
    if (declared && declared > MAX_SUBSCRIPTION_BYTES) throw new Error('订阅文件过大');
    const reader = response.body?.getReader(); const chunks = []; let size = 0;
    while (reader) { const { done, value } = await reader.read(); if (done) break; size += value.byteLength; if (size > MAX_SUBSCRIPTION_BYTES) { await reader.cancel(); throw new Error('订阅文件过大'); } chunks.push(value); }
    const output = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
    return new TextDecoder().decode(output);
}

async function fetchPublicSubscription(initialUrl) {
    let current = validateSubscriptionUrl(initialUrl);
    for (let redirects = 0; redirects <= 3; redirects++) {
        const response = await fetch(current.toString(), { redirect: 'manual', headers: { 'User-Agent': 'v2rayN/6.44', 'Accept': '*/*' }, signal: AbortSignal.timeout(15000) });
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('Location');
            if (!location || redirects === 3) throw new Error('订阅重定向无效或过多');
            current = validateSubscriptionUrl(new URL(location, current).toString()); continue;
        }
        if (!response.ok) throw new Error(`订阅请求失败: ${response.status}`);
        return response;
    }
    throw new Error('订阅重定向过多');
}

function formatIpForLink(ip) {
    if (!ip || typeof ip !== 'string') return ip;
    if (ip.startsWith('[') && ip.endsWith(']')) return ip;
    if (ip.includes(':')) return `[${ip}]`;
    return ip;
}

function parseVLESSLink(raw) {
    try {
        const schemeSep = raw.indexOf('://');
        if (schemeSep < 0) return null;
        let rest = raw.slice(schemeSep + 3);
        const hashIdx = rest.indexOf('#');
        let remark = '', hash = '';
        if (hashIdx !== -1) { hash = rest.slice(hashIdx + 1); rest = rest.slice(0, hashIdx); }
        const qIdx = rest.indexOf('?');
        let queryPart = '';
        if (qIdx !== -1) { queryPart = rest.slice(qIdx + 1); rest = rest.slice(0, qIdx); }

        const findAt = (s) => {
            const idx = s.lastIndexOf('@');
            if (idx >= 0) return [idx, 1];
            const encIdx = s.lastIndexOf('%40');
            if (encIdx >= 0) return [encIdx, 3];
            return [-1, 0];
        };
        const [atIdx, sepLen] = findAt(rest);
        if (atIdx < 0) return null;
        const safeDecode = (s) => { try { return decodeURIComponent(s); } catch(e) { return s; } };
        const uuid = safeDecode(rest.slice(0, atIdx));
        let hostPart = rest.slice(atIdx + sepLen);
        let port = 443;
        if (hostPart.startsWith('[')) {
            const bracketEnd = hostPart.indexOf(']');
            if (bracketEnd < 0) return null;
            const ipv6Addr = hostPart.slice(0, bracketEnd + 1);
            const afterBracket = hostPart.slice(bracketEnd + 1);
            if (afterBracket.startsWith(':')) {
                const portMatch = afterBracket.slice(1).match(/^\d+/);
                if (portMatch) port = parseInt(portMatch[0], 10);
            }
            hostPart = ipv6Addr;
        } else {
            let hostWithoutPort = hostPart;
            const colonIdx = hostPart.lastIndexOf(':');
            if (colonIdx > 0 && !hostPart.slice(0, colonIdx).includes(':')) {
                const pStr = hostPart.slice(colonIdx + 1);
                if (/^\d+$/.test(safeDecode(pStr))) {
                    port = parseInt(pStr, 10);
                    hostWithoutPort = hostPart.slice(0, colonIdx);
                }
            }
            hostPart = safeDecode(hostWithoutPort);
        }
        const params = new URLSearchParams(queryPart);
        const pbk = params.get('pbk') || '';
        const sid = params.get('sid') || '';
        const sni = safeDecode(params.get('sni') || '') || hostPart;
        const flow = params.get('flow') || '';
        const network = params.get('type') || 'tcp';
        const host = safeDecode(params.get('host') || '') || '';
        const path = safeDecode(params.get('path') || '') || '';
        const name = hash ? (() => { try { return decodeURIComponent(hash); } catch(e) { return hash; } })() : '';
        const isReality = params.get('security') === 'reality' || !!pbk;
        const protocol = isReality ? 'Reality' : 'VLESS';
        if (!uuid || !hostPart) return null;
        return {
            protocol, name, address: hostPart, port, uuid, password: '', sni,
            public_key: pbk, short_id: sid, flow, network: network.toLowerCase(), host, path, extra: '', enable: 1
        };
    } catch (e) { return null; }
}

function parseHysteria2Link(raw) {
    try {
        let prefixLen = 11;
        if (raw.startsWith('hy2://')) prefixLen = 5;
        else if (raw.startsWith('hysteria2://')) prefixLen = 12;
        else if (raw.startsWith('hysteria://')) prefixLen = 10;
        let rest = raw.slice(prefixLen).replace(/^\/+/, '');
        const hashIdx = rest.indexOf('#');
        let remark = '';
        if (hashIdx !== -1) { remark = rest.slice(hashIdx + 1); rest = rest.slice(0, hashIdx); }
        const qIdx = rest.indexOf('?');
        let queryPart = '';
        if (qIdx !== -1) { queryPart = rest.slice(qIdx + 1); rest = rest.slice(0, qIdx); }
        const params = new URLSearchParams(queryPart);
        let password = '';
        let host = '';
        let port = 443;
        const safeDecode = (s) => { try { return decodeURIComponent(s); } catch(e) { return s; } };
        const findAt = (s) => {
            const idx = s.lastIndexOf('@');
            if (idx >= 0) return [idx, 1];
            const encIdx = s.lastIndexOf('%40');
            if (encIdx >= 0) return [encIdx, 3];
            return [-1, 0];
        };
        const [atIdx, sepLen] = findAt(rest);
        if (atIdx >= 0) {
            password = safeDecode(rest.slice(0, atIdx));
            host = safeDecode(rest.slice(atIdx + sepLen));
        } else {
            password = params.get('password') || '';
            host = safeDecode(rest);
        }
        const colonIdx = host.lastIndexOf(':');
        if (colonIdx !== -1) {
            const maybePort = host.slice(colonIdx + 1);
            if (/^\d+$/.test(maybePort)) {
                port = parseInt(maybePort, 10);
                host = host.slice(0, colonIdx);
            }
        }
        const sni = safeDecode(params.get('sni') || '') || host;
        const name = remark ? (() => { try { return decodeURIComponent(remark); } catch (e) { return remark; } })() : '';
        if (!host || isNaN(port)) return null;
        return {
            protocol: 'Hysteria2', name, address: host, port, uuid: password, password, sni,
            public_key: '', short_id: '', flow: '', network: 'udp', host: '', path: '', extra: '', enable: 1
        };
    } catch (e) {
        return null;
    }
}

function base64ToUtf8(str) {
    try {
        const s = str.replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4;
        const padded = pad ? s + '='.repeat(4 - pad) : s;
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return new TextDecoder().decode(bytes);
    } catch (e) {
        return atob(str);
    }
}

function safeHashDecode(url) {
    const raw = (url.hash && url.hash.slice(1)) || '';
    if (!raw) return '';
    try { return decodeURIComponent(raw); } catch (e) { return raw; }
}

function resolveUrlPortForHysteria2(url) {
    if (url.port && String(url.port) !== '') return parseInt(url.port);
    const insecure = (url.searchParams.get('insecure') || url.searchParams.get('allowinsecure') || '').toString();
    const mbs = (url.searchParams.get('downmbps') || url.searchParams.get('upmbps') || '0').toString();
    if (insecure === '1' || parseInt(mbs, 10) > 0) return 443;
    const path = (url.pathname && url.pathname.replace(/^\//, '')) || '';
    const p = parseInt(path, 10);
    return Number.isFinite(p) && p > 0 ? p : 443;
}

async function parseThirdPartySubscription(content) {
    let nodes = [];
    let decoded = content;
    const trimmed = content.trim();
    if (!trimmed.includes('://')) {
        try {
            decoded = base64ToUtf8(trimmed);
        } catch (e) {
            decoded = content;
        }
    }
    // Keep the legacy importer behavior: parse every line in a downloaded
    // subscription instead of silently truncating larger airport profiles.
    // Network size and timeout limits are still enforced before parsing.
    const lines = decoded.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const protocolCounts = {};
    const debug = { totalLines: lines.length, matched: 0, rejected: 0 };
    for (const raw of lines) {
        const rawLC = raw.toLowerCase();
        const sep = rawLC.indexOf('://');
        const pf = sep > 0 ? rawLC.substring(0, sep + 3) : rawLC.substring(0, Math.min(rawLC.length, 40));
        let node = null;
        try {
            if (rawLC.startsWith('vmess://')) {
                node = {
                    protocol: 'VMess', name: '', address: '', port: 443, uuid: '', password: '', sni: '',
                    public_key: '', short_id: '', flow: '', network: 'tcp', host: '', path: '', extra: raw, enable: 1
                };
                try {
                    const jsonStr = base64ToUtf8(raw.slice(8));
                    const obj = JSON.parse(jsonStr);
                    node.name = obj.ps || ''; node.address = obj.add || obj.host || ''; node.port = parseInt(obj.port) || 443;
                    node.uuid = obj.id || obj.uuid || ''; node.sni = obj.sni || obj.host || obj.add || '';
                    node.network = (obj.net || 'tcp').toLowerCase(); node.host = obj.host || ''; node.path = obj.path || '';
                } catch (e) {}
            } else if (rawLC.startsWith('vless://')) {
                const parsed = parseVLESSLink(raw);
                if (parsed) node = parsed;
            } else if (rawLC.startsWith('trojan://')) {
                const parsed = parseVLESSLink(raw);
                if (parsed) { parsed.protocol = 'Trojan'; parsed.password = parsed.uuid; parsed.uuid = ''; node = parsed; }
            } else if (rawLC.startsWith('hysteria2://') || rawLC.startsWith('hy2://') || rawLC.startsWith('hysteria://')) {
                const parsed = parseHysteria2Link(raw);
                if (parsed) node = parsed;
            } else if (rawLC.startsWith('tuic://')) {
                const url = new URL(raw);
                node = {
                    protocol: 'TUIC', name: safeHashDecode(url), address: url.hostname, port: parseInt(url.port) || 443,
                    uuid: url.username, password: url.password || '', sni: url.searchParams.get('sni') || url.hostname,
                    public_key: '', short_id: '', flow: '', network: 'udp', host: '', path: '', extra: '', enable: 1
                };
            } else if (rawLC.startsWith('naive+https://') || rawLC.startsWith('naive://')) {
                const url = new URL(raw);
                node = {
                    protocol: 'Naive', name: safeHashDecode(url), address: url.hostname, port: parseInt(url.port) || 443,
                    uuid: url.username, password: url.password || '', sni: url.searchParams.get('sni') || url.hostname,
                    public_key: '', short_id: '', flow: '', network: 'tcp', host: '', path: '', extra: '', enable: 1
                };
            } else if (rawLC.startsWith('ss://')) {
                const rest = raw.slice(5).replace(/#.*$/, '');
                let host = '', port = 8388, password = '', method = '';
                if (rest.includes('@')) {
                    const [uinfo, saddr] = rest.split('@');
                    const decodedUi = base64ToUtf8(uinfo);
                    const [m, p] = decodedUi.split(':');
                    method = m || 'aes-256-gcm';
                    password = p || '';
                    const [h, pStr] = saddr.split(':');
                    host = h;
                    port = parseInt(pStr) || 8388;
                } else {
                    const decodedRest = base64ToUtf8(rest);
                    const parts = decodedRest.split('@');
                    if (parts.length === 2) {
                        const [uinfo2, saddr2] = parts;
                        const [m, p] = uinfo2.split(':');
                        method = m || 'aes-256-gcm';
                        password = p || '';
                        const [h, pStr] = saddr2.split(':');
                        host = h;
                        port = parseInt(pStr) || 8388;
                    }
                }
                node = {
                    protocol: 'SS', name: '', address: host, port: port, uuid: method, password, sni: host,
                    public_key: '', short_id: '', flow: '', network: 'tcp', host: '', path: '', extra: JSON.stringify({method}), enable: 1
                };
            } else if (rawLC.startsWith('ssr://')) {
                const b64 = raw.slice(6).replace(/#.*$/, '');
                const decoded = base64ToUtf8(b64);
                const base = decoded.split('/?')[0];
                const bpms = base.split(':');
                if (bpms.length >= 5) {
                    const method = bpms[0], password = base64ToUtf8(bpms[1]), host = bpms[2], port = bpms[3];
                    node = {
                        protocol: 'SSR', name: '', address: host, port: parseInt(port) || 8388, uuid: method, password,
                        sni: host, public_key: '', short_id: '', flow: '', network: 'tcp', host: '', path: '',
                        extra: JSON.stringify({method, protocol: bpms[4], obfs: bpms[5]}), enable: 1
                    };
                }
            } else {
                const sep = raw.indexOf('://');
                const pf = sep > 0 ? rawLC.substring(0, sep + 3) : rawLC.substring(0, Math.min(rawLC.length, 30));
                debug.rejected++;
            }
        } catch (e) {
            node = null;
        }
        if (node && node.address && node.port) {
            node.id = crypto.randomUUID();
            nodes.push(node);
            protocolCounts[node.protocol] = (protocolCounts[node.protocol] || 0) + 1;
            debug.matched++;
        } else if (node) debug.rejected++;
    }
    return { nodes, protocolCounts, debug };
}

let schemaReadyPromise = null;
let lastReceiptCleanup = 0;

// [D1 优化] 鉴权热路径的隔离内缓存（60 秒 TTL）：
// - Bearer 会话：面板每次调用都过 verifyAuth，避免每次查 auth_sessions；
// - Agent Token：report/config 高频轮询，避免每次查 servers。
// 失效语义：本隔离内登出/改密/踢会话会 bump epoch 立即失效；
// 其他隔离最迟 60 秒自然过期。Agent 删除/换 token 同理有 ≤60 秒窗口，
// 与 D1 本身跨地域最终一致性的延迟相当。
const sessionCache = new Map();
let sessionCacheEpoch = 0;
function invalidateSessionCache() { sessionCacheEpoch++; sessionCache.clear(); }
const agentTokenCache = new Map();

// [D1 优化] realtime_url 极少变更，60 秒缓存供 config/cron/通知路径复用。
let realtimeUrlCache = { at: 0, value: '' };
async function getRealtimeUrl(env, db) {
    if (env.REALTIME_URL) return env.REALTIME_URL;
    if (Date.now() - realtimeUrlCache.at < 60000) return realtimeUrlCache.value;
    try {
        const row = await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first();
        realtimeUrlCache = { at: Date.now(), value: row?.val || '' };
    } catch (e) { /* 读取失败时沿用旧值 */ }
    return realtimeUrlCache.value;
}

function loginThrottleKey(request) { return `${request.headers.get('CF-Connecting-IP') || 'unknown'}:${String(request.headers.get('Authorization') || '').split('.')[0].slice(0, 128)}`; }

async function loginAllowed(db, request) {
    const row = await db.prepare('SELECT failures, window_started_at, blocked_until FROM login_throttles WHERE key = ?').bind(loginThrottleKey(request)).first();
    return !row || Number(row.blocked_until || 0) <= Date.now();
}

async function recordLoginFailure(db, request) {
    const key = loginThrottleKey(request); const now = Date.now();
    const row = await db.prepare('SELECT failures, window_started_at FROM login_throttles WHERE key = ?').bind(key).first();
    const freshWindow = !row || now - Number(row.window_started_at || 0) > 15 * 60 * 1000;
    const failures = freshWindow ? 1 : Number(row.failures || 0) + 1;
    const blockedUntil = failures >= 8 ? now + 15 * 60 * 1000 : 0;
    await db.prepare('INSERT INTO login_throttles (key, failures, window_started_at, blocked_until) VALUES (?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET failures = excluded.failures, window_started_at = excluded.window_started_at, blocked_until = excluded.blocked_until').bind(key, failures, freshWindow ? now : row.window_started_at, blockedUntil).run();
}

async function initializeDbSchema(db) {
    const initQueries = [
        `CREATE TABLE IF NOT EXISTS servers (ip TEXT PRIMARY KEY, name TEXT NOT NULL, cpu INTEGER DEFAULT 0, mem REAL DEFAULT 0, last_report INTEGER DEFAULT 0, alert_sent INTEGER DEFAULT 0, disk INTEGER DEFAULT 0, load TEXT DEFAULT "", uptime TEXT DEFAULT "", net_in_speed INTEGER DEFAULT 0, net_out_speed INTEGER DEFAULT 0, tcp_conn INTEGER DEFAULT 0, udp_conn INTEGER DEFAULT 0)`,
        `CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT NOT NULL, traffic_limit INTEGER DEFAULT 0, traffic_used INTEGER DEFAULT 0, expire_time INTEGER DEFAULT 0, enable INTEGER DEFAULT 1, sub_token TEXT)`,
        `CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, uuid TEXT NOT NULL, vps_ip TEXT NOT NULL, protocol TEXT NOT NULL, port INTEGER NOT NULL, sni TEXT, private_key TEXT, public_key TEXT, short_id TEXT, relay_type TEXT, target_ip TEXT, target_port INTEGER, target_id TEXT, enable INTEGER DEFAULT 1, traffic_used INTEGER DEFAULT 0, traffic_limit INTEGER DEFAULT 0, expire_time INTEGER DEFAULT 0, username TEXT DEFAULT 'admin', network TEXT DEFAULT 'tcp', FOREIGN KEY(vps_ip) REFERENCES servers(ip) ON DELETE CASCADE)`,
        `CREATE TABLE IF NOT EXISTS traffic_stats (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, delta_bytes INTEGER DEFAULT 0, timestamp INTEGER NOT NULL, FOREIGN KEY(ip) REFERENCES servers(ip) ON DELETE CASCADE)`,
        `CREATE INDEX IF NOT EXISTS idx_traffic_ip_time ON traffic_stats(ip, timestamp)`,
        `CREATE TABLE IF NOT EXISTS sys_config (key TEXT PRIMARY KEY, val TEXT, ts INTEGER)`,
        `CREATE TABLE IF NOT EXISTS proxy_ctrl_servers (ip TEXT PRIMARY KEY, details TEXT, last_seen INTEGER)`,
        `CREATE TABLE IF NOT EXISTS server_logs (ip TEXT PRIMARY KEY, logs TEXT, updated_at INTEGER)`,
        `CREATE TABLE IF NOT EXISTS proxy_slot_map (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS report_receipts (report_id TEXT PRIMARY KEY, vps_ip TEXT NOT NULL, created_at INTEGER NOT NULL, applied INTEGER DEFAULT 1)`,
        `CREATE TABLE IF NOT EXISTS auth_replays (nonce TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS login_throttles (key TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_started_at INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0)`,
        `CREATE TABLE IF NOT EXISTS auth_sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS user_groups (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)`,
        `CREATE TABLE IF NOT EXISTS user_group_members (group_id TEXT NOT NULL, username TEXT NOT NULL, PRIMARY KEY(group_id, username), FOREIGN KEY(group_id) REFERENCES user_groups(id) ON DELETE CASCADE, FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE)`,
        `CREATE TABLE IF NOT EXISTS user_group_resources (group_id TEXT NOT NULL, resource_type TEXT NOT NULL CHECK(resource_type IN ('vps', 'node')), resource_id TEXT NOT NULL, PRIMARY KEY(group_id, resource_type, resource_id), FOREIGN KEY(group_id) REFERENCES user_groups(id) ON DELETE CASCADE)`,
        `CREATE INDEX IF NOT EXISTS idx_group_members_user ON user_group_members(username)`,
        `CREATE INDEX IF NOT EXISTS idx_group_resources_resource ON user_group_resources(resource_type, resource_id)`,
        `CREATE TABLE IF NOT EXISTS frp_global_config (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS frp_servers (node_key TEXT PRIMARY KEY, ip TEXT, boot_id TEXT DEFAULT '', details TEXT, log TEXT DEFAULT '', candidates TEXT DEFAULT '[]', last_seen INTEGER)`,
        `CREATE TABLE IF NOT EXISTS frp_server_config (node_key TEXT PRIMARY KEY, ip TEXT, boot_id TEXT DEFAULT '', slot_map TEXT DEFAULT '{"0":"JP"}', mode TEXT DEFAULT 'auto', manual_node_ip TEXT DEFAULT '', youtube_check TEXT DEFAULT 'false', force_switch TEXT DEFAULT '{}', pending_uninstall INTEGER DEFAULT 0)`
    ];
    for (let query of initQueries) { try { await db.prepare(query).run(); } catch (e) {} }
    try { await db.prepare("ALTER TABLE nodes ADD COLUMN network TEXT DEFAULT 'tcp'").run(); } catch (e) {}
    try { await db.prepare("UPDATE nodes SET network = 'http' WHERE protocol = 'H2-Reality' AND (network IS NULL OR network = '' OR network = 'tcp')").run(); } catch (e) {}
    try { await db.prepare("UPDATE nodes SET network = 'grpc' WHERE protocol = 'gRPC-Reality' AND (network IS NULL OR network = '' OR network = 'tcp')").run(); } catch (e) {}

    const probeQueries = [
        `CREATE TABLE IF NOT EXISTS probe_settings (key TEXT PRIMARY KEY, value TEXT)`,
        `CREATE TABLE IF NOT EXISTS probe_servers (
            id TEXT PRIMARY KEY, name TEXT, cpu TEXT, ram TEXT, disk TEXT, load_avg TEXT, uptime TEXT, last_updated INTEGER,
            ram_total TEXT, net_rx TEXT, net_tx TEXT, net_in_speed TEXT, net_out_speed TEXT,
            os TEXT, cpu_info TEXT, arch TEXT, boot_time TEXT, ram_used TEXT, swap_total TEXT, 
            swap_used TEXT, disk_total TEXT, disk_used TEXT, processes TEXT, tcp_conn TEXT, udp_conn TEXT, 
            country TEXT, ip_v4 TEXT, ip_v6 TEXT, server_group TEXT DEFAULT '默认分组', price TEXT DEFAULT '', 
            expire_date TEXT DEFAULT '', bandwidth TEXT DEFAULT '', traffic_limit TEXT DEFAULT '', agent_os TEXT DEFAULT 'debian',
            ping_ct TEXT DEFAULT '0', ping_cu TEXT DEFAULT '0', ping_cm TEXT DEFAULT '0', ping_bd TEXT DEFAULT '0',
            monthly_rx TEXT DEFAULT '0', monthly_tx TEXT DEFAULT '0', last_rx TEXT DEFAULT '0', last_tx TEXT DEFAULT '0', 
            reset_month TEXT DEFAULT '', history TEXT DEFAULT '{}', is_hidden TEXT DEFAULT 'false', virt TEXT DEFAULT '',             reset_day TEXT DEFAULT '1'
        )`,
        `CREATE TABLE IF NOT EXISTS proxy_servers (ip TEXT PRIMARY KEY, socks_ip TEXT, port INTEGER, user TEXT, pass TEXT, country TEXT DEFAULT '', enabled INTEGER DEFAULT 1, last_seen INTEGER)`
    ];
    for (let query of probeQueries) { try { await db.prepare(query).run(); } catch (e) {} }

    try { await db.prepare("SELECT username FROM nodes LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE nodes ADD COLUMN username TEXT DEFAULT 'admin'").run(); } catch(e){} }
    try { await db.prepare("SELECT disk FROM servers LIMIT 1").first(); } catch (e) { const newCols = ['disk INTEGER DEFAULT 0', 'load TEXT DEFAULT ""', 'uptime TEXT DEFAULT ""', 'net_in_speed INTEGER DEFAULT 0', 'net_out_speed INTEGER DEFAULT 0', 'tcp_conn INTEGER DEFAULT 0', 'udp_conn INTEGER DEFAULT 0']; for (let col of newCols) { try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${col}`).run(); } catch(err){} } }
    try { await db.prepare("SELECT sub_token FROM users LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE users ADD COLUMN sub_token TEXT").run(); } catch(err){} }
    try {
        const { results: usersWithoutToken } = await db.prepare("SELECT username FROM users WHERE sub_token IS NULL OR sub_token = '' LIMIT 100").all();
        if (usersWithoutToken && usersWithoutToken.length) await db.batch(usersWithoutToken.map(user => db.prepare("UPDATE users SET sub_token = ? WHERE username = ? AND (sub_token IS NULL OR sub_token = '')").bind(crypto.randomUUID(), user.username)));
    } catch (error) {}
    try { await db.prepare("SELECT reset_day FROM probe_servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE probe_servers ADD COLUMN reset_day TEXT DEFAULT '1'").run(); } catch(e){} }
    try { await db.prepare("SELECT socks5_enable FROM servers LIMIT 1").first(); } catch (e) { const s5Cols = ['socks5_enable INTEGER DEFAULT 0', 'socks5_addr TEXT DEFAULT ""', 'socks5_port INTEGER DEFAULT 0', 'socks5_user TEXT DEFAULT ""', 'socks5_pass TEXT DEFAULT ""']; for (let col of s5Cols) { try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${col}`).run(); } catch(err){} } }
    try { await db.prepare("SELECT socks5_mode FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN socks5_mode TEXT DEFAULT 'global'").run(); } catch(err){} try { await db.prepare("ALTER TABLE servers ADD COLUMN socks5_domains TEXT DEFAULT ''").run(); } catch(err){} }
    try { await db.prepare("SELECT agent_token FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN agent_token TEXT").run(); } catch(err){} }
    const ensureWarpColumn = async (name, definition) => { try { await db.prepare(`SELECT ${name} FROM servers LIMIT 1`).first(); } catch (error) { try { await db.prepare(`ALTER TABLE servers ADD COLUMN ${name} ${definition}`).run(); } catch (alterError) { if (!/duplicate column/i.test(String(alterError?.message || alterError))) throw alterError; } } };
    await ensureWarpColumn('warp_mode', "TEXT NOT NULL DEFAULT 'off'");
    await ensureWarpColumn('warp_applied_mode', "TEXT NOT NULL DEFAULT 'off'");
    await ensureWarpColumn('warp_revision', 'INTEGER NOT NULL DEFAULT 0');
    await ensureWarpColumn('warp_applied_revision', 'INTEGER NOT NULL DEFAULT 0');
    await ensureWarpColumn('warp_status', "TEXT NOT NULL DEFAULT 'off'");
    await ensureWarpColumn('warp_error', "TEXT NOT NULL DEFAULT ''");
    await ensureWarpColumn('warp_applied_at', 'INTEGER NOT NULL DEFAULT 0');
    await ensureWarpColumn('egress_pending', "TEXT NOT NULL DEFAULT ''");
    await ensureWarpColumn('egress_mode', "TEXT NOT NULL DEFAULT 'native'");
    await ensureWarpColumn('egress_applied_mode', "TEXT NOT NULL DEFAULT 'native'");
    await ensureWarpColumn('egress_revision', 'INTEGER NOT NULL DEFAULT 0');
    await ensureWarpColumn('egress_applied_revision', 'INTEGER NOT NULL DEFAULT 0');
    await ensureWarpColumn('egress_status', "TEXT NOT NULL DEFAULT 'applied'");
    await ensureWarpColumn('egress_error', "TEXT NOT NULL DEFAULT ''");
    await ensureWarpColumn('egress_applied_at', 'INTEGER NOT NULL DEFAULT 0');
    try { await db.prepare("SELECT proxy_mode FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN proxy_mode TEXT DEFAULT 'global'").run(); } catch(err){} }
    try { await db.prepare("SELECT proxy_categories FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN proxy_categories TEXT DEFAULT ''").run(); } catch(err){} }
    try { await db.prepare("SELECT egress_ip FROM servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE servers ADD COLUMN egress_ip TEXT DEFAULT ''").run(); } catch(err){} }
    try { await db.prepare("SELECT last_report_id FROM probe_servers LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE probe_servers ADD COLUMN last_report_id TEXT DEFAULT ''").run(); } catch(err){} }
    try { await db.prepare("SELECT applied FROM report_receipts LIMIT 1").first(); } catch (e) { try { await db.prepare("ALTER TABLE report_receipts ADD COLUMN applied INTEGER DEFAULT 1").run(); } catch(err){} }

    // 初始化云端测速数据
    const checkNodes = await db.prepare("SELECT value FROM probe_settings WHERE key = 'cached_nodes_data'").first();
    if (!checkNodes) {
        try {
            const res = await fetch('https://raw.githubusercontent.com/a63414262/CF-Server-Monitor-Pro/refs/heads/main/nodes.json');
            if (res.ok) {
                const dataText = await res.text();
                await db.prepare("INSERT INTO probe_settings (key, value) VALUES ('cached_nodes_data', ?)").bind(dataText).run();
            }
        } catch(e) {}
    }

    const tpsQueries = [
        `CREATE TABLE IF NOT EXISTS third_party_subscriptions (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, is_enable INTEGER DEFAULT 1, added_at INTEGER, last_fetched_at INTEGER)`,
        `CREATE TABLE IF NOT EXISTS third_party_nodes (id TEXT PRIMARY KEY, subscription_id TEXT NOT NULL, name TEXT, protocol TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL, uuid TEXT, password TEXT, sni TEXT, public_key TEXT, short_id TEXT, flow TEXT, network TEXT, host TEXT, path TEXT, extra TEXT, enable INTEGER DEFAULT 1, created_at INTEGER, FOREIGN KEY(subscription_id) REFERENCES third_party_subscriptions(id) ON DELETE CASCADE)`
    ];
    for (let query of tpsQueries) { try { await db.prepare(query).run(); } catch (e) {} }
}

// [D1 优化] 哨兵快路径：成熟库只需 4 次探测即可确认结构为当前版本，
// 跳过 initializeDbSchema 的 ~60 条 DDL/探测语句（每个新隔离冷启动都省）。
// 任一探测不满足即走完整初始化（含建表/补列/种子数据），行为与旧版一致。
async function schemaLooksCurrent(db) {
    try {
        const row = await db.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name IN ('servers','users','nodes','traffic_stats','sys_config','report_receipts','auth_replays','login_throttles','auth_sessions','user_groups','user_group_members','user_group_resources','probe_settings','probe_servers','third_party_subscriptions','third_party_nodes','frp_global_config','frp_servers','frp_server_config')").first();
        if (Number(row?.c || 0) < 19) return false;
        await db.prepare("SELECT egress_mode, agent_token FROM servers LIMIT 1").first();
        await db.prepare("SELECT last_report_id FROM probe_servers LIMIT 1").first();
        return true;
    } catch (e) { return false; }
}

async function ensureDbSchema(db) {
    if (!schemaReadyPromise) {
        schemaReadyPromise = (async () => {
            if (await schemaLooksCurrent(db)) return;
            await initializeDbSchema(db);
        })().catch(error => {
            schemaReadyPromise = null;
            throw error;
        });
    }
    return schemaReadyPromise;
}

async function verifyAuth(authHeader, request, db, env, context) {
    try {
        if (!authHeader || !env.ADMIN_PASSWORD) return null;
        if (authHeader.startsWith('Bearer ')) {
            const token = authHeader.slice(7);
            if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) return null;
            const tokenHash = await sha256(token);
            const cached = sessionCache.get(tokenHash);
            if (cached && cached.epoch === sessionCacheEpoch && cached.exp > Date.now()) return cached.username;
            const session = await db.prepare('SELECT username, expires_at FROM auth_sessions WHERE token_hash = ? AND expires_at > ?').bind(tokenHash, Date.now()).first();
            if (session?.username) {
                if (sessionCache.size > 512) sessionCache.clear();
                sessionCache.set(tokenHash, { username: session.username, exp: Math.min(Number(session.expires_at) || 0, Date.now() + 60000), epoch: sessionCacheEpoch });
            }
            return session?.username || null;
        }
        const adminUser = env.ADMIN_USERNAME || "admin";
        const adminPass = env.ADMIN_PASSWORD;
        const parts = authHeader.split('.');
        if (parts.length !== 4) return null;
        const [b64User, timestamp, nonce, clientSig] = parts;
        const timestampNumber = Number(timestamp);
        if (!Number.isFinite(timestampNumber) || Math.abs(Date.now() - timestampNumber) > 120000 || !/^[0-9a-f-]{36}$/i.test(nonce)) return null;
        const username = atob(b64User);
        let baseKeyHex;
        if (username === adminUser) baseKeyHex = await sha256(adminPass);
        else return null;
        const keyBytes = new Uint8Array(baseKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
        const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const url = new URL(request.url);
        const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${username}\n${timestamp}\n${nonce}\n${request.method}\n${url.pathname}`));
        const expectedSig = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (clientSig !== expectedSig) return null;
        const receipt = await db.prepare('INSERT OR IGNORE INTO auth_replays (nonce, username, expires_at) VALUES (?, ?, ?)').bind(nonce, username, Date.now() + 180000).run();
        if (Number(receipt.meta?.changes || 0) !== 1) return null;
        context?.waitUntil(db.prepare('DELETE FROM auth_replays WHERE expires_at < ?').bind(Date.now()).run().catch(() => {}));
        return username;
    } catch (error) {
        return null;
    }
}

async function verifyAgent(authHeader, ip, db, env) {
    if (!authHeader || !ip) return false;
    const presentedHash = await sha256(authHeader);
    const cached = agentTokenCache.get(ip);
    if (cached && cached.exp > Date.now()) {
        if (cached.hash === presentedHash) return true;
        // 出示的 token 与缓存不符：落库复核（可能是刚轮换的新 token）
    }
    const server = await db.prepare("SELECT agent_token FROM servers WHERE ip = ?").bind(ip).first();
    if (!server || !server.agent_token) { agentTokenCache.delete(ip); return false; }
    const ok = timingSafeEqual(authHeader, server.agent_token);
    if (ok) {
        if (agentTokenCache.size > 512) agentTokenCache.clear();
        agentTokenCache.set(ip, { hash: await sha256(server.agent_token), exp: Date.now() + 60000 });
    }
    return ok;
}

// 住宅模块 Agent 面 Basic 鉴权。用户名与面板管理员一致（ADMIN_USERNAME），
// 口令优先使用独立的 FRP_AGENT_PASSWORD：设置后 Agent 面只认它，面板管理员
// 密码不再下发到 VPS（c2.json 里写的就是这个独立口令）；未设置时回退
// ADMIN_PASSWORD（与 FRP 原版 WEB_PASS 的统一模型一致）。
async function verifyFrpBasic(request, env) {
    const agentPassword = env.FRP_AGENT_PASSWORD || env.ADMIN_PASSWORD;
    if (!agentPassword) return false;
    const header = request.headers.get('Authorization') || '';
    if (!header.startsWith('Basic ')) return false;
    let decoded = '';
    try { decoded = atob(header.slice(6).trim()); } catch (e) { return false; }
    const sep = decoded.indexOf(':');
    if (sep < 0) return false;
    const userOk = await timingSafeEqual(decoded.slice(0, sep), env.ADMIN_USERNAME || 'admin');
    const passOk = await timingSafeEqual(decoded.slice(sep + 1), agentPassword);
    return userOk && passOk;
}

// ==============================================
// 探针纯净 API 子系统处理
// ==============================================
async function handleProbeAPI(request, env, context, pathArray) {
    const subPath = pathArray ? pathArray.join('/') : '';
    const url = new URL(request.url);
    const method = request.method;
    const db = env.DB;

    // Telegram Bot 交互回调控制
    if (method === 'POST' && subPath === 'tg_webhook') {
        try {
            const webhookSecret = env.TG_WEBHOOK_SECRET || '';
            if (!webhookSecret || request.headers.get('X-Telegram-Bot-Api-Secret-Token') !== webhookSecret) return new Response('Unauthorized', { status: 401 });
            const body = await request.json();
            const message = body.message; const callback_query = body.callback_query;
            let tgBotToken = ''; let tgChatId = '';
            try { const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('tg_bot_token', 'tg_chat_id')").all(); results.forEach(r => { if(r.key === 'tg_bot_token') tgBotToken = r.value; if(r.key === 'tg_chat_id') tgChatId = r.value; }); } catch(e){}
            
            const tgSend = async (chatId, text, kb=null) => { const p = { chat_id: chatId, text, parse_mode: 'HTML' }; if (kb) p.reply_markup = kb; await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(p)}); };
            const tgEdit = async (chatId, msgId, text, kb=null) => { const p = { chat_id: chatId, message_id: msgId, text, parse_mode: 'HTML' }; if (kb) p.reply_markup = kb; await fetch(`https://api.telegram.org/bot${tgBotToken}/editMessageText`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(p)}); };

            let chatId, text, msgId;
            if (message) { chatId = message.chat.id.toString(); text = message.text || ''; msgId = message.message_id; } 
            else if (callback_query) { chatId = callback_query.message.chat.id.toString(); text = callback_query.data; msgId = callback_query.message.message_id; }
            if (chatId !== tgChatId) return new Response('OK', { status: 200 });

            const mainMenuText = `🖥 <b>Server Monitor Pro 探针管理</b>\n\n您可以使用命令快速设置系统：\n<code>/set_interval 10</code> - 上报间隔10秒\n<code>/set_sitetitle 新标题</code> - 更改大盘标题\n<code>/menu</code> - 调出本菜单`;
            const mainMenuKb = { inline_keyboard: [ [{text: '📋 探针节点列表', callback_data: 'cb_list_nodes'}], [{text: '⚙️ 系统设置快捷开关', callback_data: 'cb_settings'}] ] };
            
            if (callback_query) {
                if (text === 'cb_menu') await tgEdit(chatId, msgId, mainMenuText, mainMenuKb);
                else if (text === 'cb_list_nodes') {
                    const { results } = await db.prepare('SELECT id, name, last_updated FROM probe_servers WHERE is_hidden != "true"').all();
                    let kb = { inline_keyboard: [] };
                    for (const s of results) { kb.inline_keyboard.push([{text: `${s.name}`, callback_data: `cb_node_${s.id}`}]); }
                    kb.inline_keyboard.push([{text: '🔙 返回', callback_data: 'cb_menu'}]);
                    await tgEdit(chatId, msgId, '📋 <b>当前在线探针：</b>', kb);
                }
                else if (text.startsWith('cb_node_')) {
                    const id = text.split('_')[2]; const s = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
                    if (s) await tgEdit(chatId, msgId, `🖥 <b>探针详情:</b> ${escapeHtml(s.name)}\n\n系统: ${escapeHtml(s.os||'-')}\nIP类型: IPv4:${escapeHtml(s.ip_v4)} / IPv6:${escapeHtml(s.ip_v6)}\n运行时长: ${escapeHtml(s.uptime)}\n分组: ${escapeHtml(s.server_group)}`, {inline_keyboard: [[{text: '🔙 返回列表', callback_data: 'cb_list_nodes'}]]});
                }
                else if (text === 'cb_settings') {
                    let set = { is_public: 'true', show_price: 'true' }; try { const { results } = await db.prepare("SELECT key, value FROM probe_settings").all(); results.forEach(r => set[r.key]=r.value); } catch(e){}
                    const kb = { inline_keyboard: [
                        [{text: `${set.is_public === 'true' ? '✅' : '❌'} 公开大盘`, callback_data: 'cb_tog_is_public'}, {text: `${set.show_price === 'true' ? '✅' : '❌'} 显示价格`, callback_data: 'cb_tog_show_price'}],
                        [{text: '🔙 返回主菜单', callback_data: 'cb_menu'}]
                    ]};
                    await tgEdit(chatId, msgId, '⚙️ <b>点击切换探针前台展示状态</b>', kb);
                }
                else if (text.startsWith('cb_tog_')) {
                    const key = text.replace('cb_tog_', '');
                    let cur = 'true'; try { const r = await db.prepare('SELECT value FROM probe_settings WHERE key=?').bind(key).first(); if(r) cur = r.value; } catch(e){}
                    const next = cur === 'true' ? 'false' : 'true';
                    await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, next).run();
                    if (key === 'is_public') await notifyRealtimePublicPolicy(env, db, next === 'true', url.origin).catch(() => {});
                    await tgSend(chatId, `✅ 属性 ${key} 已成功切换！`);
                }
            }
            if (message) {
                const cmdParts = text.trim().split(/\s+/); const cmd = cmdParts[0].toLowerCase();
                if (cmd === '/start' || cmd === '/menu') await tgSend(chatId, mainMenuText, mainMenuKb);
                else if (cmd === '/set_interval' && cmdParts[1]) { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('report_interval', cmdParts[1]).run(); await tgSend(chatId, `✅ 上报间隔设为 ${cmdParts[1]} 秒`); }
                else if (cmd === '/set_sitetitle') { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind('site_title', text.replace(cmdParts[0], '').trim()).run(); await tgSend(chatId, '✅ 大盘标题已更新'); }
            }
            return new Response('OK', { status: 200 });
        } catch(e) { return new Response('Webhook Error', {status:200}); }
    }

    if (method === 'GET' && subPath === 'public') {
        const isAjax = url.searchParams.get('ajax') === '1';
        const cacheKey = new Request(`${url.origin}/api/probe/public?ajax=${isAjax ? '1' : '0'}`);
        const cached = await caches.default.match(cacheKey);
        if (cached) return cached;
        const settings = { theme: 'theme1', is_public: 'true', site_title: '⚡ Server Monitor Pro', show_price: 'true', show_expire: 'true', show_bw: 'true', show_tf: 'true', custom_css: '', custom_bg: '', custom_head: '', custom_script: '', report_interval: '5', enable_popup: 'false', popup_content: '', cached_nodes_data: '' };
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        const authHeader = request.headers.get("Authorization");
        const isLoggedIn = await verifyAuth(authHeader, request, db, env, context);
        if (settings.is_public !== 'true' && !isLoggedIn) return Response.json({ error: "Private Dashboard" }, { status: 401 });
        const servers = (await db.prepare('SELECT p.id, p.name, p.cpu, p.ram, p.disk, p.load_avg, p.uptime, p.last_updated, p.net_in_speed, p.net_out_speed, p.os, p.arch, p.virt, p.tcp_conn, p.udp_conn, p.country, p.ip_v4, p.ip_v6, p.server_group, p.price, p.expire_date, p.bandwidth, p.traffic_limit, p.ping_ct, p.ping_cu, p.ping_cm, p.ping_bd, p.monthly_rx, p.monthly_tx, p.net_rx, p.net_tx, p.cpu_info, p.ram_used, p.ram_total, p.disk_used, p.disk_total FROM probe_servers p INNER JOIN servers s ON s.ip = p.id WHERE p.is_hidden != "true"').all()).results;
        const publicKeys = new Set(['theme', 'is_public', 'site_title', 'show_price', 'show_expire', 'show_bw', 'show_tf', 'custom_css', 'custom_bg', 'custom_head', 'custom_script', 'report_interval', 'enable_popup', 'popup_content', 'cached_nodes_data', 'auto_reset_traffic', 'visits_total', 'visits_today', 'visits_date']);
        for (const key of Object.keys(settings)) if (!publicKeys.has(key)) delete settings[key];
        const realtime = env.REALTIME_URL ? null : await db.prepare("SELECT val FROM sys_config WHERE key = 'realtime_url'").first();
        const response = Response.json({ settings, servers, realtime_url: env.REALTIME_URL || realtime?.val || '' }, { headers: { 'Cache-Control': 'public, max-age=15, s-maxage=15' } });
        if (settings.is_public === 'true') context.waitUntil(caches.default.put(cacheKey, response.clone()));
        return response;
    }

    if (method === 'GET' && subPath === 'detail') {
        const id = url.searchParams.get('id');
        const server = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(id).first();
        if (!server || server.is_hidden === 'true') return Response.json({ error: "Not found" }, { status: 404 });
        const publicSetting = await db.prepare("SELECT value FROM probe_settings WHERE key = 'is_public'").first();
        if (publicSetting && publicSetting.value !== 'true' && !(await verifyAuth(request.headers.get('Authorization'), request, db, env, context))) return Response.json({ error: "Unauthorized" }, { status: 401 });
        return Response.json(server);
    }

    const probeUser = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
    if (!probeUser) return Response.json({error: "Unauthorized"}, {status: 401});
    if (subPath.startsWith('admin/') && probeUser !== (env.ADMIN_USERNAME || 'admin')) return Response.json({error: "Forbidden"}, {status: 403});

    // 🌟 GitHub 云端拉取三网节点库
    if (method === 'POST' && subPath === 'admin/pull_github') {
        try {
            const res = await fetch('https://raw.githubusercontent.com/a63414262/CF-Server-Monitor-Pro/refs/heads/main/nodes.json');
            if (res.ok) {
                const dataText = await res.text();
                await db.prepare("INSERT INTO probe_settings (key, value) VALUES ('cached_nodes_data', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").bind(dataText).run();
                return Response.json({ success: true });
            }
            return Response.json({ error: 'Fetch failed' }, { status: 400 });
        } catch (e) { return Response.json({ error: e.message }, { status: 400 }); }
    }

    if (method === 'GET' && subPath === 'admin/data') {
        const settings = {};
        try { const { results } = await db.prepare('SELECT * FROM probe_settings').all(); if (results) results.forEach(r => settings[r.key] = r.value); } catch(e){}
        const servers = (await db.prepare('SELECT id, name, last_updated, server_group, price, expire_date, bandwidth, traffic_limit, agent_os, is_hidden, reset_day FROM probe_servers').all()).results;
        return Response.json({ settings, servers });
    }
    
    if (method === 'POST' && subPath === 'admin/settings') {
        const { settings } = await readJsonBody(request, 64 * 1024);
        if (!settings || typeof settings !== 'object' || Array.isArray(settings) || Object.keys(settings).length > 80) return Response.json({ error: 'Invalid settings' }, { status: 400 });
        const frequencyKeys = ['realtime_admin_interval', 'realtime_public_interval', 'realtime_idle_interval'];
        let frequencySettings = settings;
        if (frequencyKeys.some(key => Object.prototype.hasOwnProperty.call(settings, key))) {
            const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('realtime_admin_interval', 'realtime_public_interval', 'realtime_idle_interval')").all();
            frequencySettings = { ...Object.fromEntries((results || []).map(row => [row.key, row.value])), ...settings };
            if (!realtimeFrequencyPolicy(frequencySettings)) return Response.json({ error: 'Invalid realtime frequency policy' }, { status: 400 });
        }
        for (const [k, v] of Object.entries(settings)) { await db.prepare('INSERT INTO probe_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(k, v).run(); }
        if (Object.prototype.hasOwnProperty.call(settings, 'is_public')) await notifyRealtimePublicPolicy(env, db, settings.is_public === 'true', url.origin).catch(() => {});
        if (frequencyKeys.some(key => Object.prototype.hasOwnProperty.call(settings, key))) await notifyRealtimeFrequencyPolicy(env, db, frequencySettings, url.origin).catch(() => {});
        if (settings.tg_bot_token) {
            try {
               await fetch(`https://api.telegram.org/bot${settings.tg_bot_token}/setWebhook`, {
                  method: 'POST', headers: {'Content-Type': 'application/json'},
                   body: JSON.stringify({ url: `${url.origin}/api/probe/tg_webhook`, ...(env.TG_WEBHOOK_SECRET ? { secret_token: env.TG_WEBHOOK_SECRET } : {}) })
               });
            } catch(e) {}
        }
        return Response.json({ success: true });
    }

    if (method === 'PUT' && subPath === 'admin/server') {
        const data = await readJsonBody(request, 16 * 1024);
        await db.prepare(`UPDATE probe_servers SET name=?, server_group=?, price=?, expire_date=?, bandwidth=?, traffic_limit=?, agent_os=?, is_hidden=?, reset_day=? WHERE id=?`).bind(data.name || 'Unnamed', data.server_group || '默认分组', data.price || '', data.expire_date || '', data.bandwidth || '', data.traffic_limit || '', data.agent_os || 'debian', data.is_hidden || 'false', data.reset_day || '1', data.id).run();
        return Response.json({ success: true });
    }
    
    if (method === 'DELETE' && subPath === 'admin/server') {
        const id = url.searchParams.get('id');
        await db.prepare('DELETE FROM probe_servers WHERE id = ?').bind(id).run();
        return Response.json({ success: true });
    }

    return Response.json({error: "Not Found"}, {status: 404});
}

// ==============================================
// 住宅IP代理：FRP 控制器已融合进本 Worker
// (引擎来自 Free-Residential-IP-Proxy-Controller-Sec，不再依赖外部部署)。
// 数据表：frp_global_config / frp_server_config / frp_servers（本 D1）。
// 凭据模型：Agent 面 Basic 鉴权的用户名与面板管理员一致（ADMIN_USERNAME），
// 口令优先使用独立的 FRP_AGENT_PASSWORD（设置后管理员密码不下发到 VPS）；
// 未设置时回退 ADMIN_PASSWORD，即 FRP 里 WEB_USER / WEB_PASS 的统一模型。
// VPS 上 c2.json 的 web_pass 就是生效的 Agent 口令；数据面 SOCKS5 凭据
// 仍为 PROXY_USER / PROXY_PASS（与 FRP 一致）。
// ==============================================
function frpDefaultPort(env) {
    const p = Number.parseInt(env && env.PROXY_PORT, 10);
    return Number.isInteger(p) && p >= 1 && p <= 65535 ? p : 7920;
}
const frpCleanBootId = (b) => String(b || '').replace(/[\|"]/g, '').trim().slice(0, 64);
const frpNodeKeyOf = (ip, bootId) => {
    const b = frpCleanBootId(bootId);
    return b ? `${String(ip).trim()}|${b}` : String(ip).trim();
};
const frpSplitNodeKey = (nk) => {
    const s = String(nk || '');
    const i = s.indexOf('|');
    return i === -1 ? [s, ''] : [s.slice(0, i), s.slice(i + 1)];
};
function frpReqNodeKey(data) {
    const node = String((data && data.node) || '').trim();
    if (node) return node;
    const ip = String((data && data.ip) || '').trim();
    return ip ? frpNodeKeyOf(ip, data.boot_id) : '';
}
function frpSlotCountry(slotMap, fallback = 'JP') {
    const raw = slotMap && (slotMap['0'] ?? slotMap[0] ?? slotMap.country);
    return String(raw || fallback).toUpperCase();
}

// 全局配置 30 秒隔离缓存（写路径主动失效），压低 config 热路径的 D1 读。
let frpGlobalCfgCache = { at: 0, data: null };
async function frpReadGlobalConfig(db, env) {
    if (frpGlobalCfgCache.data && Date.now() - frpGlobalCfgCache.at < 30000) return frpGlobalCfgCache.data;
    const { results } = await db.prepare(`SELECT key, value FROM frp_global_config WHERE key IN ('slot_map', 'force_switch', 'proxy_port', 'mode', 'manual_node_ip', 'youtube_check', 'config_fetch_interval', 'heartbeat_interval', 'frontend_poll_interval')`).all();
    const dft = frpDefaultPort(env);
    let slot_map = { 0: 'JP' };
    let force_switch = {};
    let proxy_port = dft;
    let mode = 'auto';
    let manual_node_ip = '';
    let youtube_check = false;
    let config_fetch_interval = 15;
    let heartbeat_interval = 30;
    let frontend_poll_interval = 5;
    if (results) {
        for (let row of results) {
            if (row.key === 'slot_map') { try { slot_map = JSON.parse(row.value); } catch (e) {} }
            if (row.key === 'force_switch') { try { force_switch = JSON.parse(row.value); } catch (e) {} }
            if (row.key === 'proxy_port') proxy_port = parseInt(row.value, 10) || dft;
            if (row.key === 'mode') mode = row.value === 'manual' ? 'manual' : 'auto';
            if (row.key === 'manual_node_ip') manual_node_ip = row.value;
            if (row.key === 'youtube_check') youtube_check = row.value === 'true';
            if (row.key === 'config_fetch_interval') config_fetch_interval = Math.max(5, Math.min(3600, parseInt(row.value, 10) || 15));
            if (row.key === 'heartbeat_interval') heartbeat_interval = Math.max(10, Math.min(3600, parseInt(row.value, 10) || 30));
            if (row.key === 'frontend_poll_interval') frontend_poll_interval = Math.max(5, Math.min(300, parseInt(row.value, 10) || 5));
        }
    }
    const data = { slot_map, force_switch, proxy_port, mode, manual_node_ip, youtube_check, config_fetch_interval, heartbeat_interval, frontend_poll_interval };
    frpGlobalCfgCache = { at: Date.now(), data };
    return data;
}

async function frpUpsertGlobal(db, key, value) {
    await db.prepare(`INSERT INTO frp_global_config (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value`).bind(key, String(value)).run();
    frpGlobalCfgCache = { at: 0, data: null };
}

// 确保某节点有专属配置行（不存在时以全局配置为默认值创建）。
// 先读后写：Agent 每 15 秒拉一次配置，命中已有行时只走读，不产生写操作。
async function frpEnsureServerConfig(db, env, ip, bootId = '') {
    const nk = frpNodeKeyOf(ip, bootId);
    const existing = await db.prepare(`SELECT node_key FROM frp_server_config WHERE node_key = ?1`).bind(nk).first();
    if (existing) return nk;
    const g = await frpReadGlobalConfig(db, env);
    const b = frpCleanBootId(bootId);
    await db.prepare(`INSERT OR IGNORE INTO frp_server_config (node_key, ip, boot_id, slot_map, mode, manual_node_ip, youtube_check, force_switch, pending_uninstall) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)`)
        .bind(nk, String(ip).trim(), b, JSON.stringify(g.slot_map), g.mode, g.manual_node_ip, String(g.youtube_check), JSON.stringify(g.force_switch)).run();
    return nk;
}

// 清理失联节点（待远程卸载的保留，避免卸载指令丢失）
async function frpCleanupStale(db) {
    const cutoff = Date.now() - 120000;
    await db.prepare(`DELETE FROM frp_servers WHERE last_seen < ?1 AND NOT EXISTS (SELECT 1 FROM frp_server_config sc WHERE sc.node_key = frp_servers.node_key AND sc.pending_uninstall = 1)`).bind(cutoff).run();
}

// FRP 节点行 -> KUI 面板行：details 从 {slot,node_ip,...} 适配为
// {tunnel, active, country, port, node_ip, exit_ip, ready, connected_time}；
// FRP 的 log 字段映射为面板的 logs。
function adaptFrpNodeRow(row) {
    let details = [];
    try { details = JSON.parse(row.details || '[]'); } catch (e) { details = []; }
    const adapted = (Array.isArray(details) ? details : []).map(d => ({
        tunnel: 'tun_main',
        active: !!d.node_ip,
        country: String(d.country || '').toUpperCase().slice(0, 2),
        port: Number(d.port) || 0,
        node_ip: String(d.node_ip || ''),
        exit_ip: String(d.node_ip || ''),
        ready: !!d.node_ip,
        connected_time: Math.max(0, Math.min(Number(d.connected_time) || 0, 31536000)),
    }));
    return { ip: row.ip, details: JSON.stringify(adapted), last_seen: Number(row.last_seen) || 0, logs: String(row.log || '').slice(0, 16 * 1024), cfg: row.cfg || null };
}

async function frpLocalNodes(db) {
    const { results } = await db.prepare(`
        SELECT s.*,
               sc.slot_map AS c_slot_map, sc.mode AS c_mode, sc.manual_node_ip AS c_manual_node_ip,
               sc.youtube_check AS c_youtube_check, sc.pending_uninstall AS c_pending_uninstall
        FROM frp_servers s LEFT JOIN frp_server_config sc ON s.node_key = sc.node_key
        ORDER BY s.last_seen DESC`).all();
    return (results || []).map(server => {
        let candidates = [];
        try { candidates = JSON.parse(server.candidates || '[]'); } catch (e) {}
        let country = 'JP';
        try { const m = JSON.parse(server.c_slot_map || '{"0":"JP"}'); country = m[0] || m['0'] || 'JP'; } catch (e) {}
        const adapted = adaptFrpNodeRow(server);
        adapted.candidates = candidates;
        adapted.cfg = {
            country,
            mode: server.c_mode === 'manual' ? 'manual' : 'auto',
            manual_node_ip: server.c_manual_node_ip || '',
            youtube_check: server.c_youtube_check === 'true',
            pending_uninstall: server.c_pending_uninstall === 1,
        };
        return adapted;
    });
}

async function testispLookup(subPath) {
    let targetIp;
    try { targetIp = decodeURIComponent(subPath.replace('testisp-lookup/', '')); }
    catch (error) { return new Response(JSON.stringify({ error: 'Invalid IP' }), { status: 400, headers: { 'Content-Type': 'application/json' } }); }
    if (!/^[0-9a-fA-F:.]+$/.test(targetIp)) return new Response(JSON.stringify({ error: 'Invalid IP' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    try {
        const resp = await fetch(`https://testisp.info/api/check?ip=${encodeURIComponent(targetIp)}`, {
            headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json' }
        });
        const text = await resp.text();
        return new Response(text, { status: resp.status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' } });
    } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

// VPS 安装脚本（对应 FRP 的 /agent）：凭据由服务端写进本机 c2.json（600），
// 下发的引擎代码不含任何口令。鉴权（agent_token）在路由层完成。
function frpInstallerScript(request, env) {
    const agentPassword = env.FRP_AGENT_PASSWORD || env.ADMIN_PASSWORD;
    if (!agentPassword || !env.PROXY_USER || !env.PROXY_PASS) {
        return Response.json({ error: '住宅模块未就绪：请先设置 FRP_AGENT_PASSWORD（或 ADMIN_PASSWORD）/ PROXY_USER / PROXY_PASS' }, { status: 503 });
    }
    const domain = new URL(request.url).origin;
    const c2conf = JSON.stringify({ web_user: env.ADMIN_USERNAME || 'admin', web_pass: agentPassword, proxy_user: env.PROXY_USER, proxy_pass: env.PROXY_PASS, c2_url: domain });
    const agentScript = `#!/usr/bin/env bash
echo "=========================================================="
echo "    免费住宅IP智能调度系统 (KUI 融合版) 直连部署"
echo "=========================================================="
set -e

if [ "$(id -u)" -ne 0 ]; then echo "[-] 请以 root 身份运行此安装脚本。" >&2; exit 1; fi
if ! command -v systemctl >/dev/null 2>&1; then echo "[-] 本系统没有 systemd，无法安装守护进程。" >&2; exit 1; fi

if command -v crontab >/dev/null 2>&1; then
  crontab -l 2>/dev/null | grep -v "/opt/proxy_lite/heartbeat.sh" | crontab - || true
fi
rm -f /opt/proxy_lite/heartbeat.sh

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/4] 写入 C2 凭证配置 (仅 root 可读)..."
cat > /opt/proxy_lite/c2.json << 'C2JSON_EOF'
${c2conf}
C2JSON_EOF
chmod 600 /opt/proxy_lite/c2.json
C2_URL="${domain}"
C2_AUTH="$(python3 -c "import json;d=json.load(open('/opt/proxy_lite/c2.json'));print(d['web_user']+':'+d['web_pass'])")"

echo "[2/4] 从 KUI 拉取智能隔离引擎 (鉴权下载)..."
curl -sfL -u "$C2_AUTH" "$C2_URL/api/proxy/scripts/lite_manager.py" -o lite_manager.py
curl -sfL -u "$C2_AUTH" "$C2_URL/api/proxy/scripts/proxy_server.py" -o proxy_server.py
chmod 600 lite_manager.py proxy_server.py

echo "[3/4] 配置系统群组守护..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Residential Proxy Core Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/proxy-lite.conf << 'EOF'
[Journal]
SystemMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=7day
EOF
systemctl restart systemd-journald || true
journalctl --vacuum-size=50M --vacuum-time=7d >/dev/null 2>&1 || true
systemctl restart proxy-lite.service

echo "[4/4] 校验引擎启动..."
sleep 3
systemctl is-active --quiet proxy-lite.service && echo "[+] KUI 融合版住宅引擎部署成功，守护进程运行中。" || echo "[!] 服务未正常启动，请检查 journalctl -u proxy-lite.service"
`;
    return new Response(agentScript, { headers: { 'Content-Type': 'text/plain;charset=UTF-8', 'Cache-Control': 'no-store' } });
}

async function proxyModule(method, subPath, request, env) {
    const db = env.DB;
    const url = new URL(request.url);
    try {
        // ================= Agent 面（Basic 鉴权已在路由层完成） =================
        // Agent 拉配置：?ip=本机公网IP[&boot=启动标识] 时下发该机器专属策略；
        // 否则走全局默认（兼容无 boot 的老行为）
        if (subPath === 'agent-config' && method === 'GET') {
            const g = await frpReadGlobalConfig(db, env);
            const qip = (url.searchParams.get('ip') || '').trim();
            if (qip) {
                const qboot = frpCleanBootId(url.searchParams.get('boot'));
                const qkey = await frpEnsureServerConfig(db, env, qip, qboot);
                const sc = await db.prepare(`SELECT * FROM frp_server_config WHERE node_key = ?1`).bind(qkey).first();
                let slot_map = g.slot_map, force_switch = g.force_switch, mode = g.mode,
                    manual_node_ip = g.manual_node_ip, youtube_check = g.youtube_check, uninstall = false;
                if (sc) {
                    try { slot_map = JSON.parse(sc.slot_map); } catch (e) {}
                    try { force_switch = JSON.parse(sc.force_switch); } catch (e) {}
                    mode = sc.mode === 'manual' ? 'manual' : 'auto';
                    manual_node_ip = sc.manual_node_ip || '';
                    youtube_check = sc.youtube_check === 'true';
                    uninstall = sc.pending_uninstall === 1;
                }
                return Response.json({ slot_map, force_switch, proxy_port: g.proxy_port, mode, manual_node_ip, youtube_check,
                    config_fetch_interval: g.config_fetch_interval, heartbeat_interval: g.heartbeat_interval,
                    frontend_poll_interval: g.frontend_poll_interval, uninstall });
            }
            return Response.json({ ...g, uninstall: false });
        }

        // Agent 心跳上报
        if (subPath === 'report' && method === 'POST') {
            const data = await readJsonBody(request.clone(), MAX_PROXY_REPORT_BYTES).catch(() => null);
            if (!data) return new Response('invalid body', { status: 400 });
            const rip = String(data.ip || '').trim();
            if (!rip) return new Response('missing ip', { status: 400 });
            const rboot = frpCleanBootId(data.boot_id);
            const rkey = frpNodeKeyOf(rip, rboot);
            await db.prepare(`
                INSERT INTO frp_servers (ip, boot_id, node_key, details, log, candidates, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(node_key) DO UPDATE SET ip = excluded.ip, boot_id = excluded.boot_id, details = excluded.details, log = excluded.log, candidates = excluded.candidates, last_seen = excluded.last_seen
            `).bind(rip, rboot, rkey, JSON.stringify(data.details || []), String(data.log || '').slice(-12000), JSON.stringify(data.candidates || []).slice(0, 100000), Date.now()).run();
            try { await frpEnsureServerConfig(db, env, rip, rboot); } catch (e) {}
            // 同一出口 IP 下：已失联旧节点的残留卸载标记自动清除（重装场景）
            try {
                await db.prepare(`
                    UPDATE frp_server_config SET pending_uninstall = 0
                    WHERE ip = ?1 AND node_key != ?2 AND pending_uninstall = 1
                      AND NOT EXISTS (SELECT 1 FROM frp_servers s WHERE s.node_key = frp_server_config.node_key AND s.last_seen > ?3)
                `).bind(rip, rkey, Date.now() - 120000).run();
            } catch (e) {}
            return new Response('OK', { status: 200 });
        }

        // Agent 远程卸载完成后的注销回调
        if (subPath === 'server/uninstalled' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 16 * 1024).catch(() => ({}));
            const nkey = frpReqNodeKey(data);
            if (!nkey) return new Response('missing node', { status: 400 });
            await db.prepare(`DELETE FROM frp_servers WHERE node_key = ?1`).bind(nkey).run();
            await db.prepare(`DELETE FROM frp_server_config WHERE node_key = ?1`).bind(nkey).run();
            return new Response('OK');
        }

        // 引擎脚本下发（lite_manager 的监听端口按当前全局配置回填）
        if (subPath === 'scripts/lite_manager.py' || subPath === 'scripts/proxy_server.py') {
            const assetPath = subPath === 'scripts/lite_manager.py' ? '/vps/lite_manager.py' : '/vps/proxy_server.py';
            const assetRes = await env.ASSETS.fetch(new URL(assetPath, url.origin));
            if (!assetRes.ok) return new Response('script unavailable', { status: 503 });
            let code = await assetRes.text();
            if (subPath === 'scripts/lite_manager.py') {
                const g = await frpReadGlobalConfig(db, env);
                code = code.split('__BAKED_PROXY_PORT__').join(String(g.proxy_port));
            }
            return new Response(code, { headers: { 'Content-Type': 'text/x-python; charset=utf-8', 'Cache-Control': 'no-store' } });
        }

        // VPS 安装脚本（agent_token 鉴权在路由层完成）
        if (subPath === 'installer' && method === 'GET') {
            return frpInstallerScript(request, env);
        }

        // ================= 面板面 =================
        if (subPath === 'countries' && method === 'GET') {
            try {
                const requestedCountries = [
                    "AE","AR","AT","AU","BE","BD","BG","BH","BR","CA","CH","CL","CN","CO",
                    "CR","CY","CZ","DE","DK","EE","EG","ES","FI","FR","GB","GR","HK","HR",
                    "HU","ID","IE","IL","IN","IQ","IR","IS","IT","JM","JO","JP","KE","KH",
                    "KR","KW","KZ","LA","LB","LK","LT","LU","LV","MA","MD","MM","MN","MO",
                    "MX","MY","NG","NL","NO","NP","NZ","OM","PA","PE","PH","PK","PL","PT",
                    "QA","RO","RS","RU","SA","SE","SG","SI","SK","TH","TR","TW","UA","US",
                    "UY","UZ","VE","VN","ZA"
                ];
                const response = await fetch("https://www.vpngate.net/api/iphone/", { signal: AbortSignal.timeout(8000) });
                const text = await response.text();
                const lines = text.split('\n');
                const countries = new Set(requestedCountries);
                for (let i = 2; i < lines.length; i++) {
                    const parts = lines[i].split(',');
                    if (parts.length > 6) {
                        const country = parts[6];
                        if (country && country.length === 2 && country !== "xx" && country !== "--") countries.add(country);
                    }
                }
                return Response.json(Array.from(countries));
            } catch (err) {
                return Response.json(["JP", "KR", "US", "GB", "TW"]);
            }
        }

        if (subPath === 'proxies' && method === 'GET') {
            await frpCleanupStale(db);
            const { results } = await db.prepare(`SELECT ip, details FROM frp_servers`).all();
            const proxyList = [];
            if (results) {
                for (let server of results) {
                    let nodes = [];
                    try { nodes = JSON.parse(server.details || '[]'); } catch (e) {}
                    for (let node of nodes) {
                        proxyList.push(`socks5://${env.PROXY_USER || ''}:${env.PROXY_PASS || ''}@${server.ip}:${node.port}#${node.country}_Port${node.port}_${node.node_ip || 'IP'}`);
                    }
                }
            }
            return new Response(proxyList.join('\n'), { headers: { 'Content-Type': 'text/plain;charset=UTF-8' } });
        }

        if ((subPath === 'nodes' || subPath === 'pool') && method === 'GET') {
            await frpCleanupStale(db);
            const nodes = await frpLocalNodes(db);
            if (subPath === 'pool') return Response.json(nodes.map(n => ({ ip: n.ip, details: n.details, last_seen: n.last_seen })));
            return Response.json(nodes);
        }

        if (subPath.startsWith('testisp-lookup/')) return await testispLookup(subPath);

        if (subPath === 'config' && method === 'GET') {
            const g = await frpReadGlobalConfig(db, env);
            const port = g.proxy_port;
            const requestIp = url.searchParams.get('ip');
            if (requestIp) {
                const sc = await db.prepare(`
                    SELECT sc.* FROM frp_server_config sc
                    LEFT JOIN frp_servers s ON s.node_key = sc.node_key
                    WHERE sc.ip = ?1 ORDER BY s.last_seen DESC LIMIT 1`).bind(requestIp).first();
                let country = frpSlotCountry(g.slot_map);
                let mode = g.mode, manualNodeIp = g.manual_node_ip, youtubeCheck = g.youtube_check;
                if (sc) {
                    try { country = frpSlotCountry(JSON.parse(sc.slot_map || '{}'), country); } catch (e) {}
                    mode = sc.mode === 'manual' ? 'manual' : 'auto';
                    manualNodeIp = sc.manual_node_ip || '';
                    youtubeCheck = sc.youtube_check === 'true';
                }
                return Response.json({ ip: requestIp, '0': country, country, port, slot_map: { '0': country }, mode, manual_node_ip: manualNodeIp, youtube_check: youtubeCheck, proxy: { enabled: true, port, user: '', pass: '', country } });
            }
            const country = frpSlotCountry(g.slot_map);
            return Response.json({ ...(g.slot_map || {}), '0': country, country, port, slot_map: g.slot_map || {}, mode: g.mode, manual_node_ip: g.manual_node_ip, youtube_check: g.youtube_check, proxy: { enabled: true, port, user: '', pass: '', country } });
        }

        if (subPath === 'config' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 16 * 1024).catch(() => ({}));
            const country = String(data['0'] || data.country || 'JP').toUpperCase().trim() || 'JP';
            const port = Number.parseInt(data.port, 10);
            // 强制换 IP：面板 pcSwitchIP 走 config+switch_trigger；Vue 走 /switch
            if (data.switch_trigger) {
                if (data.ip) {
                    await frpEnsureServerConfig(db, env, data.ip, '');
                    await db.prepare(`UPDATE frp_server_config SET force_switch = ?2 WHERE ip = ?1`).bind(String(data.ip), JSON.stringify({ '0': Date.now() })).run();
                } else {
                    const g = await frpReadGlobalConfig(db, env);
                    const fs = { ...(g.force_switch || {}), '0': Date.now() };
                    await frpUpsertGlobal(db, 'force_switch', JSON.stringify(fs));
                }
                return Response.json({ success: true, switch_trigger: data.switch_trigger });
            }
            if (data.ip) {
                await frpEnsureServerConfig(db, env, data.ip, '');
                await db.prepare(`UPDATE frp_server_config SET slot_map = ?2, mode = 'auto' WHERE ip = ?1`)
                    .bind(String(data.ip), JSON.stringify({ '0': country })).run();
            }
            if (Number.isInteger(port) && port >= 1 && port <= 65535) {
                await frpUpsertGlobal(db, 'proxy_port', String(port));
                await frpUpsertGlobal(db, 'slot_map', JSON.stringify({ '0': country }));
            }
            // enabled/mesh 是旧本地控制器的概念，FRP 模型无对应开关：不做破坏性操作，响应中明示。
            return Response.json({ success: true, slot_map: { '0': country }, proxy: { enabled: data.enabled !== false, port: Number.isInteger(port) ? port : frpDefaultPort(env), country }, ...(data.enabled === false ? { note: 'FRP 无单节点开关，enabled=false 已忽略；停用住宅出口请把出口模式切回原生' } : {}) });
        }

        if (subPath === 'switch' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 8 * 1024).catch(() => ({}));
            if (data.ip) {
                await frpEnsureServerConfig(db, env, data.ip, '');
                await db.prepare(`UPDATE frp_server_config SET force_switch = ?2 WHERE ip = ?1`).bind(String(data.ip), JSON.stringify({ '0': Date.now() })).run();
            } else {
                const g = await frpReadGlobalConfig(db, env);
                const fs = { ...(g.force_switch || {}), '0': Date.now() };
                await frpUpsertGlobal(db, 'force_switch', JSON.stringify(fs));
            }
            return Response.json({ success: true, switch_trigger: Date.now() });
        }

        // ---------- 单节点策略 API（与 FRP 原生接口同语义，node = ip 或 ip|boot_id） ----------
        if (subPath === 'server/config' && method === 'GET') {
            const qkey = ((url.searchParams.get('node') || url.searchParams.get('ip') || '').trim());
            if (!qkey) return new Response('missing node', { status: 400 });
            const [qIp, qBoot] = frpSplitNodeKey(qkey);
            await frpEnsureServerConfig(db, env, qIp, qBoot);
            const sc = await db.prepare(`SELECT * FROM frp_server_config WHERE node_key = ?1`).bind(qkey).first();
            let country = 'JP';
            try { const m = JSON.parse(sc.slot_map || '{"0":"JP"}'); country = (m[0] || m['0'] || 'JP'); } catch (e) {}
            return Response.json({ node: qkey, ip: qIp, country, mode: sc.mode === 'manual' ? 'manual' : 'auto',
                manual_node_ip: sc.manual_node_ip || '', youtube_check: sc.youtube_check === 'true',
                pending_uninstall: sc.pending_uninstall === 1 });
        }

        if (subPath === 'server/config' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 16 * 1024).catch(() => ({}));
            const nkey = frpReqNodeKey(data);
            const country = (String(data.country || 'JP').toUpperCase().trim() || 'JP').slice(0, 4);
            const mode = data.mode === 'manual' ? 'manual' : 'auto';
            const manualNodeIp = String(data.manual_node_ip || '').trim();
            const youtubeCheck = data.youtube_check === true;
            if (!nkey) return new Response('missing node', { status: 400 });
            if (mode === 'manual' && !manualNodeIp) return new Response('manual mode requires a node ip', { status: 400 });
            const [nIp, nBoot] = frpSplitNodeKey(nkey);
            await frpEnsureServerConfig(db, env, nIp, nBoot);
            await db.prepare(`UPDATE frp_server_config SET slot_map = ?2, mode = ?3, manual_node_ip = ?4, youtube_check = ?5 WHERE node_key = ?1`)
                .bind(nkey, JSON.stringify({ 0: country }), mode, manualNodeIp, String(youtubeCheck)).run();
            return new Response('OK');
        }

        if (subPath === 'server/switch' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 8 * 1024).catch(() => ({}));
            const nkey = frpReqNodeKey(data);
            if (!nkey) return new Response('missing node', { status: 400 });
            const [nIp, nBoot] = frpSplitNodeKey(nkey);
            await frpEnsureServerConfig(db, env, nIp, nBoot);
            const sc = await db.prepare(`SELECT force_switch FROM frp_server_config WHERE node_key = ?1`).bind(nkey).first();
            let fs = {};
            try { fs = JSON.parse((sc && sc.force_switch) || '{}'); } catch (e) {}
            fs['0'] = Date.now();
            await db.prepare(`UPDATE frp_server_config SET force_switch = ?2 WHERE node_key = ?1`).bind(nkey, JSON.stringify(fs)).run();
            return new Response('OK');
        }

        // 删除节点：uninstall=下发远程卸载指令；force=仅删除记录
        if (subPath === 'server/remove' && method === 'POST') {
            const data = await readJsonBody(request.clone(), 8 * 1024).catch(() => ({}));
            const nkey = frpReqNodeKey(data);
            const mode = data.mode === 'force' ? 'force' : 'uninstall';
            if (!nkey) return new Response('missing node', { status: 400 });
            if (mode === 'force') {
                await db.prepare(`DELETE FROM frp_servers WHERE node_key = ?1`).bind(nkey).run();
                await db.prepare(`DELETE FROM frp_server_config WHERE node_key = ?1`).bind(nkey).run();
            } else {
                const [nIp, nBoot] = frpSplitNodeKey(nkey);
                await frpEnsureServerConfig(db, env, nIp, nBoot);
                await db.prepare(`UPDATE frp_server_config SET pending_uninstall = 1 WHERE node_key = ?1`).bind(nkey).run();
            }
            return new Response('OK');
        }

        return new Response('Not Found', { status: 404 });
    } catch (e) {
        return Response.json({ success: false, error: '住宅模块处理失败: ' + (e.message || String(e)) }, { status: 500 });
    }
}

async function checkOfflineServers(env) {
    const db = env.DB; const nowMs = Date.now();
    await ensureDbSchema(db);
    const realtime = await getRealtimeUrl(env, db);
    const offlineThreshold = realtime ? 1200000 : 360000;
    const { results } = await db.prepare(`SELECT ip, name, last_report FROM servers WHERE last_report < ? AND alert_sent = 0`).bind(nowMs - offlineThreshold).all();
    if (!results || !results.length) return 0;
    let tgBotToken = env.TG_BOT_TOKEN; let tgChatId = env.TG_CHAT_ID;
    try { const { results: settings } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('tg_bot_token', 'tg_chat_id')").all(); settings.forEach(r => { if(r.key === 'tg_bot_token') tgBotToken = r.value; if(r.key === 'tg_chat_id') tgChatId = r.value; }); } catch(e){}
    const updates = [];
    for (const vps of results) {
        let delivered = !tgBotToken || !tgChatId;
        if (tgBotToken && tgChatId) {
            const text = `⚠️ [KUI 节点失联告警]\n\n节点别名: ${vps.name}\n公网IP: ${vps.ip}\n最后在线: ${new Date(vps.last_report).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`;
            try { const response = await fetch(`https://api.telegram.org/bot${tgBotToken}/sendMessage`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: tgChatId, text }) }); const result = await response.json().catch(()=>({ok:false})); delivered = response.ok && result.ok === true; }
            catch (error) { console.error(`[cron] Telegram alert failed for ${vps.ip}:`, error); }
        }
        if (delivered) updates.push(db.prepare("UPDATE servers SET alert_sent = 1 WHERE ip = ?").bind(vps.ip));
    }
    if (updates.length) await chunkBatch(db, updates);
    return results.length;
}

// ==============================================
// KUI 主体接口路由
// ==============================================
export async function onRequest(context) {
    const { request, env, params } = context;
    const method = request.method;
    const action = params.path ? params.path[0] : ''; 
    const db = env.DB; 

    // 防御：未绑定 D1 数据库时直接返回清晰错误，避免 Cloudflare 1101 (Worker threw exception)
    if (!env || !env.DB) {
        return new Response(JSON.stringify({ error: "D1 binding 'DB' is not configured in Cloudflare Pages. Please bind a D1 database (variable name DB) and redeploy." }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    if (action === "probe") {
        await ensureDbSchema(db);
        return await handleProbeAPI(request, env, context, params.path.slice(1));
    }

    if (action === "ui_ping" && method === "POST") {
        if (!(await verifyAuth(request.headers.get("Authorization"), request, db, env, context))) return new Response("Unauthorized", { status: 401 });
        const now = Date.now();
        const current = await db.prepare("SELECT ts FROM sys_config WHERE key = 'ui_active'").first();
        if (!current || now - current.ts > 45000) await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('ui_active', '1', ?)").bind(now).run();
        return Response.json({ success: true });
    }

    if (action === "cron_check" && method === "POST") {
        if (!env.CRON_SECRET || request.headers.get('Authorization') !== `Bearer ${env.CRON_SECRET}`) return new Response('Unauthorized', { status: 401 });
        await ensureDbSchema(db);
        return Response.json({ success: true, alerted: await checkOfflineServers(env) });
    }

    if (action === "agent_update" && method === "GET") {
        const ip = new URL(request.url).searchParams.get('ip');
        if (!(await verifyAgent(request.headers.get('Authorization'), ip, db, env))) return new Response('Unauthorized', { status: 401 });
        if (!env.ASSETS) return Response.json({ error: 'ASSETS binding is unavailable' }, { status: 503 });
        const component = new URL(request.url).searchParams.get('component') || 'agent';
        // 住宅引擎脚本（lite_manager.py / proxy_server.py）由 /api/proxy/scripts/* 凭
        // Basic 鉴权下发，不走本通道；本通道只发 KUI 自身的组件。
        const assets = { agent: '/vps/agent.py', 'realtime-client': '/vps/realtime_client.py', 'proxy-installer': '/vps/residential-proxy.sh', 'full-installer': '/vps/kui.sh' };
        if (!assets[component]) return Response.json({ error: 'Unknown agent component' }, { status: 400 });
        const assetUrl = new URL(assets[component], request.url);
        const asset = await env.ASSETS.fetch(assetUrl);
        if (!asset.ok) return new Response('Agent asset not found', { status: 404 });
        const source = await asset.arrayBuffer();
        const digest = await crypto.subtle.digest('SHA-256', source);
        const sha256 = Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
        const server = await db.prepare('SELECT agent_token FROM servers WHERE ip = ?').bind(ip).first();
        if (!server?.agent_token) return new Response('Agent token unavailable', { status: 503 });
        const manifest = updateManifest(component, sha256, source.byteLength);
        const mac = await hmacHex(server.agent_token, manifest);
        const contentType = component.endsWith('installer') ? 'text/x-shellscript; charset=utf-8' : 'text/x-python; charset=utf-8';
        return new Response(source, { headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store', 'X-Agent-SHA256': sha256, 'X-Agent-Manifest-Version': '1', 'X-Agent-Length': String(source.byteLength), 'X-Agent-MAC': mac, 'X-Proxy-Controller-Mode': 'merged' } });
    }

    // 🌟 Agent 统一探针与管理上报接口
    if (action === "report" && method === "POST") {
     try {
        await ensureDbSchema(db);
        const data = validateTrafficReport(await readJsonBody(request, MAX_REPORT_BYTES));
        const nowMs = Date.now();
        const vpsIp = data.ip;
        const authHeader = request.headers.get("Authorization");
        if (!(await verifyAgent(authHeader, vpsIp, db, env))) return new Response("Unauthorized", { status: 401 });
        if (!data.report_id) return Response.json({ error: "report_id is required" }, { status: 400 });
        // [D1 优化] 幂等判重改用 probe_servers.last_report_id（只记最近一笔；
        // Agent 只会重试待确认的那一笔，足够防重复计费），彻底停用
        // report_receipts 表（原来每笔上报要 1 读 + 2 写）。
        // 一次 LEFT JOIN 读回服务器名 + 探针最近写入时间，供下方写节流判断。
        const kuiServer = await db.prepare('SELECT s.name AS name, p.last_report_id AS last_report_id, p.last_updated AS last_updated FROM servers s LEFT JOIN probe_servers p ON p.id = s.ip WHERE s.ip = ?').bind(vpsIp).first();
        if (!kuiServer) {
            return Response.json({ error: "Server has been removed from KUI panel." }, { status: 403 });
        }
        const serverName = kuiServer.name;
        const duplicateReport = !!kuiServer.last_report_id && kuiServer.last_report_id === data.report_id;
        const hasTraffic = !duplicateReport && data.node_traffic.length > 0;
        // [D1 优化] 状态写节流：120 秒内已写过、且本笔无节点流量增量时，
        // 跳过 servers / probe_servers 的状态 UPDATE。月流量按 DB 中保存的
        // last_rx/last_tx 在下一次写入时差分结算，不会丢失；实时面板数据
        // 走 DO WebSocket，不受节流影响。
        const stateDue = !kuiServer.last_updated || (nowMs - Number(kuiServer.last_updated) >= 120000);
        const writeState = stateDue || hasTraffic;

        if (writeState) try { 
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?")
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, vpsIp).run(); 
        } catch (e) { 
            await ensureDbSchema(db); 
            await db.prepare("UPDATE servers SET cpu=?, mem=?, disk=?, load=?, uptime=?, net_in_speed=?, net_out_speed=?, tcp_conn=?, udp_conn=?, last_report=?, alert_sent=0 WHERE ip=?")
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', data.net_in_speed||0, data.net_out_speed||0, data.tcp_conn||0, data.udp_conn||0, nowMs, vpsIp).run(); 
        }

        if (writeState) try {
            let countryCode = request.cf && request.cf.country ? request.cf.country : 'XX'; 
            if (countryCode.toUpperCase() === 'TW') countryCode = 'CN';

            const probeServer = await db.prepare('SELECT * FROM probe_servers WHERE id = ?').bind(vpsIp).first();
            
            // --- 全新核心：基于动态 reset_day 的流量生命周期重置 ---
            const localNow = new Date(nowMs + 8 * 60 * 60000); 
            let y = localNow.getFullYear();
            let m = localNow.getMonth() + 1;
            let d = localNow.getDate();
            
            let resetDayVal = probeServer ? parseInt(probeServer.reset_day) || 1 : 1;
            if (resetDayVal < 1) resetDayVal = 1; if (resetDayVal > 31) resetDayVal = 31;
            
            let maxDaysThisMonth = new Date(y, m, 0).getDate();
            let actualResetDayThisMonth = Math.min(resetDayVal, maxDaysThisMonth);
            
            let currentCycleStr = '';
            if (d < actualResetDayThisMonth) {
                let pm = m - 1; let py = y;
                if (pm === 0) { pm = 12; py -= 1; }
                let maxDaysPrevMonth = new Date(py, pm, 0).getDate();
                let actualResetDayPrevMonth = Math.min(resetDayVal, maxDaysPrevMonth);
                currentCycleStr = `${py}-${pm}-${actualResetDayPrevMonth}`;
            } else {
                currentCycleStr = `${y}-${m}-${actualResetDayThisMonth}`;
            }

            let monthly_rx = 0, monthly_tx = 0, last_rx = 0, last_tx = 0;
            let reset_month = currentCycleStr;
            let history = {};

            if (!probeServer) {
                await db.prepare(`INSERT INTO probe_servers (id, name, cpu, ram, disk, load_avg, uptime, last_updated, ram_total, net_rx, net_tx, net_in_speed, net_out_speed, os, cpu_info, arch, boot_time, ram_used, swap_total, swap_used, disk_total, disk_used, processes, tcp_conn, udp_conn, country, ip_v4, ip_v6, server_group, price, expire_date, bandwidth, traffic_limit, ping_ct, ping_cu, ping_cm, ping_bd, monthly_rx, monthly_tx, last_rx, last_tx, reset_month, agent_os, history, is_hidden, virt, reset_day) VALUES (?, ?, '0', '0', '0', '0', '0', 0, '0', '0', '0', '0', '0', '', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', ?, '1', '0', '默认分组', '免费', '', '', '', '0', '0', '0', '0', '0', '0', '0', '0', ?, 'debian', '{}', 'false', '', '1')`).bind(vpsIp, serverName, countryCode, currentCycleStr).run();
            } else {
                monthly_rx = parseFloat(probeServer.monthly_rx || '0'); monthly_tx = parseFloat(probeServer.monthly_tx || '0');
                last_rx = parseFloat(probeServer.last_rx || '0'); last_tx = parseFloat(probeServer.last_tx || '0');
                reset_month = probeServer.reset_month || currentCycleStr;
                
                let autoReset = 'false';
                try { const r = await db.prepare("SELECT value FROM probe_settings WHERE key = 'auto_reset_traffic'").first(); if (r) autoReset = r.value; } catch(e){}
                // 周期变动立即清零结算
                if (autoReset === 'true' && currentCycleStr !== reset_month) { monthly_rx = 0; monthly_tx = 0; reset_month = currentCycleStr; }
                try { history = JSON.parse(probeServer.history || '{}'); } catch(e) {}
            }

            const current_rx = parseFloat(data.net_rx || '0'); const current_tx = parseFloat(data.net_tx || '0');
            const probeAlreadyApplied = probeServer && probeServer.last_report_id === data.report_id;
            if (!duplicateReport && !probeAlreadyApplied) {
                if (current_rx >= last_rx) monthly_rx += (current_rx - last_rx); else monthly_rx += current_rx;
                if (current_tx >= last_tx) monthly_tx += (current_tx - last_tx); else monthly_tx += current_tx;
                last_rx = current_rx; last_tx = current_tx;
            }

            const lastHistTime = history.last_time || 0;
            if (nowMs - lastHistTime >= 300000 || !history.time) {
                const maxPoints = 288; 
                const updateArr = (arr, val) => { if (!Array.isArray(arr)) arr = []; arr.push(val); if (arr.length > maxPoints) arr.shift(); return arr; };
                const updateLabels = (arr) => { if (!Array.isArray(arr)) arr = []; const d = new Date(nowMs + 8 * 60 * 60000); arr.push(d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0')); if (arr.length > maxPoints) arr.shift(); return arr; };
                history.cpu = updateArr(history.cpu, parseFloat(data.cpu) || 0); history.ram = updateArr(history.ram, parseFloat(data.mem) || 0); history.proc = updateArr(history.proc, parseInt(data.processes) || 0); 
                history.net_in = updateArr(history.net_in, parseFloat(data.net_in_speed) || 0); history.net_out = updateArr(history.net_out, parseFloat(data.net_out_speed) || 0); 
                history.tcp = updateArr(history.tcp, parseInt(data.tcp_conn) || 0); history.udp = updateArr(history.udp, parseInt(data.udp_conn) || 0); 
                history.ping_ct = updateArr(history.ping_ct, parseInt(data.ping_ct) || 0); history.ping_cu = updateArr(history.ping_cu, parseInt(data.ping_cu) || 0); history.ping_cm = updateArr(history.ping_cm, parseInt(data.ping_cm) || 0); history.ping_bd = updateArr(history.ping_bd, parseInt(data.ping_bd) || 0); 
                history.time = updateLabels(history.time); history.last_time = nowMs;
            }

            await db.prepare(`UPDATE probe_servers SET cpu=?, ram=?, disk=?, load_avg=?, uptime=?, last_updated=?, ram_total=?, net_rx=?, net_tx=?, net_in_speed=?, net_out_speed=?, os=?, cpu_info=?, arch=?, boot_time=?, ram_used=?, swap_total=?, swap_used=?, disk_total=?, disk_used=?, processes=?, tcp_conn=?, udp_conn=?, ping_ct=?, ping_cu=?, ping_cm=?, ping_bd=?, monthly_rx=CASE WHEN last_report_id=? THEN monthly_rx ELSE ? END, monthly_tx=CASE WHEN last_report_id=? THEN monthly_tx ELSE ? END, last_rx=CASE WHEN last_report_id=? THEN last_rx ELSE ? END, last_tx=CASE WHEN last_report_id=? THEN last_tx ELSE ? END, reset_month=?, history=?, virt=?, last_report_id=? WHERE id=?`)
                    .bind(data.cpu||0, data.mem||0, data.disk||0, data.load||'', data.uptime||'', nowMs, data.ram_total||'0', data.net_rx||'0', data.net_tx||'0', data.net_in_speed||0, data.net_out_speed||0, data.os||'', data.cpu_info||'', data.arch||'', data.boot_time||'', data.ram_used||'0', data.swap_total||'0', data.swap_used||'0', data.disk_total||'0', data.disk_used||'0', data.processes||'0', data.tcp_conn||0, data.udp_conn||0, data.ping_ct||'0', data.ping_cu||'0', data.ping_cm||'0', data.ping_bd||'0', data.report_id, monthly_rx.toString(), data.report_id, monthly_tx.toString(), data.report_id, last_rx.toString(), data.report_id, last_tx.toString(), reset_month, JSON.stringify(history), data.virt||'', data.report_id, vpsIp).run();

        } catch (e) { console.error("探针数据同步失败:", e); }

        const stmts = []; let totalDelta = 0;
        if (hasTraffic) {
            const traffic = data.node_traffic;
            if (traffic.length) {
                const trafficJson = JSON.stringify(traffic.map(nt => ({ id: nt.id, bytes: Number(nt.delta_bytes) })));
                const deltaCte = `WITH deltas(id, bytes) AS (SELECT json_extract(value, '$.id'), CAST(json_extract(value, '$.bytes') AS INTEGER) FROM json_each(?))`;
                stmts.push(db.prepare(`${deltaCte} UPDATE nodes SET traffic_used = traffic_used + COALESCE((SELECT SUM(bytes) FROM deltas WHERE deltas.id = nodes.id), 0) WHERE vps_ip = ? AND id IN (SELECT id FROM deltas)`).bind(trafficJson, vpsIp));
                stmts.push(db.prepare(`${deltaCte}, user_deltas(username, bytes) AS (SELECT n.username, SUM(d.bytes) FROM deltas d JOIN nodes n ON n.id = d.id AND n.vps_ip = ? GROUP BY n.username) UPDATE users SET traffic_used = traffic_used + COALESCE((SELECT bytes FROM user_deltas WHERE user_deltas.username = users.username), 0) WHERE username IN (SELECT username FROM user_deltas)`).bind(trafficJson, vpsIp));
                totalDelta = data.total_delta;
            }
        }
        if (data.argo_urls && data.argo_urls.length > 0) { for (let argo of data.argo_urls) { stmts.push(db.prepare("UPDATE nodes SET sni = ? WHERE id = ? AND vps_ip = ? AND protocol = 'VLESS-Argo' AND sni != ?").bind(argo.url, argo.id, vpsIp, argo.url)); } }
        if (totalDelta > 0) stmts.push(db.prepare("INSERT INTO traffic_stats (ip, delta_bytes, timestamp) VALUES (?, ?, ?)").bind(vpsIp, totalDelta, nowMs));
        if (stmts.length > 0) {
            await db.batch(stmts);
        }
        // report_receipts 已停用（判重改走 last_report_id）；这里仅每小时顺手
        // 清理历史遗留行，等存量排空后可整体移除。
        if (nowMs - lastReceiptCleanup > 3600000) {
            lastReceiptCleanup = nowMs;
            context.waitUntil(db.prepare("DELETE FROM report_receipts WHERE created_at < ?").bind(nowMs - 604800000).run().catch(() => {}));
        }
        
        let fastMode = false; try { const uiActive = await db.prepare("SELECT ts FROM sys_config WHERE key = 'ui_active'").first(); if (uiActive && (nowMs - uiActive.ts < 90000)) fastMode = true; } catch(e) {}
        
        let reportInterval = 5; let pingCt = 'default'; let pingCu = 'default'; let pingCm = 'default';
        try { 
            const { results } = await db.prepare("SELECT key, value FROM probe_settings WHERE key IN ('report_interval', 'ping_node_ct', 'ping_node_cu', 'ping_node_cm')").all(); 
            if (results) {
                results.forEach(r => {
                    if (r.key === 'report_interval') reportInterval = parseInt(r.value) || 5;
                    if (r.key === 'ping_node_ct') pingCt = r.value;
                    if (r.key === 'ping_node_cu') pingCu = r.value;
                    if (r.key === 'ping_node_cm') pingCm = r.value;
                });
            }
        } catch(e) {}
        
        const effectiveInterval = Math.min(300, fastMode ? Math.max(15, reportInterval) : Math.max(120, reportInterval));
        return Response.json({ success: true, fast_mode: fastMode, interval: effectiveInterval, ping_ct: pingCt, ping_cu: pingCu, ping_cm: pingCm });
     } catch (err) {
        return Response.json({ error: "REPORT_ERR: " + (err && err.message ? err.message : String(err)) }, { status: 500 });
     }
    }

    if (action === "config" && method === "GET") {
        await ensureDbSchema(db);
        const ip = new URL(request.url).searchParams.get("ip"); const now = Date.now(); const adminUser = env.ADMIN_USERNAME || "admin";
        const authHeader = request.headers.get("Authorization");
        const currentUser = await verifyAuth(authHeader, request, db, env, context);
        const agentAuthenticated = await verifyAgent(authHeader, ip, db, env);
        if (currentUser !== adminUser && !agentAuthenticated) return new Response("Unauthorized", { status: 401 });
        const query = `SELECT n.* FROM nodes n LEFT JOIN users u ON n.username = u.username WHERE n.vps_ip = ? AND n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit) AND (n.expire_time = 0 OR n.expire_time > ?) AND (n.username = ? OR n.username = 'admin' OR (u.username IS NOT NULL AND u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) AND (u.expire_time = 0 OR u.expire_time > ?)))`;
        const { results: machineNodes } = await db.prepare(query).bind(ip, now, adminUser, now).all();
        for (let node of machineNodes) { if (node.protocol === "dokodemo-door" && node.relay_type === "internal") { const targetNode = await db.prepare("SELECT * FROM nodes WHERE id = ?").bind(node.target_id).first(); if (targetNode) node.chain_target = { ip: targetNode.vps_ip, port: targetNode.port, protocol: targetNode.protocol, uuid: targetNode.uuid, password: targetNode.private_key, sni: targetNode.sni, public_key: targetNode.public_key, short_id: targetNode.short_id }; } }
        let proxyCfg = { global: {}, toggle: { enable: false } };
        try {
            const r = await db.prepare("SELECT value FROM probe_settings WHERE key='proxy_config'").first();
            if (r && r.value) { try { proxyCfg.global = JSON.parse(r.value); } catch (ex) {} }
            const t = await db.prepare("SELECT value FROM probe_settings WHERE key='proxy_toggle_' || ?").bind(ip).first();
            if (t && t.value) { try { proxyCfg.toggle = JSON.parse(t.value); } catch (ex) {} }
        } catch (ex) {}
        let socks5_outbound = { enabled: false };
        let egress = { desired_mode: 'native', applied_mode: 'native', revision: 0, applied_revision: 0, status: 'applied', error: '', applied_at: 0 };
        let residential_outbound = { available: false };
        let mergedAgentToken = '';
        try {
            // [D1 优化] agent_token 并入这条 servers 查询，省掉单独一次读取。
            const s = await db.prepare("SELECT egress_mode, egress_applied_mode, egress_revision, egress_applied_revision, egress_status, egress_error, egress_applied_at, proxy_mode, proxy_categories, egress_ip, socks5_addr, socks5_port, socks5_user, socks5_pass, agent_token FROM servers WHERE ip = ?").bind(ip).first();
            if (s) { mergedAgentToken = s.agent_token || ''; egress = { desired_mode: s.egress_mode || 'native', applied_mode: s.egress_applied_mode || 'native', revision: Number(s.egress_revision || 0), applied_revision: Number(s.egress_applied_revision || 0), status: s.egress_status || 'applied', error: s.egress_error || '', applied_at: Number(s.egress_applied_at || 0), proxy_mode: s.proxy_mode || 'global', proxy_categories: s.proxy_categories || '', egress_ip: s.egress_ip || '', socks5_addr: s.socks5_addr || '', socks5_port: Number(s.socks5_port || 0), socks5_user: s.socks5_user || '', socks5_pass: s.socks5_pass || '' }; }
            // 住宅出口由本机住宅引擎提供（127.0.0.1:<全局端口> 的 SOCKS5），
            // 端口读融合模块的 frp_global_config（30 秒缓存）；SOCKS5 凭据为本机
            // PROXY_USER/PROXY_PASS，且仅向通过 Agent 鉴权的请求下发。
            let port = frpDefaultPort(env);
            try { port = Number((await frpReadGlobalConfig(db, env)).proxy_port) || port; } catch (_) {}
            const credsReady = !!(env.PROXY_USER && env.PROXY_PASS);
            residential_outbound = { available: credsReady, reason: credsReady ? '' : '未设置 PROXY_USER / PROXY_PASS（住宅 SOCKS5 凭据）', addr: '127.0.0.1', port, user: agentAuthenticated ? env.PROXY_USER || '' : '', pass: agentAuthenticated ? env.PROXY_PASS || '' : '' };
        } catch (ex) {}
        const realtimeUrl = await getRealtimeUrl(env, db);
        return Response.json({ success: true, configs: machineNodes, agent_token: mergedAgentToken, proxy: proxyCfg, residential_outbound, egress, realtime_url: realtimeUrl });
    }

        if (action === "egress_result" && method === "POST") {
            await ensureDbSchema(db);
            const body = await request.json();
            const ip = body.ip || request.headers.get('X-KUI-IP');
            if (!ip || !(await verifyAgent(request.headers.get('Authorization'), ip, db, env))) return new Response('Unauthorized', { status: 401 });
            const modes = ['native', 'residential', 'warp_ipv4', 'warp_ipv6', 'warp_dual', 'socks5'];
        const revision = Number(body.revision);
        if (!Number.isSafeInteger(revision) || revision < 0 || !modes.includes(body.applied_mode)) return Response.json({ error: 'Invalid egress result' }, { status: 400 });
        const success = body.success === true;
        const status = success ? 'applied' : 'failed';
        const error = success ? '' : String(body.error || 'Egress apply failed').slice(0, 500);
        const egress_ip = body.egress_ip ? String(body.egress_ip).slice(0, 64) : '';
        let result;
        if (success) {
            const s5_enable = body.applied_mode === 'residential' || body.applied_mode === 'socks5' ? 1 : 0;
            try {
                result = await db.prepare("UPDATE servers SET egress_applied_mode = ?, egress_applied_revision = ?, egress_status = 'applied', egress_error = '', egress_applied_at = ?, socks5_enable = ?, warp_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END, warp_applied_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END, proxy_mode = CASE WHEN ? IN ('residential','socks5') THEN proxy_mode ELSE 'global' END, proxy_categories = CASE WHEN ? IN ('residential','socks5') THEN proxy_categories ELSE '' END, egress_ip = ? WHERE ip = ? AND egress_revision = ? AND egress_mode = ?").bind(body.applied_mode, revision, Date.now(), s5_enable, body.applied_mode, body.applied_mode, body.applied_mode, body.applied_mode, body.applied_mode, body.applied_mode, egress_ip, ip, revision, body.applied_mode).run();
            } catch (sqlErr) {
                try {
                    result = await db.prepare("UPDATE servers SET egress_applied_mode = ?, egress_applied_revision = ?, egress_status = 'applied', egress_error = '', egress_applied_at = ?, socks5_enable = ?, warp_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END, warp_applied_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END, egress_ip = ? WHERE ip = ? AND egress_revision = ? AND egress_mode = ?").bind(body.applied_mode, revision, Date.now(), s5_enable, body.applied_mode, body.applied_mode, body.applied_mode, body.applied_mode, egress_ip, ip, revision, body.applied_mode).run();
                } catch (sqlErr2) {
                    result = await db.prepare("UPDATE servers SET egress_applied_mode = ?, egress_applied_revision = ?, egress_status = 'applied', egress_error = '', egress_applied_at = ?, socks5_enable = ?, warp_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END, warp_applied_mode = CASE WHEN ? LIKE 'warp_%' THEN substr(?, 6) ELSE 'off' END WHERE ip = ? AND egress_revision = ? AND egress_mode = ?").bind(body.applied_mode, revision, Date.now(), s5_enable, body.applied_mode, body.applied_mode, body.applied_mode, body.applied_mode, ip, revision, body.applied_mode).run();
                }
            }
        } else {
            result = await db.prepare("UPDATE servers SET egress_status = 'failed', egress_error = ?, egress_applied_at = ? WHERE ip = ? AND egress_revision = ? AND egress_applied_mode = ?").bind(error, Date.now(), ip, revision, body.applied_mode).run();
        }
        return Response.json({ success: true, accepted: Number(result.meta?.changes || 0) > 0 });
    }

    // 🌟 住宅IP代理：FRP 控制器已融合进本 Worker（见 proxyModule）
    if (action === "proxy") {
        const sub = params.path && params.path.length > 1 ? params.path.slice(1).join('/') : '';
        const allowedProxyPaths = sub === 'config' || sub === 'report' || sub === 'proxies' || sub === 'nodes' || sub === 'countries' || sub === 'pool' || sub === 'switch'
            || sub === 'agent-config' || sub === 'installer' || sub === 'server/config' || sub === 'server/switch' || sub === 'server/remove' || sub === 'server/uninstalled'
            || sub === 'scripts/lite_manager.py' || sub === 'scripts/proxy_server.py' || sub.startsWith('testisp-lookup/');
        if (!allowedProxyPaths || sub.includes('..')) return new Response('Not Found', { status: 404 });
        if (sub === "mesh" || sub.startsWith("mesh/")) {
            return new Response(JSON.stringify({ error: "mesh is not supported" }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }
        await ensureDbSchema(db);
        // Agent 面（report / agent-config / scripts / uninstalled 回调）：
        // FRP 引擎用管理员 Basic 凭据（与面板同一套）；失败计入登录限流。
        const frpAgentFacing = sub === 'report' || sub === 'agent-config' || sub === 'server/uninstalled' || sub.startsWith('scripts/');
        if (frpAgentFacing) {
            if (!(await loginAllowed(db, request))) return new Response('Too Many Requests', { status: 429 });
            if (!(await verifyFrpBasic(request, env))) {
                await recordLoginFailure(db, request).catch(() => {});
                return new Response('Unauthorized', { status: 401 });
            }
        } else if (sub === 'installer') {
            // 安装脚本内含 c2 凭据，只能凭本机 agent_token 领取
            const installerIp = new URL(request.url).searchParams.get('ip');
            if (!(await verifyAgent(request.headers.get('Authorization'), installerIp, db, env))) return new Response('Unauthorized', { status: 401 });
        } else if (sub === 'config' && method === 'GET') {
            const requestIp = new URL(request.url).searchParams.get('ip');
            const user = await verifyAuth(request.headers.get('Authorization'), request, db, env, context);
            if (user !== (env.ADMIN_USERNAME || 'admin') && !(await verifyAgent(request.headers.get('Authorization'), requestIp, db, env))) return new Response('Forbidden', { status: 403 });
        } else {
            const user = await verifyAuth(request.headers.get('Authorization'), request, db, env, context);
            if (user !== (env.ADMIN_USERNAME || 'admin')) return new Response('Forbidden', { status: 403 });
        }
        return await proxyModule(method, sub, request, env);
    }

    // 🌟 核心拦截并拆分普通订阅与 Clash 订阅生成
    if (action === "sub" && method === "GET") {
        await ensureDbSchema(db);
        const subscriptionProtection = await db.prepare("SELECT value FROM probe_settings WHERE key = 'subscription_protection'").first();
        if (subscriptionProtection?.value === 'true') {
            return protectedSubscriptionResponse(request);
        }
        const urlObj = new URL(request.url); 
        const ip = urlObj.searchParams.get("ip"); 
        const reqUser = urlObj.searchParams.get("user"); 
        // 订阅 token 优先从 Authorization: Bearer 头读取，避免长期 token 落进 URL
        // （边缘日志/浏览器历史）。保留 ?token= 查询参数以兼容旧客户端。
        const bearerHeader = String(request.headers.get("Authorization") || "");
        const token = urlObj.searchParams.get("token") || (bearerHeader.startsWith("Bearer ") ? bearerHeader.slice(7) : ""); 
        const format = urlObj.searchParams.get("format"); 
        const adminUser = env.ADMIN_USERNAME || "admin";

        let isValid = false;
        if (reqUser === adminUser) { 
            let adminSubToken = '';
            try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='admin_sub_token'").first(); if(r && r.val) adminSubToken = r.val; } catch(e){} 
            isValid = !!adminSubToken && !!token && (await timingSafeEqual(token, adminSubToken));
        } 
        else { 
            const u = await db.prepare("SELECT password, sub_token FROM users WHERE username = ? AND enable = 1").bind(reqUser).first();
            if (u) isValid = !!u.sub_token && !!token && (await timingSafeEqual(token, u.sub_token));
        }
        
        // Invalid tokens deliberately look like absent endpoints. Protected
        // subscriptions return a harmless HTTP 200 profile before validation.
        if (!isValid) return json({ error: "Not found" }, 404);
        
        const now = Date.now(); 
        let query; 
        let sqlParams = [now];
        
        if (reqUser === adminUser) { 
            query = `SELECT * FROM nodes WHERE enable = 1 AND (traffic_limit = 0 OR traffic_used < traffic_limit) AND (expire_time = 0 OR expire_time > ?) AND (username = ? OR username = 'admin')`; 
            sqlParams.push(adminUser); 
            if (ip) { query += " AND vps_ip = ?"; sqlParams.push(ip); } 
        } else { 
            query = `SELECT DISTINCT n.* FROM nodes n JOIN users u ON u.username = ? WHERE n.enable = 1 AND (n.traffic_limit = 0 OR n.traffic_used < n.traffic_limit) AND (n.expire_time = 0 OR n.expire_time > ?) AND u.enable = 1 AND (u.traffic_limit = 0 OR u.traffic_used < u.traffic_limit) AND (u.expire_time = 0 OR u.expire_time > ?) AND (n.username = u.username OR EXISTS (SELECT 1 FROM user_group_members gm JOIN user_group_resources gr ON gr.group_id = gm.group_id WHERE gm.username = u.username AND ((gr.resource_type = 'node' AND gr.resource_id = n.id) OR (gr.resource_type = 'vps' AND gr.resource_id = n.vps_ip))))`;
            sqlParams = [reqUser, now, now];
            if (ip) { query += " AND n.vps_ip = ?"; sqlParams.push(ip); } 
        }
        
        const { results } = await db.prepare(query).bind(...sqlParams).all(); 
        
        let subLinks = [];
        let clashProxies = [];
        let proxyNames = [];

        for (let node of results) {
            const vpsInfo = await db.prepare("SELECT name FROM servers WHERE ip = ?").bind(node.vps_ip).first(); 
            const rawRemark = `${vpsInfo ? vpsInfo.name : 'KUI'} | ${node.protocol}_${node.port}`; 
            const remark = encodeURIComponent(rawRemark); 
            let link = "";
            let cProxy = "";
            const nodeIp = formatIpForLink(node.vps_ip);
            const nodeSni = node.sni || '';

            // --- 传统 Base64 URL 生成 ---
            switch (node.protocol) {
                case "VLESS": link = `vless://${node.uuid}@${nodeIp}:${node.port}?encryption=none&security=none&type=tcp#${remark}`; break;
                case "XTLS-Reality": case "Reality": link = `vless://${node.uuid}@${nodeIp}:${node.port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${nodeSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=tcp&headerType=none#${remark}`; break;
                case "Hysteria2": link = `hysteria2://${encodeURIComponent(node.uuid || node.private_key)}@${nodeIp}:${node.port}/?insecure=1&sni=${encodeURIComponent(nodeSni)}&alpn=h3#${remark}`; break;
                case "TUIC": link = `tuic://${node.uuid}:${node.private_key}@${nodeIp}:${node.port}?sni=${nodeSni}&congestion_control=bbr&alpn=h3&allow_insecure=1#${remark}`; break;
                case "Trojan": link = `trojan://${node.private_key}@${nodeIp}:${node.port}?security=tls&sni=${nodeSni}&allowInsecure=1&type=tcp#${remark}`; break;
                case "H2-Reality": link = `vless://${node.uuid}@${nodeIp}:${node.port}?encryption=none&security=reality&sni=${nodeSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=http#${remark}`; break;
                case "gRPC-Reality": link = `vless://${node.uuid}@${nodeIp}:${node.port}?encryption=none&security=reality&sni=${nodeSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=grpc&serviceName=grpc#${remark}`; break;
                case "AnyTLS": link = `anytls://${node.private_key}@${nodeIp}:${node.port}?security=tls&sni=${nodeSni}&insecure=1#${remark}`; break;
                case "Naive": link = `naive+https://${node.uuid}:${node.private_key}@${nodeIp}:${node.port}?security=tls&sni=${nodeSni}#${remark}`; break;
                case "Socks5": link = `socks5://${btoa(`${node.uuid}:${node.private_key}`)}@${nodeIp}:${node.port}#${remark}`; break;
                case "VLESS-Argo": if (!(node.sni || '').includes('等待')) link = `vless://${node.uuid}@${node.sni}:443?encryption=none&security=tls&type=ws&host=${node.sni}&path=%2F#${remark}-Argo`; break;
            }
            if (link) subLinks.push(link);

            // --- 动态拼装 Clash YAML 代理字典 (支持 Clash Meta / Mihomo) ---
            if (format === 'clash') {
                if (node.protocol.includes("VLESS") || node.protocol.includes("Reality")) {
                    const serverIpOrSni = (node.protocol === 'VLESS-Argo' && !(node.sni || '').includes('等待')) ? node.sni : nodeIp;
                    const serverPort = node.protocol === 'VLESS-Argo' ? 443 : node.port;
                    cProxy = `  - name: ${yamlString(rawRemark)}\n    type: vless\n    server: ${yamlString(serverIpOrSni)}\n    port: ${serverPort}\n    uuid: ${yamlString(node.uuid)}\n    udp: true`;
                    
                    if (node.protocol === "XTLS-Reality" || node.protocol === "Reality") {
                        cProxy += `\n    tls: true\n    flow: xtls-rprx-vision\n    servername: ${yamlString(nodeSni)}\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: ${yamlString(node.public_key)}\n      short-id: ${yamlString(node.short_id || "")}`;
                     } else if (node.protocol === "gRPC-Reality") {
                         cProxy += `\n    tls: true\n    alpn:\n      - h2\n    servername: ${yamlString(nodeSni)}\n    client-fingerprint: chrome\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc\n    reality-opts:\n      public-key: ${yamlString(node.public_key)}\n      short-id: ${yamlString(node.short_id || "")}`;
                     } else if (node.protocol === "H2-Reality") {
                         cProxy += `\n    tls: true\n    alpn:\n      - h2\n    servername: ${yamlString(nodeSni)}\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: ${yamlString(node.public_key || '')}\n      short-id: ${yamlString(node.short_id || "")}\n    network: h2\n    h2-opts:\n      host:\n        - ${yamlString(nodeSni || nodeIp)}\n      path: "/"`;
                    } else if (node.protocol === 'VLESS-Argo' && !(node.sni || '').includes('等待')) {
                        cProxy += `\n    tls: true\n    servername: ${yamlString(nodeSni)}\n    network: ws\n    ws-opts:\n      path: "/"\n      headers:\n        Host: ${yamlString(nodeSni)}`;
                    }
                } else if (node.protocol === "Trojan") {
                    cProxy = `  - name: ${yamlString(rawRemark)}\n    type: trojan\n    server: ${yamlString(nodeIp)}\n    port: ${node.port}\n    password: ${yamlString(node.private_key)}\n    udp: true\n    sni: ${yamlString(nodeSni)}\n    skip-cert-verify: true`;
                } else if (node.protocol === "AnyTLS") {
                    cProxy = `  - name: ${yamlString(rawRemark)}\n    type: anytls\n    server: ${yamlString(nodeIp)}\n    port: ${node.port}\n    password: ${yamlString(node.private_key)}\n    client-fingerprint: chrome\n    udp: true\n    sni: ${yamlString(nodeSni)}\n    skip-cert-verify: true`;
                } else if (node.protocol === "Hysteria2") {
                    cProxy = `  - name: ${yamlString(rawRemark)}\n    type: hysteria2\n    server: ${yamlString(nodeIp)}\n    port: ${node.port}\n    password: ${yamlString(node.uuid || node.private_key)}\n    sni: ${yamlString(nodeSni)}\n    skip-cert-verify: true`;
                } else if (node.protocol === "TUIC") {
                    cProxy = `  - name: ${yamlString(rawRemark)}\n    type: tuic\n    server: ${yamlString(nodeIp)}\n    port: ${node.port}\n    uuid: ${yamlString(node.uuid)}\n    password: ${yamlString(node.private_key)}\n    sni: ${yamlString(nodeSni)}\n    skip-cert-verify: true`;
                }
                
                if (cProxy) {
                    clashProxies.push(cProxy);
                    proxyNames.push(yamlString(rawRemark));
                }
            }
        }

        // --- 第三方订阅节点整合进订阅 ---
        try {
            const { results: thNodes } = await db.prepare("SELECT * FROM third_party_nodes WHERE enable = 1").all();
            for (const node of thNodes) {
                try {
                const remark = encodeURIComponent(node.name || `TP_${node.protocol}_${node.port}`);
                let link = "";
                const thirdIp = formatIpForLink(node.address);
                const thirdSni = node.sni || '';
                switch (node.protocol) {
                    case "VMess": link = (node.extra && node.extra.startsWith('vmess://')) ? node.extra : ''; break;
                    case "VLESS": {
                        if (node.flow && (node.public_key || node.flow.includes('rprx'))) {
                            link = `vless://${node.uuid}@${thirdIp}:${node.port}?encryption=none&flow=${node.flow}&security=reality&sni=${thirdSni}&fp=chrome&pbk=${node.public_key||''}&sid=${node.short_id||''}&type=${node.network||'tcp'}${node.path ? '&path=' + encodeURIComponent(node.path) : ''}#${remark}`;
                        } else {
                            link = `vless://${node.uuid}@${thirdIp}:${node.port}?encryption=none&security=none&type=${node.network||'tcp'}${node.path ? '&path=' + encodeURIComponent(node.path) : ''}${node.host ? '&host=' + encodeURIComponent(node.host) : ''}#${remark}`;
                        }
                        break;
                    }
                    case "XTLS-Reality": case "Reality": link = `vless://${node.uuid}@${thirdIp}:${node.port}?encryption=none&flow=${node.flow||'xtls-rprx-vision'}&security=reality&sni=${thirdSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id||""}&type=${node.network||'tcp'}${node.path?'&path='+encodeURIComponent(node.path):''}${node.host?'&host='+encodeURIComponent(node.host):''}#${remark}`; break;
                    case "Hysteria2": link = `hysteria2://${encodeURIComponent(node.uuid || node.password)}@${thirdIp}:${node.port}/?insecure=1&sni=${encodeURIComponent(thirdSni)}&alpn=h3#${remark}`; break;
                    case "TUIC": link = `tuic://${node.uuid}:${node.password}@${thirdIp}:${node.port}?sni=${thirdSni}&congestion_control=bbr&alpn=h3&allow_insecure=1#${remark}`; break;
                    case "Trojan": link = `trojan://${node.password}@${thirdIp}:${node.port}?security=tls&sni=${thirdSni}&allowInsecure=1&type=tcp#${remark}`; break;
                    case "H2-Reality": link = `vless://${node.uuid}@${thirdIp}:${node.port}?encryption=none&security=reality&sni=${thirdSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=http#${remark}`; break;
                    case "gRPC-Reality": link = `vless://${node.uuid}@${thirdIp}:${node.port}?encryption=none&security=reality&sni=${thirdSni}&fp=chrome&pbk=${node.public_key}&sid=${node.short_id || ""}&type=grpc&serviceName=grpc#${remark}`; break;
                    case "AnyTLS": link = `anytls://${node.password}@${thirdIp}:${node.port}?security=tls&sni=${thirdSni}&insecure=1#${remark}`; break;
                    case "Naive": link = `naive+https://${node.uuid}:${node.password}@${thirdIp}:${node.port}?security=tls&sni=${thirdSni}#${remark}`; break;
                    case "Socks5": link = `socks5://${btoa(unescape(encodeURIComponent(`${node.uuid}:${node.password}`)))}@${thirdIp}:${node.port}#${remark}`; break;
                    case "SS": {
                        const method = node.uuid || (() => { try { return JSON.parse(node.extra || '{}').method; } catch(e) { return ''; } })();
                        link = `ss://${btoa(unescape(encodeURIComponent(`${method}:${node.password}`)))}@${thirdIp}:${node.port}#${remark}`;
                        break;
                    }
                    case "SSR": link = `ssr://${btoa(unescape(encodeURIComponent(`${thirdIp}:${node.port}:origin:${node.uuid}:plain:${btoa(node.password || '')}/?remarks=${btoa(unescape(encodeURIComponent(node.name || 'SSR')))}`)))}`; break;
                }
                if (link) subLinks.push(link);

                if (format === 'clash') {
                    let cProxy = "";
                    if (node.protocol === "VMess") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: vmess\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    uuid: ${yamlString(node.uuid)}\n    alterId: 0\n    cipher: auto\n    udp: true${node.network && node.network !== 'tcp' ? `\n    network: ${yamlString(node.network)}${node.host ? `\n    ws-headers:\n      Host: ${yamlString(node.host)}` : ''}${node.path ? `\n    ws-path: ${yamlString(node.path)}` : ''}` : ''}`;
                    } else if (node.protocol.includes("VLESS") || node.protocol.includes("Reality")) {
                        const isReality = (node.flow && node.flow.includes('rprx')) || ["XTLS-Reality", "Reality", "H2-Reality", "gRPC-Reality"].includes(node.protocol);
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: vless\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    uuid: ${yamlString(node.uuid)}\n    udp: true`;
                        if (isReality) {
                             cProxy += `\n    tls: true${['http', 'grpc'].includes((node.network || '').toLowerCase()) || ['H2-Reality', 'gRPC-Reality'].includes(node.protocol) ? '\n    alpn:\n      - h2' : ''}\n    servername: ${yamlString(thirdSni)}\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: ${yamlString(node.public_key || '')}\n      short-id: ${yamlString(node.short_id || "")}`;
                            if (((node.protocol === "Reality" || node.protocol === "XTLS-Reality") && node.flow && node.flow.includes('rprx')) || node.protocol === "VLESS") {
                                cProxy += `\n    flow: ${node.flow || 'xtls-rprx-vision'}`;
                            }
                            const net = node.network || 'tcp';
                            if (net === 'grpc') {
                                cProxy += `\n    network: grpc\n    grpc-opts:\n      grpc-service-name: ${node.extra?.serviceName || 'grpc'}`;
                            } else if (net === 'http') {
                                const path = node.path || '/';
                                const hostHeader = node.host || thirdSni || thirdIp;
                                cProxy += `\n    network: h2\n    h2-opts:\n      host:\n        - ${yamlString(hostHeader)}\n      path: ${yamlString(path)}`;
                            } else if (net === 'ws') {
                                const path = node.path || '/';
                                const hostHeader = node.host || thirdSni || thirdIp;
                                cProxy += `\n    network: ws\n    ws-opts:\n      path: ${yamlString(path)}\n      headers:\n        Host: ${yamlString(hostHeader)}`;
                            }
                        } else if (node.protocol === "gRPC-Reality") {
                            cProxy += `\n    tls: true\n    servername: ${yamlString(thirdSni)}\n    client-fingerprint: chrome\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc\n    reality-opts:\n      public-key: ${yamlString(node.public_key)}\n      short-id: ${yamlString(node.short_id || "")}`;
                         } else if (node.protocol === "H2-Reality") {
                             cProxy += `\n    tls: true\n    servername: ${yamlString(thirdSni)}\n    client-fingerprint: chrome\n    network: h2\n    h2-opts:\n      host:\n        - ${yamlString(thirdSni || thirdIp)}\n      path: "/"`;
                        }
                    } else if (node.protocol === "Trojan") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: trojan\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    password: ${yamlString(node.password)}\n    udp: true\n    sni: ${yamlString(thirdSni)}\n    skip-cert-verify: true`;
                    } else if (node.protocol === "AnyTLS") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: anytls\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    password: ${yamlString(node.password)}\n    client-fingerprint: chrome\n    udp: true\n    sni: ${yamlString(thirdSni)}\n    skip-cert-verify: true`;
                    } else if (node.protocol === "Hysteria2") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: hysteria2\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    password: ${yamlString(node.uuid || node.password)}\n    sni: ${yamlString(thirdSni)}\n    skip-cert-verify: true`;
                    } else if (node.protocol === "TUIC") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: tuic\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    uuid: ${yamlString(node.uuid)}\n    password: ${yamlString(node.password)}\n    sni: ${yamlString(thirdSni)}\n    skip-cert-verify: true`;
                    } else if (node.protocol === "SS") {
                        cProxy = `  - name: ${yamlString(node.name || 'TP')}\n    type: ss\n    server: ${yamlString(thirdIp)}\n    port: ${node.port}\n    cipher: ${yamlString(node.uuid)}\n    password: ${yamlString(node.password)}`;
                    }
                    if (cProxy) {
                        clashProxies.push(cProxy);
                        proxyNames.push(yamlString(node.name || 'TP'));
                    }
                }
                } catch(e) {}
            }
        } catch (e) {}

        // Residential SOCKS5 endpoints are runtime proxy records rather than
        // regular protocol nodes, so append them explicitly for the admin.
        // They include shared proxy credentials and must never be exposed to
        // ordinary user subscriptions.
        if (reqUser === adminUser && env.PROXY_USER && env.PROXY_PASS) {
            try {
                const cutoff = Date.now() - 1800000;
                // 住宅节点状态来自融合模块的本地 frp_servers 表，不再读旧表。
                const proxyServers = await frpLocalNodes(db);
                for (const server of proxyServers) {
                    if (Number(server.last_seen || 0) < cutoff) continue;
                    if (ip && server.ip !== ip) continue;
                    let details = [];
                    try { details = JSON.parse(server.details || '[]'); } catch {}
                    const active = details.find(detail => detail?.active && Number.isInteger(Number(detail.port)) && Number(detail.port) >= 1 && Number(detail.port) <= 65535);
                    if (!active) continue;
                    const port = Number(active.port);
                    const serverIp = formatIpForLink(server.ip);
                    const name = `住宅 SOCKS5 | ${active.country || 'AUTO'} | ${server.ip}:${port}`;
                    const encodedCredentials = btoa(unescape(encodeURIComponent(`${env.PROXY_USER}:${env.PROXY_PASS}`)));
                    subLinks.push(`socks5://${encodedCredentials}@${serverIp}:${port}#${encodeURIComponent(name)}`);
                    if (format === 'clash') {
                        clashProxies.push(`  - name: ${yamlString(name)}\n    type: socks5\n    server: ${yamlString(serverIp)}\n    port: ${port}\n    username: ${yamlString(env.PROXY_USER)}\n    password: ${yamlString(env.PROXY_PASS)}\n    udp: true`);
                        proxyNames.push(yamlString(name));
                    }
                }
            } catch (error) {
                console.error('Failed to append residential SOCKS5 subscriptions:', error);
            }
        }

        // --- 若为 Clash 格式，渲染 YAML 返回 ---
        if (format === 'clash') {
            const proxyGroupList = proxyNames.length > 0 ? proxyNames.map(n => `      - ${n}`).join('\n') : '      - DIRECT';
            const hasIPv6 = results.some(n => /:/.test(n.vps_ip)) || clashProxies.some(p => /server:\s*["']?\[/.test(p));
            const clashYaml = `port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
ipv6: ${hasIPv6 ? 'true' : 'false'}
external-controller: 127.0.0.1:9090

proxies:
${clashProxies.join('\n')}

proxy-groups:
  - name: "PROXY"
    type: select
    proxies:
      - "AUTO"
${proxyGroupList}
  - name: "AUTO"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
${proxyGroupList}

rules:
  - MATCH,PROXY
`;
            return new Response(clashYaml, { 
                headers: { 
                    "Content-Type": "text/yaml; charset=utf-8", 
                    "Content-Disposition": "attachment; filename=kui-clash.yaml" 
                }
            });
        }

        // --- 否则走默认的 Base64 普通订阅格式 ---
        return new Response(btoa(unescape(encodeURIComponent(subLinks.join('\n')))), { headers: { "Content-Type": "text/plain; charset=utf-8" }});
    }

    if (action === "login" && method === "POST") {
        await ensureDbSchema(db);
        if (!(await loginAllowed(db, request))) return Response.json({ error: "Too many attempts" }, { status: 429, headers: { 'Retry-After': '900' } });
        let credentials;
        try { credentials = await readJsonBody(request, 8 * 1024); } catch { credentials = {}; }
        const username = String(credentials.username || '').trim(); const password = String(credentials.password || '');
        let valid = false;
        if (username === (env.ADMIN_USERNAME || 'admin')) valid = password.length > 0 && (await timingSafeEqual(password, env.ADMIN_PASSWORD || ''));
        else { const user = await db.prepare('SELECT password FROM users WHERE username = ? AND enable = 1').bind(username).first(); valid = !!user && await passwordMatches(password, user.password); if (valid && /^[0-9a-f]{64}$/i.test(user.password || '')) await db.prepare('UPDATE users SET password = ? WHERE username = ?').bind(await passwordHash(password), username).run(); }
        if (valid) { const token = await sessionToken(); await db.prepare('INSERT INTO auth_sessions (token_hash, username, expires_at) VALUES (?, ?, ?)').bind(await sha256(token), username, Date.now() + 12 * 60 * 60 * 1000).run(); context.waitUntil(db.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(Date.now()).run().catch(() => {})); await db.prepare('DELETE FROM login_throttles WHERE key = ?').bind(loginThrottleKey(request)).run(); return Response.json({ success: true, token, role: username === (env.ADMIN_USERNAME || "admin") ? 'admin' : 'user' }); }
        await recordLoginFailure(db, request);
        return Response.json({ error: "Unauthorized" }, { status: 401 });
    }

    if (action === "logout" && method === "POST") {
        await ensureDbSchema(db);
        const authHeader = request.headers.get("Authorization") || "";
        if (authHeader.startsWith("Bearer ")) {
            const token = authHeader.slice(7);
            if (/^[A-Za-z0-9_-]{32,128}$/.test(token)) {
                await db.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(await sha256(token)).run();
                invalidateSessionCache();
            }
        }
        return Response.json({ success: true });
    }

    if (action === "realtime_auth" && method === "POST") {
        await ensureDbSchema(db);
        const username = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
        const isAdminUser = username === (env.ADMIN_USERNAME || "admin");
        return Response.json({ success: isAdminUser, admin: isAdminUser }, { status: isAdminUser ? 200 : 403, headers: { "Cache-Control": "no-store" } });
    }

    const currentUser = await verifyAuth(request.headers.get("Authorization"), request, db, env, context);
    const isAdmin = currentUser === (env.ADMIN_USERNAME || "admin");
    if (!currentUser) return Response.json({ error: "Unauthorized" }, { status: 401 });

    try {
        if (action === "data") {
            const servers = isAdmin
                ? (await db.prepare("SELECT * FROM servers").all()).results
                : (await db.prepare("SELECT ip, name, cpu, mem, last_report, disk, load, uptime, net_in_speed, net_out_speed, tcp_conn, udp_conn FROM servers").all()).results;
            if (isAdmin) {
                for (const server of servers) {
                    if (!server.agent_token) {
                        server.agent_token = crypto.randomUUID();
                        await db.prepare("UPDATE servers SET agent_token = ? WHERE ip = ? AND agent_token IS NULL").bind(server.agent_token, server.ip).run();
                    }
                }
            }
            const nodes = isAdmin ? (await db.prepare("SELECT * FROM nodes").all()).results : (await db.prepare("SELECT DISTINCT n.* FROM nodes n WHERE n.username = ? OR EXISTS (SELECT 1 FROM user_group_members gm JOIN user_group_resources gr ON gr.group_id = gm.group_id WHERE gm.username = ? AND ((gr.resource_type = 'node' AND gr.resource_id = n.id) OR (gr.resource_type = 'vps' AND gr.resource_id = n.vps_ip)))").bind(currentUser, currentUser).all()).results;
            const users = isAdmin ? (await db.prepare("SELECT * FROM users").all()).results : (await db.prepare("SELECT * FROM users WHERE username = ?").bind(currentUser).all()).results;
            const groups = isAdmin ? (await db.prepare("SELECT g.*, COALESCE((SELECT json_group_array(username) FROM user_group_members WHERE group_id = g.id), '[]') AS members, COALESCE((SELECT json_group_array(json_object('type', resource_type, 'id', resource_id)) FROM user_group_resources WHERE group_id = g.id), '[]') AS resources FROM user_groups g ORDER BY g.name").all()).results : [];
            let siteTitle = "Cluster Gateway"; try { const r = await db.prepare("SELECT val FROM sys_config WHERE key='site_title'").first(); if(r && r.val) siteTitle = r.val; } catch(e){}
            let mySubToken = "";
            if (isAdmin) {
                try {
                    const r = await db.prepare("SELECT val FROM sys_config WHERE key='admin_sub_token'").first();
                    if (r && r.val) mySubToken = r.val;
                    else { mySubToken = crypto.randomUUID(); await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('admin_sub_token', ?, ?)").bind(mySubToken, Date.now()).run(); }
                } catch(e){}
            }
            else { const u = await db.prepare("SELECT sub_token FROM users WHERE username = ?").bind(currentUser).first(); if(u && u.sub_token) mySubToken = u.sub_token; }
            const realtimeUrl = await getRealtimeUrl(env, db);
            return Response.json({ servers, nodes, users, groups, siteTitle, mySubToken, realtimeUrl });
        }
        
        if (action === "settings" && method === "POST" && isAdmin) {
            const { site_title, realtime_url } = await request.json();
            const statements = [];
            if (typeof site_title === 'string' && site_title.trim()) statements.push(db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('site_title', ?, ?)").bind(site_title.trim(), Date.now()));
            if (typeof realtime_url === 'string') {
                const normalized = realtime_url.trim().replace(/\/$/, '');
                if (normalized && !/^https:\/\//i.test(normalized)) return Response.json({ error: 'realtime_url must use https' }, { status: 400 });
                statements.push(db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('realtime_url', ?, ?)").bind(normalized, Date.now()));
            }
            if (!statements.length) return Response.json({ error: 'No supported settings supplied' }, { status: 400 });
            await db.batch(statements);
            return Response.json({ success: true });
        }
        if (action === "user" && params.path[1] === "password" && method === "PUT") { const { password } = await readJsonBody(request, 8 * 1024); if (isAdmin) return Response.json({error: "管理员密码受绝对安全保护，仅可通过 Cloudflare Pages 环境变量修改！"}, {status: 400}); if (String(password || '').length < 12) return Response.json({ error: 'Password must be at least 12 characters' }, { status: 400 }); await db.prepare("UPDATE users SET password = ? WHERE username = ?").bind(await passwordHash(password), currentUser).run(); await db.prepare("DELETE FROM auth_sessions WHERE username = ?").bind(currentUser).run(); invalidateSessionCache(); return Response.json({ success: true }); }
        if (action === "user" && params.path[1] === "sub_token" && method === "PUT") { const newToken = crypto.randomUUID(); if (isAdmin) await db.prepare("INSERT OR REPLACE INTO sys_config (key, val, ts) VALUES ('admin_sub_token', ?, ?)").bind(newToken, Date.now()).run(); else await db.prepare("UPDATE users SET sub_token = ? WHERE username = ?").bind(newToken, currentUser).run(); return Response.json({ success: true, token: newToken }); }
        if (action === "stats" && method === "GET" && isAdmin) { const query = `SELECT strftime('%m-%d', datetime(timestamp / 1000, 'unixepoch', 'localtime')) as day, SUM(delta_bytes) as total_bytes FROM traffic_stats WHERE ip = ? AND timestamp > ? GROUP BY day ORDER BY day ASC`; const { results } = await db.prepare(query).bind(new URL(request.url).searchParams.get("ip"), Date.now() - 604800000).all(); return Response.json(results || []); }
        // 管理员吊销全部登录会话：轮换 ADMIN_PASSWORD secret 后调用，
        // 防止旧密码签发的会话在 D1 中继续有效。
        if (action === "sessions" && method === "DELETE" && isAdmin) { await db.prepare("DELETE FROM auth_sessions").run(); invalidateSessionCache(); return Response.json({ success: true }); }
        
        if (action === "users" && isAdmin) {
            if (method === "POST") { const { username, password, traffic_limit, expire_time } = await readJsonBody(request, 16 * 1024); const safeUser = String(username || '').trim(); if (!/^[A-Za-z0-9_.-]{1,64}$/.test(safeUser) || safeUser === (env.ADMIN_USERNAME || 'admin')) return Response.json({ error: 'Invalid or reserved username' }, { status: 400 }); if (String(password || '').length < 12) return Response.json({ error: 'Password must be at least 12 characters' }, { status: 400 }); if (await db.prepare("SELECT username FROM users WHERE username = ?").bind(safeUser).first()) return Response.json({ error: "User already exists" }, { status: 409 }); const hash = await passwordHash(password); const subToken = crypto.randomUUID(); await db.prepare("INSERT INTO users (username, password, traffic_limit, expire_time, sub_token) VALUES (?, ?, ?, ?, ?)").bind(safeUser, hash, Math.max(0, Number(traffic_limit)||0), Math.max(0, Number(expire_time)||0), subToken).run(); return Response.json({ success: true }); }
            if (method === "PUT") { const { username, enable, reset_traffic } = await request.json(); const statements = []; if (reset_traffic) statements.push(db.prepare("UPDATE users SET traffic_used = 0 WHERE username = ?").bind(username)); if (enable !== undefined) statements.push(db.prepare("UPDATE users SET enable = ? WHERE username = ?").bind(enable, username)); if (statements.length) await db.batch(statements); return Response.json({ success: true }); }
            if (method === "DELETE") { const target = new URL(request.url).searchParams.get("username"); await db.batch([db.prepare("DELETE FROM user_group_members WHERE username = ?").bind(target), db.prepare("DELETE FROM users WHERE username = ?").bind(target), db.prepare("UPDATE nodes SET username = ? WHERE username = ?").bind(currentUser, target)]); return Response.json({ success: true }); }
        }

        if (action === "groups" && isAdmin) {
            if (method === "POST") {
                const data = await readJsonBody(request, 32 * 1024);
                const name = String(data.name || '').trim();
                if (!name || name.length > 64) return Response.json({ error: 'Group name must be 1-64 characters' }, { status: 400 });
                if (await db.prepare("SELECT id FROM user_groups WHERE name = ?").bind(name).first()) return Response.json({ error: 'Group already exists' }, { status: 409 });
                await db.prepare("INSERT INTO user_groups (id, name, created_at) VALUES (?, ?, ?)").bind(crypto.randomUUID(), name, Date.now()).run();
                return Response.json({ success: true });
            }
            if (method === "PUT") {
                const data = await readJsonBody(request, 64 * 1024);
                const groupId = String(data.id || '');
                const group = await db.prepare("SELECT id FROM user_groups WHERE id = ?").bind(groupId).first();
                if (!group) return Response.json({ error: 'Group not found' }, { status: 404 });
                const members = Array.isArray(data.members) ? [...new Set(data.members.map(value => String(value)))].slice(0, 200) : null;
                const resources = Array.isArray(data.resources) ? data.resources.slice(0, 300) : null;
                const statements = [];
                if (members) {
                    for (const username of members) if (!await db.prepare("SELECT username FROM users WHERE username = ?").bind(username).first()) return Response.json({ error: `User not found: ${username}` }, { status: 400 });
                    statements.push(db.prepare("DELETE FROM user_group_members WHERE group_id = ?").bind(groupId));
                    statements.push(...members.map(username => db.prepare("INSERT INTO user_group_members (group_id, username) VALUES (?, ?)").bind(groupId, username)));
                }
                if (resources) {
                    const normalized = [];
                    for (const item of resources) {
                        const type = item?.type === 'vps' ? 'vps' : item?.type === 'node' ? 'node' : '';
                        const id = String(item?.id || '');
                        if (!type || !id) return Response.json({ error: 'Invalid group resource' }, { status: 400 });
                        const exists = type === 'vps' ? await db.prepare("SELECT ip FROM servers WHERE ip = ?").bind(id).first() : await db.prepare("SELECT id FROM nodes WHERE id = ?").bind(id).first();
                        if (!exists) return Response.json({ error: `${type} resource not found` }, { status: 400 });
                        if (!normalized.some(resource => resource.type === type && resource.id === id)) normalized.push({ type, id });
                    }
                    statements.push(db.prepare("DELETE FROM user_group_resources WHERE group_id = ?").bind(groupId));
                    statements.push(...normalized.map(resource => db.prepare("INSERT INTO user_group_resources (group_id, resource_type, resource_id) VALUES (?, ?, ?)").bind(groupId, resource.type, resource.id)));
                }
                if (!statements.length) return Response.json({ error: 'No group changes supplied' }, { status: 400 });
                await db.batch(statements);
                return Response.json({ success: true });
            }
            if (method === "DELETE") { const id = new URL(request.url).searchParams.get("id"); await db.batch([db.prepare("DELETE FROM user_group_members WHERE group_id = ?").bind(id), db.prepare("DELETE FROM user_group_resources WHERE group_id = ?").bind(id), db.prepare("DELETE FROM user_groups WHERE id = ?").bind(id)]); return Response.json({ success: true }); }
        }
        
        if (action === "vps" && isAdmin) {
            await ensureDbSchema(db);
            if (method === "POST") { const { ip, name } = await request.json(); if (!/^[0-9A-Fa-f:.]{2,64}$/.test(String(ip || ''))) return Response.json({ error: 'Invalid VPS IP' }, { status: 400 }); const agentToken = crypto.randomUUID(); const inserted = await db.prepare("INSERT INTO servers (ip, name, alert_sent, agent_token) SELECT ?, ?, 0, ? WHERE (SELECT COUNT(*) FROM servers) < 100 ON CONFLICT(ip) DO NOTHING RETURNING ip").bind(ip, String(name || ip).slice(0, 100), agentToken).first(); if (!inserted) { if (await db.prepare('SELECT ip FROM servers WHERE ip = ?').bind(ip).first()) return Response.json({ error: 'VPS already exists' }, { status: 409 }); return Response.json({ error: "当前版本最多管理 100 台 VPS" }, { status: 409 }); } return Response.json({ success: true }); }
            if (method === "PUT") { const data = await request.json(); const ip = data.ip; if (!ip) return Response.json({ error: 'IP required' }, { status: 400 }); if (data.egress_mode === undefined) return Response.json({ error: 'Use egress_mode to configure node egress' }, { status: 400 }); const modes = ['native', 'residential', 'warp_ipv4', 'warp_ipv6', 'warp_dual', 'socks5']; if (!modes.includes(data.egress_mode)) return Response.json({ error: 'Invalid egress mode' }, { status: 400 }); if (data.egress_mode === 'residential' && (!env.PROXY_USER || !env.PROXY_PASS)) return Response.json({ error: '未配置 PROXY_USER / PROXY_PASS（住宅 SOCKS5 凭据）' }, { status: 503 }); const proxyMode = data.proxy_mode === 'selective' ? 'selective' : 'global'; const proxyCategories = data.proxy_categories ? String(data.proxy_categories) : ''; const socks5Addr = String(data.socks5_addr || '').slice(0, 128); const socks5Port = Math.min(65535, Math.max(1, Number(data.socks5_port) || 0)); const socks5User = String(data.socks5_user || '').slice(0, 64); const socks5Pass = String(data.socks5_pass || '').slice(0, 128); let changed; if (data.egress_mode === 'socks5' && socks5Addr && socks5Port) { changed = await db.prepare("UPDATE servers SET egress_mode = ?, egress_revision = egress_revision + 1, egress_status = 'pending', egress_error = '', proxy_mode = ?, proxy_categories = ?, socks5_addr = ?, socks5_port = ?, socks5_user = ?, socks5_pass = ? WHERE ip = ? RETURNING egress_revision").bind(data.egress_mode, proxyMode, proxyCategories, socks5Addr, socks5Port, socks5User, socks5Pass, ip).first(); } else { changed = await db.prepare("UPDATE servers SET egress_mode = ?, egress_revision = egress_revision + 1, egress_status = 'pending', egress_error = '', proxy_mode = ?, proxy_categories = ? WHERE ip = ? RETURNING egress_revision").bind(data.egress_mode, proxyMode, proxyCategories, ip).first(); } if (!changed) return Response.json({ error: 'VPS not found' }, { status: 404 }); context.waitUntil(notifyRealtimeVps(env, db, ip).catch(() => {})); return Response.json({ success: true, ip, egress_mode: data.egress_mode, egress_revision: Number(changed.egress_revision), egress_status: 'pending', proxy_mode: proxyMode, proxy_categories: proxyCategories, socks5_addr: data.egress_mode === 'socks5' ? socks5Addr : '', socks5_port: data.egress_mode === 'socks5' ? socks5Port : 0 }); }
            if (method === "DELETE") { 
                const ip = new URL(request.url).searchParams.get("ip"); 
                await db.batch([ db.prepare("DELETE FROM user_group_resources WHERE resource_type = 'vps' AND resource_id = ?").bind(ip), db.prepare("DELETE FROM user_group_resources WHERE resource_type = 'node' AND resource_id IN (SELECT id FROM nodes WHERE vps_ip = ?)").bind(ip), db.prepare("DELETE FROM nodes WHERE vps_ip = ?").bind(ip), db.prepare("DELETE FROM traffic_stats WHERE ip = ?").bind(ip), db.prepare("DELETE FROM servers WHERE ip = ?").bind(ip), db.prepare("DELETE FROM probe_servers WHERE id = ?").bind(ip), db.prepare("DELETE FROM proxy_ctrl_servers WHERE ip = ?").bind(ip), db.prepare("DELETE FROM server_logs WHERE ip = ?").bind(ip), db.prepare("DELETE FROM probe_settings WHERE key = ?").bind(`proxy_slot_map_${ip}`) ]);
                return Response.json({ success: true }); 
            }
        }

        if (action === "nodes" && isAdmin) {
            if (method === "POST") { const n = await request.json(); const protocols = ['VLESS','XTLS-Reality','Reality','Hysteria2','TUIC','Trojan','H2-Reality','gRPC-Reality','AnyTLS','Naive','Socks5','VLESS-Argo','dokodemo-door']; if (!/^[A-Za-z0-9_-]{1,64}$/.test(String(n.id || ''))) return Response.json({ error: 'Invalid node id' }, { status: 400 }); if (!protocols.includes(n.protocol)) return Response.json({ error: 'Invalid protocol' }, { status: 400 }); if (!Number.isInteger(Number(n.port)) || Number(n.port) < 1 || Number(n.port) > 65535) return Response.json({ error: 'Invalid port' }, { status: 400 }); if (!(await db.prepare('SELECT ip FROM servers WHERE ip = ?').bind(n.vps_ip).first())) return Response.json({ error: 'VPS not found' }, { status: 404 }); if (n.protocol === 'dokodemo-door') { if (!['internal','external'].includes(n.relay_type)) return Response.json({error:'Invalid relay type'},{status:400}); if (n.relay_type === 'external' && (!String(n.target_ip||'').trim() || !Number.isInteger(Number(n.target_port)) || Number(n.target_port)<1 || Number(n.target_port)>65535)) return Response.json({error:'Invalid relay target'},{status:400}); if (n.relay_type === 'internal' && !(await db.prepare('SELECT id FROM nodes WHERE id = ? AND vps_ip = ?').bind(n.target_id,n.vps_ip).first())) return Response.json({error:'Internal relay target not found on VPS'},{status:400}); } if (await db.prepare("SELECT id FROM nodes WHERE id = ?").bind(n.id).first()) return Response.json({ error: "Node already exists" }, { status: 409 }); let nodeUser = n.username || currentUser; if (nodeUser === 'admin') nodeUser = currentUser; await db.prepare(`INSERT INTO nodes (id, uuid, vps_ip, protocol, port, sni, private_key, public_key, short_id, relay_type, target_ip, target_port, target_id, enable, traffic_used, traffic_limit, expire_time, username, network) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(n.id, n.uuid, n.vps_ip, n.protocol, Number(n.port), n.sni||null, n.private_key||null, n.public_key||null, n.short_id||null, n.relay_type||null, n.target_ip||null, n.target_port||null, n.target_id||null, 1, 0, Math.max(0, Number(n.traffic_limit)||0), Math.max(0, Number(n.expire_time)||0), nodeUser, n.network||'tcp').run(); context.waitUntil(notifyRealtimeVps(env, db, n.vps_ip).catch(()=>{})); return Response.json({ success: true }); }
            if (method === "PUT") { const { id, enable, reset_traffic } = await request.json(); const node = await db.prepare('SELECT vps_ip FROM nodes WHERE id = ?').bind(id).first(); if (!node) return Response.json({ error: 'Node not found' }, { status: 404 }); const statements = []; if (reset_traffic) statements.push(db.prepare("UPDATE nodes SET traffic_used = 0 WHERE id = ?").bind(id)); if (enable !== undefined) statements.push(db.prepare("UPDATE nodes SET enable = ? WHERE id = ?").bind(enable ? 1 : 0, id)); if (statements.length) await db.batch(statements); context.waitUntil(notifyRealtimeVps(env, db, node.vps_ip).catch(()=>{})); return Response.json({ success: true }); }
            if (method === "DELETE") { const id = new URL(request.url).searchParams.get("id"); const node = await db.prepare('SELECT vps_ip FROM nodes WHERE id = ?').bind(id).first(); await db.batch([db.prepare("DELETE FROM user_group_resources WHERE resource_type = 'node' AND resource_id = ?").bind(id), db.prepare("DELETE FROM nodes WHERE id = ?").bind(id)]); if (node) context.waitUntil(notifyRealtimeVps(env, db, node.vps_ip).catch(()=>{})); return Response.json({ success: true }); }
        }

    if (action === "thirdparty" && isAdmin) {
            await ensureDbSchema(db);
            if (method === "POST") {
                const { name, url } = await readJsonBody(request, 16 * 1024);
                if (!url) return Response.json({ error: "请填写订阅链接" }, { status: 400 });
                let subscriptionUrl;
                try { subscriptionUrl = validateSubscriptionUrl(url); } catch (error) { return Response.json({ error: error.message || "订阅链接格式无效" }, { status: 400 }); }
                const id = crypto.randomUUID();
                const now = Date.now();
                let parsedCount = 0; let parseDebug = {};
                try {
                    const res = await fetchPublicSubscription(subscriptionUrl.toString());
                    const text = await readBoundedText(res);
                    const result = await parseThirdPartySubscription(text);
                    const { nodes, protocolCounts, debug } = result;
                    parseDebug = { protocolCounts, debug };
                    await db.prepare("INSERT INTO third_party_subscriptions (id, name, url, added_at, last_fetched_at) VALUES (?, ?, ?, ?, ?)" ).bind(id, String(name || '第三方订阅').slice(0, 100), subscriptionUrl.toString(), now, now).run();
                    if (nodes.length > 0) {
                        const stmts = nodes.map(n => db.prepare("INSERT INTO third_party_nodes (id, subscription_id, name, protocol, address, port, uuid, password, sni, public_key, short_id, flow, network, host, path, extra, enable, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(n.id, id, n.name, n.protocol, n.address, n.port, n.uuid || '', n.password || '', n.sni || '', n.public_key || '', n.short_id || '', n.flow || '', n.network || '', n.host || '', n.path || '', n.extra || '', 1, now));
                        await chunkBatch(db, stmts);
                        parsedCount = nodes.length;
                    }
                } catch (e) { console.error("解析第三方订阅失败:", e); return Response.json({ error: (e && e.message) || '订阅导入失败' }, { status: 400 }); }
                await db.prepare("UPDATE third_party_subscriptions SET last_fetched_at = ? WHERE id = ?").bind(Date.now(), id).run();
                return Response.json({ success: true, id, parsedCount, debug: parseDebug });
            }
            if (method === "GET") {
                const { results } = await db.prepare("SELECT s.*, COUNT(n.id) as node_count FROM third_party_subscriptions s LEFT JOIN third_party_nodes n ON s.id = n.subscription_id GROUP BY s.id ORDER BY s.added_at DESC").all();
                return Response.json(results || []);
            }
            if (method === "PUT") {
                const { id, enable } = await request.json();
                if (id) await db.prepare("UPDATE third_party_subscriptions SET is_enable = ? WHERE id = ?").bind(enable ? 1 : 0, id).run();
                if (id) await db.prepare("UPDATE third_party_nodes SET enable = ? WHERE subscription_id = ?").bind(enable ? 1 : 0, id).run();
                return Response.json({ success: true });
            }
            if (method === "DELETE") {
                const subId = new URL(request.url).searchParams.get("id");
                if (!subId) return Response.json({ error: "缺少订阅ID" }, { status: 400 });
                await db.prepare("DELETE FROM third_party_subscriptions WHERE id = ?").bind(subId).run();
                await db.prepare("DELETE FROM third_party_nodes WHERE subscription_id = ?").bind(subId).run();
                return Response.json({ success: true });
            }
        }

        return new Response("Not Found", { status: 404 });
    } catch (err) {
        const msg = (err && err.message) ? err.message : String(err);
        // 兜底捕获，杜绝未处理异常导致的 Cloudflare 1101
        return new Response(JSON.stringify({ error: "SERVER_ERR: " + msg }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

export async function onRequestScheduled(context) {
    try { await checkOfflineServers(context.env); } catch (error) { console.error('[cron] offline check failed:', error); throw error; }
}
