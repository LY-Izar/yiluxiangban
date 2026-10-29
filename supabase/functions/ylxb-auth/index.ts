import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type, apikey, x-client-info, prefer',
};

const ITERATIONS = 100000;

function b64url(bytes) {
  let s = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  const b = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(b, c => c.charCodeAt(0));
}
function utf8(s) { return new TextEncoder().encode(s); }
function hex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }

async function pbkdf2Hash(password, saltB64) {
  const salt = saltB64 ? b64urlDecode(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, key, 256);
  return 'pbkdf2$' + ITERATIONS + '$' + b64url(salt) + '$' + b64url(bits);
}

async function sha256Hex(text) {
  return hex(await crypto.subtle.digest('SHA-256', utf8(text)));
}

async function verifyStored(stored, password) {
  try {
    if (stored.startsWith('pbkdf2$')) {
      const [, iter, salt, hash] = stored.split('$');
      const key = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveBits']);
      const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64urlDecode(salt), iterations: Number(iter) }, key, 256);
      return b64url(bits) === hash;
    }
    return stored === await sha256Hex(password);
  } catch (_) { return false; }
}

async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, utf8(data)));
}

async function jwtSign(payload, secret) {
  const h = b64url(utf8(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
  const p = b64url(utf8(JSON.stringify(payload)));
  return h + '.' + p + '.' + await hmacSign(h + '.' + p, secret);
}

async function jwtVerify(token, secret) {
  try {
    const [h, p, sig] = token.split('.');
    if (!h || !p || !sig) return null;
    if ((await hmacSign(h + '.' + p, secret)) !== sig) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) { return null; }
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ ok: false, error: 'method' }, 405);
  try {
    return await handle(req);
  } catch (e) {
    return json({ ok: false, error: 'exception', message: String((e && (e as Error).message) || e) }, 500);
  }
});

async function handle(req: Request): Promise<Response> {
  const secret = Deno.env.get('YLXB_JWT_SECRET') || Deno.env.get('SUPABASE_JWT_SECRET') || '';

  let body = {};
  try { body = await req.json(); } catch (_) { return json({ ok: false, error: 'badjson' }, 400); }
  const action = body.action || '';

  if (action === 'check') return json({ ok: true, live: true });

  if (!secret) {
    return json({ ok: false, error: 'missing_jwt_secret', message: '请在 Supabase Dashboard → Edge Functions → Secrets 中添加 YLXB_JWT_SECRET（值=项目设置→API→JWT Secret）' }, 500);
  }
  const admin = createClient(
    Deno.env.get('SUPABASE_URL') || '',
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '',
    { auth: { persistSession: false } },
  );
  const username = String(body.username || '').trim();
  const password = String(body.password || '');

  if (action === 'lookup') {
    const authz = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const claims = authz ? await jwtVerify(authz, secret) : null;
    if (!claims) return json({ ok: false, error: 'unauthorized' }, 401);
    const code = String(body.code || '');
    if (!/^\d{6}$/.test(code)) return json({ ok: false, error: 'badcode' }, 400);
    const { data, error } = await admin.from('users').select('id,family_code,role').eq('family_code', code).limit(1);
    if (error) return json({ ok: false, error: 'db' }, 500);
    if (!data || !data.length) return json({ ok: false, error: 'notfound' }, 404);
    return json({ ok: true, elder: { id: data[0].id, family_code: data[0].family_code } });
  }

  if (action === 'rename') {
    const authz = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const claims = authz ? await jwtVerify(authz, secret) : null;
    if (!claims) return json({ ok: false, error: 'unauthorized' }, 401);
    const newU = String(body.new_username || '').trim();
    if (!/^[A-Za-z0-9_\u4e00-\u9fa5]{3,30}$/.test(newU) || newU.startsWith('test_')) return json({ ok: false, error: 'badname' }, 400);
    const { data: exists } = await admin.from('users').select('id').eq('id', newU).limit(1);
    if (exists && exists.length) return json({ ok: false, error: 'taken' }, 409);
    for (const t of ['chronic_profiles', 'chronic_alerts', 'health_metrics', 'medication_logs', 'follow_ups', 'events', 'family_bindings']) {
      await admin.from(t).update({ username: newU }).eq('username', claims.sub);
    }
    await admin.from('family_bindings').update({ family_id: newU }).eq('family_id', claims.sub);
    const { error: upErr } = await admin.from('users').update({ id: newU }).eq('id', claims.sub);
    if (upErr) return json({ ok: false, error: 'db' }, 500);
    const token = await jwtSign({ sub: newU, role: 'authenticated', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7 * 86400, ylxb_admin_level: claims.ylxb_admin_level || 'none' }, secret);
    return json({ ok: true, token, username: newU });
  }

  if (!username || !password) return json({ ok: false, error: 'missing' }, 400);
  if (username.startsWith('test_')) return json({ ok: false, error: 'reserved' }, 400);

  if (action === 'register') {
    if (password.length < 6) return json({ ok: false, error: 'weakpass' }, 400);
    const { data: exists } = await admin.from('users').select('id').eq('id', username).limit(1);
    if (exists && exists.length) return json({ ok: false, error: 'taken' }, 409);
    const familyCode = String(Math.floor(100000 + Math.random() * 900000));
    const hash = await pbkdf2Hash(password, null);
    const { error: insErr } = await admin.from('users').insert({
      id: username, pass_hash: hash, family_code: familyCode,
      role: body.role === 'family' ? 'family' : 'elder',
      email: body.email || null, email_remind: false,
    });
    if (insErr) {
      if (String(insErr.code || '') === '23505') return json({ ok: false, error: 'taken' }, 409);
      return json({ ok: false, error: 'db:' + (insErr.message || 'unknown') }, 500);
    }
    const { data: prof } = await admin.from('users').select('id,role,family_code,email,email_remind,is_admin,admin_level,sub_perms,bound_elder_codes').eq('id', username).limit(1);
    const p = (prof && prof[0]) || {};
    const token = await jwtSign({ sub: username, role: 'authenticated', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7 * 86400, ylxb_admin_level: p.admin_level || 'none' }, secret);
    return json({ ok: true, token, profile: p, family_code: p.family_code || familyCode });
  }

  if (action === 'login') {
    const { data, error } = await admin.from('users').select('id,pass_hash,role,family_code,email,email_remind,is_admin,admin_level,sub_perms,bound_elder_codes,bound_elder_code').eq('id', username).limit(1);
    if (error) return json({ ok: false, error: 'db' }, 500);
    if (!data || !data.length) return json({ ok: false, error: 'wrongpass' }, 401);
    const u = data[0];
    if (!u.pass_hash || !String(u.pass_hash).includes('$')) {
      const legacyOk = await verifyStored(u.pass_hash, password);
      if (!legacyOk) return json({ ok: false, error: 'wrongpass' }, 401);
      const upgraded = await pbkdf2Hash(password, null);
      await admin.from('users').update({ pass_hash: upgraded }).eq('id', username);
    } else {
      const ok = await verifyStored(u.pass_hash, password);
      if (!ok) return json({ ok: false, error: 'wrongpass' }, 401);
    }
    const lvl = u.admin_level || (u.is_admin ? 'sub' : 'none');
    const token = await jwtSign({ sub: username, role: 'authenticated', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 7 * 86400, ylxb_admin_level: lvl }, secret);
    return json({ ok: true, token, profile: u, family_code: u.family_code });
  }

  return json({ ok: false, error: 'unknown_action' }, 400);
}