// Supabase Edge Function: send-email
// 契约（前端 sendEmail()）：POST { to, subject, body }，Authorization: Bearer <anon key>
// body 为 HTML 字符串；成功返回 200 {ok:true}，失败返回 4xx/5xx {ok:false,error,message}
// 部署前需配置 Secrets：SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / SMTP_FROM
//   例（QQ 邮箱）：SMTP_HOST=smtp.qq.com  SMTP_PORT=465  SMTP_USER=xxx@qq.com
//                 SMTP_PASS=QQ邮箱授权码（设置→账户→开启SMTP获取）  SMTP_FROM=医路相伴 <xxx@qq.com>

import nodemailer from 'npm:nodemailer@6.9.13';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type, apikey, x-client-info, prefer',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ ok: false, error: 'method' }, 405);

  try {
    const host = Deno.env.get('SMTP_HOST') || '';
    const port = Number(Deno.env.get('SMTP_PORT') || '465');
    const user = Deno.env.get('SMTP_USER') || '';
    const pass = Deno.env.get('SMTP_PASS') || '';
    const from = Deno.env.get('SMTP_FROM') || user;
    if (!host || !user || !pass) {
      return json({ ok: false, error: 'smtp_not_configured', message: '请在 Edge Functions Secrets 配置 SMTP_HOST/SMTP_USER/SMTP_PASS/SMTP_FROM' }, 500);
    }

    let payload = {};
    try { payload = await req.json(); } catch (_) { return json({ ok: false, error: 'badjson' }, 400); }

    const to = String(payload.to || '').trim();
    const subject = String(payload.subject || '').slice(0, 200);
    const body = String(payload.body || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) return json({ ok: false, error: 'bad_to' }, 400);
    if (!subject) return json({ ok: false, error: 'bad_subject' }, 400);

    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
    });

    await transporter.sendMail({ from, to, subject, html: body });
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: 'send_failed', message: String((e && e.message) || e) }, 500);
  }
});
