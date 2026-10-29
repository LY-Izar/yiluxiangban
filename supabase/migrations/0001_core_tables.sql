-- =====================================================================
-- 0001 核心表重建（全新数据库第一步执行）
-- 依据：index.html 前端调用契约 + security_session_tokens.sql 依赖清单
-- 本文件只建表/索引/默认 RLS 锁定；具体策略由 security_session_tokens.sql 统一创建
-- 兼容：可重复执行（if not exists）
-- =====================================================================

-- 1) 用户表（id=用户名，pass_hash 由 Edge Function ylxb-auth 写入）
create table if not exists public.users (
  id                 text primary key,
  pass_hash          text,
  family_code        text,
  role               text,
  bound_elder_code   text,
  bound_elder_codes  text[] default '{}'::text[],
  email              text,
  email_remind       boolean default false,
  is_admin           boolean default false,
  admin_level        text default 'none',
  sub_perms          jsonb default '{}'::jsonb,
  created_at         timestamptz default now(),
  updated_at         timestamptz default now()
);

-- 2) 心跳会话表（heartbeat_touch 写入；失联关怀信号读取）
create table if not exists public.user_sessions (
  user_id      text not null,
  role         text not null default 'elder',
  last_seen_at timestamptz default now(),
  primary key (user_id, role)
);
alter table public.user_sessions enable row level security;
drop policy if exists us_select on public.user_sessions;
create policy us_select on public.user_sessions for select using (true);
-- 写入仅经 heartbeat_touch（security definer），无 insert/update 策略 = 直连一律拒绝

-- 3) 家庭事件流
create table if not exists public.events (
  id          bigint generated always as identity primary key,
  family_code text,
  type        text,
  text        text,
  created_at  timestamptz default now()
);
create index if not exists events_family_created_idx on public.events (family_code, created_at desc);

-- 4) 系统公告（软删除：deleted=true 不再展示）
create table if not exists public.announcements (
  id            text primary key,
  title         text default '',
  body          text default '',
  level         text default 'normal',
  popup         text default 'never',
  pin           boolean default false,
  active_from   timestamptz,
  active_to     timestamptz,
  email_sent    boolean default false,
  email_sent_ts bigint,
  email_count   int default 0,
  email_fail    int default 0,
  created_by    text,
  updated_by    text,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now(),
  ts            bigint default (extract(epoch from now()) * 1000)::bigint,
  deleted       boolean default false
);

-- 5) 应用设置（key=maintenance 等）
create table if not exists public.app_settings (
  key        text primary key,
  value      jsonb default '{}'::jsonb,
  updated_at timestamptz default now()
);

-- 6) 用药日志（前端 on_conflict=username,med_ref,scheduled_date,scheduled_time）
create table if not exists public.medication_logs (
  id             bigint generated always as identity primary key,
  username       text not null,
  med_ref        text not null,
  med_name       text,
  scheduled_date date not null,
  scheduled_time text not null,
  status         text default 'taken',
  actual_time    timestamptz,
  actual_hhmm    text,
  late_minutes   int default 0,
  reminded_count int default 0,
  created_at     timestamptz default now(),
  constraint medication_logs_unique unique (username, med_ref, scheduled_date, scheduled_time)
);
create index if not exists medlog_user_date_idx on public.medication_logs (username, scheduled_date desc);

-- 7) 健康指标
create table if not exists public.health_metrics (
  id           bigint generated always as identity primary key,
  username     text not null,
  disease_type text,
  metric_type  text,
  value1       numeric,
  value2       numeric,
  measured_at  timestamptz,
  note         text,
  created_at   timestamptz default now()
);
create index if not exists metrics_user_time_idx on public.health_metrics (username, measured_at desc);

-- 8) 慢病档案（id 由前端生成 Date.now()）
create table if not exists public.chronic_profiles (
  id            bigint primary key,
  username      text not null,
  disease_type  text,
  diagnose_date date,
  hospital      text,
  target_json   text,
  created_at    timestamptz default now()
);

-- 9) 慢病预警
create table if not exists public.chronic_alerts (
  id           bigint generated always as identity primary key,
  username     text not null,
  disease_type text,
  alert_level  text default 'normal',
  title        text,
  message      text,
  is_read      boolean default false,
  created_at   timestamptz default now()
);
create index if not exists alerts_user_unread_idx on public.chronic_alerts (username, is_read, created_at desc);

-- 10) 复诊提醒
create table if not exists public.follow_ups (
  id                   bigint generated always as identity primary key,
  username             text not null,
  disease_type         text,
  next_visit_date      date,
  department           text,
  hospital             text,
  notes                text,
  reminder_days_before int default 1,
  created_at           timestamptz default now()
);

-- 11) 权限申请审批单（前端直插 + super 审批）
create table if not exists public.pending_approvals (
  id          bigint generated always as identity primary key,
  token       text unique not null,
  operator    text,
  perm_key    text,
  action_desc text,
  payload     jsonb,
  status      text default 'pending',
  created_at  timestamptz default now(),
  expires_at  timestamptz,
  resolved_by text,
  resolved_at timestamptz
);

-- 12) 家属绑定关系（前端不直用；权威来源为 users.bound_elder_codes）
create table if not exists public.family_bindings (
  id         uuid primary key default gen_random_uuid(),
  family_id  text,
  username   text,
  created_at timestamptz default now()
);

-- 13) 管理操作审计日志（只增防篡改：触发器见 audit_tamper_guard.sql）
create table if not exists public.admin_audit_logs (
  id      bigint generated always as identity primary key,
  action  text,
  operator text,
  payload jsonb,
  ts      timestamptz default now()
);

-- 14) 备份落库（admin_save_backup/admin_get_backup）
create table if not exists public.system_settings (
  key        text primary key,
  value      text,
  updated_at timestamptz default now()
);

-- 15) 维护快照（security_session_tokens.sql 引用；预留表）
create table if not exists public.maintenance_snapshot (
  id         bigint generated always as identity primary key,
  created_at timestamptz default now(),
  payload    jsonb
);

-- ---------- 全部业务表先启用 RLS（默认拒绝一切；策略由 security_session_tokens.sql 创建） ----------
alter table public.users             enable row level security;
alter table public.events            enable row level security;
alter table public.announcements     enable row level security;
alter table public.app_settings      enable row level security;
alter table public.medication_logs   enable row level security;
alter table public.health_metrics    enable row level security;
alter table public.chronic_profiles  enable row level security;
alter table public.chronic_alerts    enable row level security;
alter table public.follow_ups        enable row level security;
alter table public.pending_approvals enable row level security;
alter table public.family_bindings   enable row level security;
alter table public.admin_audit_logs  enable row level security;
alter table public.system_settings   enable row level security;
alter table public.maintenance_snapshot enable row level security;

select '0001-core-tables-OK' as 部署标记;
