-- =====================================================================
-- 0003 管理台 RPC 全量重建（第三步执行）
-- 前置：0001 核心表 + 0002 核心 RPC + security_session_tokens.sql
--       （_adm_assert / _adm_require_super / _ylxb_sub 均来自后者）
-- 签名依据：前端 adminRPC() 实际传参（命名参数必须一字不差）
-- 守卫：用户/权限类 = _adm_require_super（仅最高管理员）；公告/维护/统计 = _adm_assert（super 或 sub）
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- 1) 用户列表 ----------
create or replace function public.admin_list_users(
  lim  int default 500,
  offs int default 0,
  kw   text default ''
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_rows  jsonb;
  v_total bigint;
  v_kw    text := btrim(coalesce(kw, ''));
begin
  perform public._adm_assert();
  select count(*) into v_total from users
    where v_kw = '' or id ilike '%' || v_kw || '%' or coalesce(email,'') ilike '%' || v_kw || '%';
  select coalesce(jsonb_agg(t), '[]'::jsonb) into v_rows
    from (
      select id, role, family_code, email, email_remind,
             is_admin, admin_level, sub_perms,
             bound_elder_code, bound_elder_codes,
             created_at, updated_at
        from users
        where v_kw = '' or id ilike '%' || v_kw || '%' or coalesce(email,'') ilike '%' || v_kw || '%'
        order by created_at desc
        limit least(greatest(coalesce(lim, 500), 1), 1000)
        offset greatest(coalesce(offs, 0), 0)
    ) t;
  return jsonb_build_object('ok', true, 'rows', v_rows, 'total', v_total);
end $$;

-- ---------- 2) 保存次管权限（可同时晋升为次管） ----------
create or replace function public.admin_set_sub_perms(
  target_id text default null,
  perms     jsonb default null,
  promote   boolean default false
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_lvl text;
begin
  perform public._adm_require_super();
  if coalesce(target_id, '') = '' then
    raise exception '缺少目标账号';
  end if;
  select admin_level into v_lvl from users where id = target_id;
  if v_lvl is null then
    raise exception '目标账号不存在';
  end if;
  if v_lvl = 'super' then
    raise exception '不能修改最高管理员的授权';
  end if;
  update users set sub_perms = coalesce(perms, '{}'::jsonb), updated_at = now() where id = target_id;
  if promote then
    update users set is_admin = true, admin_level = 'sub', updated_at = now() where id = target_id;
  end if;
  return jsonb_build_object('ok', true, 'target_id', target_id, 'perms', perms, 'promoted', promote);
end $$;

-- ---------- 3) 设为/撤销次级管理员 ----------
create or replace function public.admin_set_admin(
  target_id   text default null,
  make_admin  boolean default true
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_lvl text;
begin
  perform public._adm_require_super();
  if coalesce(target_id, '') = '' then
    raise exception '缺少目标账号';
  end if;
  select admin_level into v_lvl from users where id = target_id;
  if v_lvl is null then
    raise exception '目标账号不存在';
  end if;
  if v_lvl = 'super' then
    raise exception '不能修改最高管理员身份';
  end if;
  if make_admin then
    update users set is_admin = true, admin_level = 'sub', updated_at = now() where id = target_id;
    return jsonb_build_object('ok', true, 'target_id', target_id, 'is_admin', true, 'admin_level', 'sub', 'note', '已设为次级管理员');
  else
    update users set is_admin = false, admin_level = 'none', sub_perms = '{}'::jsonb, updated_at = now() where id = target_id;
    return jsonb_build_object('ok', true, 'target_id', target_id, 'is_admin', false, 'admin_level', 'none', 'note', '已撤销管理员');
  end if;
end $$;

-- ---------- 4) 重置用户密码（存 SHA-256，下次经 ylxb-auth 登录自动升级 PBKDF2） ----------
create or replace function public.admin_reset_user_pass(
  target_id text default null,
  new_pass  text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_sub text;
begin
  perform public._adm_require_super();
  if coalesce(target_id, '') = '' then
    raise exception '缺少目标账号';
  end if;
  if coalesce(new_pass, '') is null or length(new_pass) < 6 then
    raise exception '新密码至少 6 位';
  end if;
  v_sub := public._ylxb_sub();
  if not exists (select 1 from users where id = target_id) then
    raise exception '目标账号不存在';
  end if;
  if (select admin_level from users where id = target_id) = 'super' and target_id <> v_sub then
    raise exception '不能重置最高管理员密码';
  end if;
  update users
    set pass_hash = encode(extensions.digest(new_pass, 'sha256'), 'hex'), updated_at = now()
    where id = target_id;
  return jsonb_build_object('ok', true, 'target_id', target_id);
end $$;

-- ---------- 5) 删除用户账号及其全部数据 ----------
create or replace function public.admin_delete_user(
  target_id text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_family text;
begin
  perform public._adm_require_super();
  if coalesce(target_id, '') = '' then
    raise exception '缺少目标账号';
  end if;
  select family_code into v_family from users where id = target_id;
  if v_family is null then
    raise exception '目标账号不存在';
  end if;
  if (select admin_level from users where id = target_id) = 'super' then
    raise exception '不能删除最高管理员账号';
  end if;
  delete from medication_logs  where username = target_id;
  delete from health_metrics   where username = target_id;
  delete from chronic_profiles where username = target_id;
  delete from chronic_alerts   where username = target_id;
  delete from follow_ups       where username = target_id;
  delete from family_ocr_rules where elder_username = target_id;
  delete from user_sessions    where user_id = target_id;
  delete from pending_approvals where operator = target_id;
  delete from family_bindings  where username = target_id or family_id = target_id;
  delete from events           where family_code = v_family;
  delete from users            where id = target_id;
  return jsonb_build_object('ok', true, 'deleted_users', 1);
end $$;

-- ---------- 6) 邮箱覆盖率统计 ----------
create or replace function public.admin_count_emails(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_total bigint; v_with bigint;
begin
  perform public._adm_assert(caller);
  select count(*), count(*) filter (where coalesce(email, '') <> '') into v_total, v_with from users;
  return jsonb_build_object(
    'ok', true,
    'total_users', v_total,
    'with_email', v_with,
    'without_email', v_total - v_with,
    'bind_rate', case when v_total = 0 then 0 else round(v_with * 100.0 / v_total, 2) end
  );
end $$;

-- ---------- 7) 数据库概况计数（8 张业务表精确计数） ----------
create or replace function public.admin_table_counts(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_counts jsonb := '{}'::jsonb;
begin
  perform public._adm_assert(caller);
  select jsonb_build_object(
    'users',            (select count(*) from users),
    'chronic_profiles', (select count(*) from chronic_profiles),
    'chronic_alerts',   (select count(*) from chronic_alerts),
    'health_metrics',   (select count(*) from health_metrics),
    'medication_logs',  (select count(*) from medication_logs),
    'follow_ups',       (select count(*) from follow_ups),
    'events',           (select count(*) from events),
    'family_bindings',  (select count(*) from family_bindings)
  ) into v_counts;
  return jsonb_build_object('ok', true, 'counts', v_counts);
end $$;

-- ---------- 8) 存储空间（500MB 档；remaining_pct 单位=剩余 MB，与前端阈值文案一致） ----------
create or replace function public.admin_get_db_size(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_size  bigint;
  v_limit bigint := 524288000; -- 500MB
begin
  perform public._adm_assert(caller);
  v_size := pg_database_size(current_database());
  return jsonb_build_object(
    'ok', true,
    'database_size', v_size,
    'remaining_pct', round(greatest(0, (v_limit - v_size)) / 1048576.0, 2),
    'used_pct', round(v_size * 100.0 / v_limit, 2)
  );
end $$;

-- ---------- 9) 删除指定用户的数据类别（保留账号） ----------
create or replace function public.admin_delete_user_data(
  target_id  text default null,
  categories text[] default '{}'
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_family text;
  v_deleted jsonb := '{}'::jsonb;
  v_c text;
  v_n int;
begin
  perform public._adm_require_super();
  if coalesce(target_id, '') = '' then
    raise exception '缺少目标账号';
  end if;
  select family_code into v_family from users where id = target_id;
  if v_family is null then
    raise exception '目标账号不存在';
  end if;
  foreach v_c in array categories loop
    case v_c
      when 'chronic_profiles' then
        delete from chronic_profiles where username = target_id; get diagnostics v_n = row_count;
      when 'chronic_alerts' then
        delete from chronic_alerts where username = target_id; get diagnostics v_n = row_count;
      when 'health_metrics' then
        delete from health_metrics where username = target_id; get diagnostics v_n = row_count;
      when 'medication_logs' then
        delete from medication_logs where username = target_id; get diagnostics v_n = row_count;
      when 'follow_ups' then
        delete from follow_ups where username = target_id; get diagnostics v_n = row_count;
      when 'events' then
        delete from events where family_code = v_family; get diagnostics v_n = row_count;
      when 'family_bindings' then
        delete from family_bindings where username = target_id or family_id = target_id; get diagnostics v_n = row_count;
      else
        v_n := 0;
    end case;
    v_deleted := v_deleted || jsonb_build_object(v_c, v_n);
  end loop;
  return jsonb_build_object('ok', true, 'deleted', v_deleted);
end $$;

-- ---------- 10) 清空整张表（白名单 7 张业务表；v_tname 规避参数歧义教训） ----------
create or replace function public.admin_truncate_table(
  table_name text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_tname  text := btrim(coalesce(table_name, ''));
  v_n      int := 0;
  v_allowed text[] := array['chronic_profiles','chronic_alerts','health_metrics','medication_logs','follow_ups','events','family_bindings'];
begin
  perform public._adm_require_super();
  if not (v_tname = any (v_allowed)) then
    raise exception '表不在允许清空的白名单内';
  end if;
  execute format('delete from public.%I', v_tname);
  get diagnostics v_n = row_count;
  return jsonb_build_object('ok', true, 'table', v_tname, 'deleted', v_n);
end $$;

-- ---------- 11) 全库备份（users + 7 张业务表 → JSON 落 system_settings 由前端触发） ----------
create or replace function public.admin_backup_data(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_data   jsonb;
  v_sql    text;
  v_size   bigint;
begin
  perform public._adm_require_super(caller);
  v_size := pg_database_size(current_database());
  select jsonb_build_object(
    'users',            (select coalesce(jsonb_agg(t), '[]'::jsonb) from (select id, family_code, role, bound_elder_code, bound_elder_codes, email, email_remind, is_admin, admin_level, sub_perms, created_at from users) t),
    'chronic_profiles', (select coalesce(jsonb_agg(t), '[]'::jsonb) from chronic_profiles t),
    'chronic_alerts',   (select coalesce(jsonb_agg(t), '[]'::jsonb) from chronic_alerts t),
    'health_metrics',   (select coalesce(jsonb_agg(t), '[]'::jsonb) from health_metrics t),
    'medication_logs',  (select coalesce(jsonb_agg(t), '[]'::jsonb) from medication_logs t),
    'follow_ups',       (select coalesce(jsonb_agg(t), '[]'::jsonb) from follow_ups t),
    'events',           (select coalesce(jsonb_agg(t), '[]'::jsonb) from events t),
    'family_bindings',  (select coalesce(jsonb_agg(t), '[]'::jsonb) from family_bindings t)
  ) into v_data;
  v_sql := '-- 医路相伴 数据库备份 ' || to_char(now() AT TIME ZONE 'Asia/Shanghai', 'YYYY-MM-DD HH24:MI:SS') || E'\n'
    || '-- 数据库大小：' || v_size || ' 字节' || E'\n'
    || '-- 各表行数：' || E'\n'
    || '-- users: '            || jsonb_array_length(v_data->'users') || E'\n'
    || '-- chronic_profiles: ' || jsonb_array_length(v_data->'chronic_profiles') || E'\n'
    || '-- chronic_alerts: '   || jsonb_array_length(v_data->'chronic_alerts') || E'\n'
    || '-- health_metrics: '   || jsonb_array_length(v_data->'health_metrics') || E'\n'
    || '-- medication_logs: '  || jsonb_array_length(v_data->'medication_logs') || E'\n'
    || '-- follow_ups: '       || jsonb_array_length(v_data->'follow_ups') || E'\n'
    || '-- events: '           || jsonb_array_length(v_data->'events') || E'\n'
    || '-- family_bindings: '  || jsonb_array_length(v_data->'family_bindings') || E'\n'
    || '-- 恢复方式：将本 JSON 中各表数组逐行 INSERT 回同名表（pass_hash 已从 users 备份中剔除）';
  return jsonb_build_object('ok', true, 'json_data', v_data, 'sql_summary', v_sql, 'database_size', v_size);
end $$;

-- ---------- 12) 维护模式开关（写 app_settings key=maintenance） ----------
create or replace function public.admin_set_maintenance_mode(
  enabled boolean default false
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_val jsonb;
begin
  perform public._adm_assert();
  insert into app_settings (key, value, updated_at)
  values ('maintenance', jsonb_build_object('enabled', coalesce(enabled, false)), now())
  on conflict (key) do update
    set value = coalesce(app_settings.value, '{}'::jsonb) || jsonb_build_object('enabled', coalesce(enabled, false)),
        updated_at = now()
  returning value into v_val;
  return jsonb_build_object('ok', true, 'value', v_val);
end $$;

-- ---------- 13) 公告保存（新增或更新，返回落库后的完整行） ----------
create or replace function public.admin_ann_save(
  rec jsonb default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_op     text := nullif(public._ylxb_sub(), '');
  v_id     text := nullif(btrim(coalesce(rec ->> 'id', '')), '');
  v_now_ms bigint := (extract(epoch from now()) * 1000)::bigint;
  v_row    announcements%rowtype;
begin
  perform public._adm_assert();
  if rec is null then
    raise exception '缺少公告内容';
  end if;
  if v_id is null then
    v_id := 'a' || v_now_ms::text || '_' || substr(md5(random()::text), 1, 4);
  end if;

  update announcements set
      title         = coalesce(rec ->> 'title', title),
      body          = coalesce(rec ->> 'body', body),
      level         = coalesce(nullif(rec ->> 'level', ''), 'normal'),
      popup         = coalesce(nullif(rec ->> 'popup', ''), 'never'),
      pin           = coalesce((rec ->> 'pin')::boolean, pin),
      active_from   = case when coalesce(rec ->> 'active_from', '') = '' then null else (rec ->> 'active_from')::timestamptz end,
      active_to     = case when coalesce(rec ->> 'active_to', '') = '' then null else (rec ->> 'active_to')::timestamptz end,
      email_sent    = coalesce((rec ->> 'email_sent')::boolean, email_sent),
      email_sent_ts = (rec ->> 'email_sent_ts')::bigint,
      email_count   = coalesce((rec ->> 'email_count')::int, email_count),
      email_fail    = coalesce((rec ->> 'email_fail')::int, email_fail),
      updated_by    = v_op,
      updated_at    = now(),
      ts            = coalesce((rec ->> 'ts')::bigint, v_now_ms),
      deleted       = coalesce((rec ->> 'deleted')::boolean, deleted)
    where id = v_id
    returning * into v_row;

  if not found then
    insert into announcements (
      id, title, body, level, popup, pin, active_from, active_to,
      email_sent, email_sent_ts, email_count, email_fail,
      created_by, updated_by, created_at, updated_at, ts, deleted
    ) values (
      v_id,
      coalesce(rec ->> 'title', ''),
      coalesce(rec ->> 'body', ''),
      coalesce(nullif(rec ->> 'level', ''), 'normal'),
      coalesce(nullif(rec ->> 'popup', ''), 'never'),
      coalesce((rec ->> 'pin')::boolean, false),
      case when coalesce(rec ->> 'active_from', '') = '' then null else (rec ->> 'active_from')::timestamptz end,
      case when coalesce(rec ->> 'active_to', '') = '' then null else (rec ->> 'active_to')::timestamptz end,
      coalesce((rec ->> 'email_sent')::boolean, false),
      (rec ->> 'email_sent_ts')::bigint,
      coalesce((rec ->> 'email_count')::int, 0),
      coalesce((rec ->> 'email_fail')::int, 0),
      v_op, v_op, now(), now(),
      coalesce((rec ->> 'ts')::bigint, v_now_ms),
      false
    ) returning * into v_row;
  end if;

  return to_jsonb(v_row);
end $$;

-- ---------- 14) 公告置顶切换 ----------
create or replace function public.admin_ann_toggle_pin(
  ann_id text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_op  text := nullif(public._ylxb_sub(), '');
  v_pin boolean;
  v_ts  bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  perform public._adm_assert();
  if coalesce(ann_id, '') = '' then
    raise exception '缺少公告 id';
  end if;
  update announcements
    set pin = not coalesce(pin, false), ts = v_ts, updated_by = v_op, updated_at = now()
    where id = ann_id
    returning pin into v_pin;
  if not found then
    raise exception '公告不存在';
  end if;
  return jsonb_build_object('ok', true, 'id', ann_id, 'pin', v_pin, 'ts', v_ts);
end $$;

-- ---------- 15) 公告删除（软删除） ----------
create or replace function public.admin_ann_delete(
  ann_id text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_op text := nullif(public._ylxb_sub(), '');
begin
  perform public._adm_assert();
  if coalesce(ann_id, '') = '' then
    raise exception '缺少公告 id';
  end if;
  update announcements
    set deleted = true, ts = (extract(epoch from now()) * 1000)::bigint, updated_by = v_op, updated_at = now()
    where id = ann_id;
  if not found then
    raise exception '公告不存在';
  end if;
  return jsonb_build_object('ok', true, 'id', ann_id);
end $$;

-- ---------- 16) 收紧管理 RPC 执行权限（ anon/public 不可执行；authenticated/service_role 保留） ----------
do $$
declare
  f record;
begin
  for f in
    select p.oid::regprocedure as sig
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and p.proname like 'admin\_%'
  loop
    execute format('revoke all on function %s from public, anon', f.sig);
  end loop;
end $$;

select '0003-admin-rpcs-OK' as 部署标记;
