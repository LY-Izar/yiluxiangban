-- =====================================================================
-- 0002 核心 RPC（第二步执行，依赖 0001 的表）
-- auth_check_user_exists：注册/登录前查重（anon 可调）
-- heartbeat_touch：心跳上报（anon 可调）
-- family_makeup_log：家属代老人补记服药（需会话 JWT）
-- admin_write_audit / admin_read_audit：管理审计（v1 读取，v2 在 audit_tamper_guard.sql）
-- =====================================================================

-- 1) 账号查重（前端登录/注册界面调用，返回 {exists:bool}）
create or replace function public.auth_check_user_exists(
  username text default null
) returns jsonb
language sql security definer set search_path = public as $$
  select jsonb_build_object(
    'exists',
    coalesce((select true from users where id = btrim(coalesce(username, '')) limit 1), false)
  );
$$;

-- 2) 心跳上报（前端 anon key 调用；写入/刷新 user_sessions）
create or replace function public.heartbeat_touch(
  caller text default null,
  h_role text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_user text := btrim(coalesce(caller, ''));
  v_r    text := coalesce(h_role, 'elder');
begin
  if v_user = '' then
    return jsonb_build_object('ok', false, 'reason', 'no_user');
  end if;
  if v_r not in ('elder', 'family') then
    v_r := 'elder';
  end if;
  insert into user_sessions (user_id, role, last_seen_at)
  values (v_user, v_r, now())
  on conflict (user_id, role) do update set last_seen_at = now();
  return jsonb_build_object('ok', true);
end $$;

-- 3) 家属代老人补记服药（服务端校验绑定关系 + 禁止补记未来）
create or replace function public.family_makeup_log(
  target_username text default null,
  p_date          text default null,
  p_time          text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_caller   text;
  v_codes    text[];
  v_family   text;
  v_exists   boolean;
  v_ref      text;
  v_late     int := 0;
  v_inserted int := 0;
begin
  v_caller := public._ylxb_sub();
  if v_caller is null or v_caller = '' then
    raise exception '未登录：缺少有效会话令牌';
  end if;
  select bound_elder_codes into v_codes from users where id = v_caller;
  if v_codes is null then
    raise exception '无管理员或家属身份';
  end if;
  if btrim(coalesce(target_username, '')) = '' then
    raise exception '缺少目标老人账号';
  end if;
  -- 目标必须是有效账号，且其 family_code 在调用者的绑定列表内
  select family_code into v_family from users where id = btrim(target_username);
  if v_family is null then
    raise exception '老人账号不存在';
  end if;
  if not (v_family = any (v_codes)) then
    raise exception '未绑定该老人，无法补记';
  end if;
  -- 日期校验：YYYY-MM-DD 且不得为未来
  begin
    v_exists := (btrim(p_date)::date) <= current_date;
  exception when others then
    raise exception '日期格式无效（应为 YYYY-MM-DD）';
  end;
  if not v_exists then
    raise exception '不能补记未来日期的服药';
  end if;
  if p_time !~ '^\d{2}:\d{2}$' then
    raise exception '时间格式无效（应为 HH:MM）';
  end if;

  v_ref := 'fam' || substr(md5(btrim(target_username) || ':' || btrim(p_date) || ':' || btrim(p_time) || ':fam_makeup_v1'), 1, 8);
  if btrim(p_date)::date = current_date then
    v_late := greatest(0, extract(epoch from (now() - (btrim(p_date) || ' ' || btrim(p_time))::timestamptz)) / 60)::int;
  end if;

  insert into medication_logs
    (username, med_ref, med_name, scheduled_date, scheduled_time,
     status, actual_time, actual_hhmm, late_minutes, reminded_count)
  values
    (btrim(target_username), v_ref, '家属补记', btrim(p_date)::date, btrim(p_time),
     'taken', now(), to_char(now(), 'HH24:MI'), v_late, 0)
  on conflict (username, med_ref, scheduled_date, scheduled_time) do nothing;
  get diagnostics v_inserted = row_count;

  insert into events (family_code, type, text)
  values (v_family, '用药依从性', '家属补记服药：' || btrim(p_date) || ' ' || btrim(p_time));

  return jsonb_build_object('ok', true, 'already', v_inserted = 0);
end $$;

-- 4) 管理审计写入（audit() 前端调用传 p_action/p_payload；审计防篡改脚本内部传 caller 三参）
create or replace function public.admin_write_audit(
  caller    text default null,
  p_action  text default null,
  p_payload jsonb default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_id bigint;
begin
  if btrim(coalesce(p_action, '')) = '' then
    raise exception '缺少审计操作名';
  end if;
  insert into admin_audit_logs (action, operator, payload)
  values (btrim(p_action), coalesce(btrim(caller), nullif(public._ylxb_sub(), '')), p_payload)
  returning id into v_id;
  return jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- 5) 审计读取 v1（降级兼容；v2 在 audit_tamper_guard.sql，二选一不冲突）
create or replace function public.admin_read_audit(
  caller   text default '',
  p_action text default '',
  p_limit  int  default 50
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_rows jsonb;
begin
  perform public._adm_require_super();
  select coalesce(jsonb_agg(t), '[]'::jsonb) into v_rows
    from (
      select action, operator, payload, ts
        from admin_audit_logs
       where btrim(coalesce(p_action, '')) = '' or action ilike '%' || btrim(p_action) || '%'
       order by ts desc
       limit least(greatest(coalesce(p_limit, 50), 1), 200)
    ) t;
  return jsonb_build_object('rows', v_rows);
end $$;

select '0002-core-rpcs-OK' as 部署标记;
