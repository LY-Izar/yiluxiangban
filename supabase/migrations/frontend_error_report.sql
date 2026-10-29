-- 前端错误上报（frontend_errors 表 + 管理 RPC）
-- 1) report_frontend_error：所有用户（含游客/体验模式）浏览器报错自动上报
-- 2) admin_read_frontend_errors：super 读取（关键字筛选，返回 id 与总数）
-- 3) admin_delete_frontend_errors：super 清理（按勾选 id 或截止日期，删除行为写入审计日志）
-- 部署：Supabase SQL Editor 整段执行，Results 应显示 ferr-report-OK

create table if not exists public.frontend_errors (
  id bigint generated always as identity primary key,
  username text default '',
  role text default '',
  view text default '',
  message text default '',
  stack text default '',
  ua text default '',
  env text default '',
  ts timestamptz not null default now()
);
alter table public.frontend_errors enable row level security;

create or replace function public.report_frontend_error(
  caller   text  default '',
  p_payload jsonb default null
) returns jsonb
language plpgsql security definer as $$
declare
  v_user text; v_role text; v_view text;
  v_msg text; v_stack text; v_ua text; v_env text;
  v_recent int;
begin
  v_user  := left(coalesce(nullif(p_payload->>'username',''), coalesce(caller,''), '游客'), 60);
  v_role  := left(coalesce(p_payload->>'role',''), 20);
  v_view  := left(coalesce(p_payload->>'view',''), 40);
  v_msg   := left(coalesce(p_payload->>'message',''), 500);
  v_stack := left(coalesce(p_payload->>'stack',''), 2000);
  v_ua    := left(coalesce(p_payload->>'ua',''), 300);
  v_env   := left(coalesce(p_payload->>'env',''), 20);
  if v_msg = '' then v_msg := '未知错误'; end if;

  select count(*) into v_recent from public.frontend_errors
   where username = v_user and ts > now() - interval '5 minutes';
  if v_recent >= 20 then
    return jsonb_build_object('ok', false, 'reason', 'rate-limited');
  end if;

  insert into public.frontend_errors(username, role, view, message, stack, ua, env)
  values (v_user, v_role, v_view, v_msg, v_stack, v_ua, v_env);
  return jsonb_build_object('ok', true);
end; $$;

create or replace function public.admin_read_frontend_errors(
  caller  text default '',
  p_kw    text default '',
  p_limit int  default 50
) returns jsonb
language plpgsql security definer as $$
declare
  v_rows  jsonb;
  v_total bigint;
  v_today bigint;
begin
  perform public._adm_require_super();
  select count(*) into v_total
    from public.frontend_errors
   where p_kw = '' or username ilike '%' || p_kw || '%' or message ilike '%' || p_kw || '%';
  select count(*) into v_today
    from public.frontend_errors
   where ts > now() - interval '24 hours';
  select coalesce(jsonb_agg(t), '[]'::jsonb) into v_rows
    from (
      select id, username, role, view, message, stack, ua, env, ts
        from public.frontend_errors
       where p_kw = '' or username ilike '%' || p_kw || '%' or message ilike '%' || p_kw || '%'
       order by ts desc
       limit least(greatest(coalesce(p_limit, 50), 1), 200)
    ) t;
  return jsonb_build_object('rows', v_rows, 'total', v_total, 'today', v_today);
end; $$;

create or replace function public.admin_delete_frontend_errors(
  caller   text default '',
  p_ids    text[] default null,
  p_before text   default null
) returns jsonb
language plpgsql security definer as $$
declare
  v_del    int := 0;
  v_before timestamptz := null;
begin
  perform public._adm_require_super();

  if p_ids is not null and coalesce(array_length(p_ids, 1), 0) > 0 then
    delete from public.frontend_errors where id::text = any(p_ids);
    get diagnostics v_del = row_count;
  elsif p_before is not null and btrim(p_before) <> '' then
    begin
      v_before := btrim(p_before)::timestamptz;
    exception when others then
      raise exception '日期格式无效：%（示例 2026-01-01）', p_before;
    end;
    if v_before >= now() then
      raise exception '截止时间必须早于当前时间';
    end if;
    delete from public.frontend_errors where ts < v_before;
    get diagnostics v_del = row_count;
  else
    raise exception '请先勾选要删除的错误记录，或填写清理截止日期';
  end if;

  begin
    perform public.admin_write_audit(
      public._ylxb_sub(),
      'admin.ferr.delete',
      jsonb_build_object(
        'deleted', v_del,
        'by_ids', to_jsonb(coalesce(p_ids, array[]::text[])),
        'before', coalesce(v_before::text, null)
      )
    );
  exception when others then
    raise notice '审计留痕失败（不影响删除结果）：%', sqlerrm;
  end;

  return jsonb_build_object('ok', true, 'deleted', v_del);
end; $$;

revoke all on function public.report_frontend_error(text, jsonb) from public;
grant execute on function public.report_frontend_error(text, jsonb) to anon, authenticated;
revoke all on function public.admin_read_frontend_errors(text, text, int) from public, anon;
grant execute on function public.admin_read_frontend_errors(text, text, int) to authenticated;
revoke all on function public.admin_delete_frontend_errors(text, text[], text) from public, anon;
grant execute on function public.admin_delete_frontend_errors(text, text[], text) to authenticated;

select 'ferr-report-OK' as 部署标记;
