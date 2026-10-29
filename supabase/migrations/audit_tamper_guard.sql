-- 审计日志防篡改 + 日志清理（仅最高管理员）
-- 1) admin_audit_logs 设为只增表：直接 UPDATE / DELETE / TRUNCATE 一律报错
-- 2) admin_read_audit_v2：读取日志（带 id 与总数，供前端勾选批量删除）
-- 3) admin_delete_audit_logs：唯一合法删除入口（按勾选 id 或按截止日期），删除行为本身自动写入一条审计记录
-- 部署：Supabase SQL Editor 整段执行，Results 应显示 audit-guard-OK

create or replace function public.admin_audit_logs_guard()
returns trigger language plpgsql as $$
begin
  if coalesce(current_setting('app.audit_guard_bypass', true), '') <> 'on' then
    raise exception 'admin_audit_logs 为只增审计表，禁止直接修改、删除或清空（清理请走管理台「管理操作日志」卡片）';
  end if;
  return coalesce(new, old);
end; $$;

drop trigger if exists admin_audit_logs_guard_row on public.admin_audit_logs;
create trigger admin_audit_logs_guard_row
  before update or delete on public.admin_audit_logs
  for each row execute function public.admin_audit_logs_guard();

drop trigger if exists admin_audit_logs_guard_truncate on public.admin_audit_logs;
create trigger admin_audit_logs_guard_truncate
  before truncate on public.admin_audit_logs
  for each statement execute function public.admin_audit_logs_guard();

create or replace function public.admin_read_audit_v2(
  caller   text default '',
  p_action text default '',
  p_limit  int  default 50
) returns jsonb
language plpgsql security definer as $$
declare
  v_rows  jsonb;
  v_total bigint;
begin
  perform public._adm_require_super();
  select count(*) into v_total
    from public.admin_audit_logs
   where p_action = '' or action ilike '%' || p_action || '%';
  select coalesce(jsonb_agg(t), '[]'::jsonb) into v_rows
    from (
      select id, action, operator, payload, ts
        from public.admin_audit_logs
       where p_action = '' or action ilike '%' || p_action || '%'
       order by ts desc
       limit least(greatest(coalesce(p_limit, 50), 1), 200)
    ) t;
  return jsonb_build_object('rows', v_rows, 'total', v_total);
end; $$;

create or replace function public.admin_delete_audit_logs(
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
    perform set_config('app.audit_guard_bypass', 'on', true);
    delete from public.admin_audit_logs where id::text = any(p_ids);
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
    perform set_config('app.audit_guard_bypass', 'on', true);
    delete from public.admin_audit_logs where ts < v_before;
    get diagnostics v_del = row_count;
  else
    raise exception '请先勾选要删除的日志，或填写清理截止日期';
  end if;

  begin
    perform public.admin_write_audit(
      public._ylxb_sub(),
      'admin.audit.delete',
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

revoke all on function public.admin_read_audit_v2(text, text, int) from public, anon;
grant execute on function public.admin_read_audit_v2(text, text, int) to authenticated;
revoke all on function public.admin_delete_audit_logs(text, text[], text) from public, anon;
grant execute on function public.admin_delete_audit_logs(text, text[], text) to authenticated;

select 'audit-guard-OK' as 部署标记;
