-- =====================================================================
-- 0004 定时维护自动转正（可选；依赖 0001 的 app_settings）
-- 前端已有 10s 轮询与本地 schedDue 兜底，本文件仅为长驻 Realtime 页面补上
-- "到点自动转正/结束" 的服务端保障。若执行失败（pg_cron 未启用）可跳过，不影响功能。
-- 执行前提：Supabase Dashboard → Database → Extensions 启用 pg_cron 与 pg_net（本文件只用 pg_cron）
-- =====================================================================

create or replace function public.rollover_maintenance()
returns void
language plpgsql security definer set search_path = public as $$
declare
  v_val jsonb;
begin
  select value into v_val from app_settings where key = 'maintenance';
  if v_val is null or jsonb_typeof(v_val) <> 'object' then
    return;
  end if;
  if not coalesce((v_val ->> 'scheduled')::boolean, false) then
    return;
  end if;

  declare
    v_start timestamptz := nullif(v_val ->> 'start_at', '')::timestamptz;
    v_end   timestamptz := nullif(v_val ->> 'end_at', '')::timestamptz;
    v_enabled boolean := coalesce((v_val ->> 'enabled')::boolean, false);
    v_new   boolean;
  begin
    if v_start is null then return; end if;
    if now() >= v_start and (v_end is null or now() < v_end) then
      v_new := true;   -- 进入维护窗口
    elsif v_end is not null and now() >= v_end then
      v_new := false;  -- 维护结束
    else
      return;
    end if;
    if v_new <> v_enabled then
      update app_settings
        set value = v_val || jsonb_build_object('enabled', v_new), updated_at = now()
        where key = 'maintenance';
    end if;
  end;
end $$;

-- 每分钟检查一次
select cron.schedule(
  'ylxb-maintenance-rollover',
  '* * * * *',
  $$select public.rollover_maintenance();$$
);

select '0004-maintenance-cron-OK' as 部署标记;
