-- =====================================================================
-- 瀹夊叏鍔犲浐杩佺Щ锛氳嚜寤轰細璇濅护鐗岋紙鏂规鈶★級  v2锛堥€傞厤鐪熷疄搴撶粨鏋勶級
-- v2 淇锛氱湡瀹炲簱 family_bindings.family_id 涓?uuid 涓斿墠绔笉浣跨敤璇ヨ〃锛孿n--          缁戝畾鍏崇郴鏉冨▉鏉ユ簮鏀逛负 users.bound_elder_codes锛坱ext[]锛夈€俓n-- 閮ㄧ讲椤哄簭瑕佹眰锛氬厛閮ㄧ讲 Edge Function ylxb-auth锛屾渶鍚庢墽琛屾湰鏂囦欢銆俓n-- 鎵ц鍚庯細anon 澶卞幓涓€鍒囪〃璁块棶锛堥櫎鍏憡/璁剧疆鍙锛夛紱涓€鍒囪韩浠芥潵鑷?JWT claims銆俓n-- =====================================================================

-- ---------- 1) JWT 韬唤杈呭姪鍑芥暟 ----------
create or replace function public._ylxb_sub() returns text
language sql stable as $$
  select coalesce(auth.jwt() ->> 'sub', '');
$$;

create or replace function public._ylxb_admin_level() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(auth.jwt() ->> 'ylxb_admin_level', 'none');
$$;

-- 褰撳墠鐧诲綍鐢ㄦ埛缁戝畾鐨勮€佷汉閭€璇风爜闆嗗悎锛坒amily 瑙嗚鐨勫彲瑙佽寖鍥达級
create or replace function public._ylxb_bound_codes() returns text[]
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select bound_elder_codes from users where id = public._ylxb_sub()),
    '{}'::text[]
  );
$$;

-- 褰撳墠鐧诲綍鐢ㄦ埛鐨勫搴個璇风爜锛坋lder 瑙嗚锛塡ncreate or replace function public._ylxb_my_family_code() returns text
language sql stable security definer set search_path = public as $$
  select coalesce(
    (select family_code from users where id = public._ylxb_sub()),
    ''
  );
$$;

-- 鏁版嵁鍙鎬э細鏈汉 鎴?鎴戝凡缁戝畾璇ヨ€佷汉锛堥€氳繃 bound_elder_codes 鍖归厤鍏?family_code锛塡ncreate or replace function public._can_read_user_data(target_username text) returns boolean
language sql stable security definer set search_path = public as $$
  select target_username = public._ylxb_sub()
      or exists (
        select 1
        from users elder
        where elder.id = target_username
          and elder.family_code = any (public._ylxb_bound_codes())
      );
$$;

-- ---------- 2) 绠＄悊鍛?RPC 瀹堝崼锛氭敼涓?JWT 韬唤锛坈aller 鍙傛暟寮冪敤浣嗕笉鍒狅紝淇濇寔鍏煎锛?----------
create or replace function public._adm_assert(caller_id text default null) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_sub text;
  v_lvl text;
begin
  v_sub := public._ylxb_sub();
  if v_sub is null or v_sub = '' then
    raise exception '鏈櫥褰曪細缂哄皯鏈夋晥浼氳瘽浠ょ墝';
  end if;
  select admin_level into v_lvl from users where id = v_sub;
  if v_lvl is null or v_lvl not in ('super','sub') then
    raise exception '鏃犵鐞嗗憳鏉冮檺';
  end if;
end $$;

create or replace function public._adm_require_super(caller_id text default null) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_sub text;
  v_lvl text;
begin
  v_sub := public._ylxb_sub();
  if v_sub is null or v_sub = '' then
    raise exception '鏈櫥褰曪細缂哄皯鏈夋晥浼氳瘽浠ょ墝';
  end if;
  select admin_level into v_lvl from users where id = v_sub;
  if v_lvl is distinct from 'super' then
    raise exception '闇€瑕佹渶楂樼鐞嗗憳鏉冮檺';
  end if;
end $$;

-- ---------- 3) users ----------
alter table public.users enable row level security;
drop policy if exists users_select on public.users;
create policy users_select on public.users for select
  using (
    id = public._ylxb_sub()
    or family_code = any (public._ylxb_bound_codes())
  );
drop policy if exists users_update on public.users;
create policy users_update on public.users for update
  using (id = public._ylxb_sub())
  with check (id = public._ylxb_sub());
drop policy if exists users_delete on public.users;
create policy users_delete on public.users for delete
  using (id = public._ylxb_sub());
-- INSERT 鏃犵瓥鐣ワ細娉ㄥ唽鍙厑璁哥粡 Edge Function锛坰ervice_role锛塡n
-- ---------- 4) family_bindings锛氬墠绔笉浣跨敤锛屾暣浣撻攣姝伙紙浠?service_role锛?----------
alter table public.family_bindings enable row level security;
-- 涓嶅垱寤轰换浣曠瓥鐣ワ細anon/authenticated 涓€寰嬩笉鍙锛涚粦瀹氬叧绯绘潈濞佹潵婧愪负 users.bound_elder_codes

-- ---------- 5) 涓氬姟鏁版嵁琛細鏈汉璇诲啓锛岀粦瀹氬灞炲彧璇?----------
alter table public.chronic_profiles enable row level security;
drop policy if exists cp_select on public.chronic_profiles;
create policy cp_select on public.chronic_profiles for select
  using (public._can_read_user_data(username));
drop policy if exists cp_write on public.chronic_profiles;
create policy cp_write on public.chronic_profiles for all
  using (username = public._ylxb_sub())
  with check (username = public._ylxb_sub());

alter table public.health_metrics enable row level security;
drop policy if exists hm_select on public.health_metrics;
create policy hm_select on public.health_metrics for select
  using (public._can_read_user_data(username));
drop policy if exists hm_write on public.health_metrics;
create policy hm_write on public.health_metrics for all
  using (username = public._ylxb_sub())
  with check (username = public._ylxb_sub());

alter table public.medication_logs enable row level security;
drop policy if exists ml_select on public.medication_logs;
create policy ml_select on public.medication_logs for select
  using (public._can_read_user_data(username));
drop policy if exists ml_write on public.medication_logs;
create policy ml_write on public.medication_logs for all
  using (username = public._ylxb_sub())
  with check (username = public._ylxb_sub());

alter table public.follow_ups enable row level security;
drop policy if exists fu_select on public.follow_ups;
create policy fu_select on public.follow_ups for select
  using (public._can_read_user_data(username));
drop policy if exists fu_write on public.follow_ups;
create policy fu_write on public.follow_ups for all
  using (username = public._ylxb_sub())
  with check (username = public._ylxb_sub());

alter table public.chronic_alerts enable row level security;
drop policy if exists ca_select on public.chronic_alerts;
create policy ca_select on public.chronic_alerts for select
  using (public._can_read_user_data(username));
drop policy if exists ca_write on public.chronic_alerts;
create policy ca_write on public.chronic_alerts for all
  using (username = public._ylxb_sub())
  with check (username = public._ylxb_sub());

-- ---------- 6) events锛氭湰浜猴紙鎸?family_code锛変笌缁戝畾瀹跺睘 ----------
alter table public.events enable row level security;
drop policy if exists ev_select on public.events;
create policy ev_select on public.events for select
  using (
    family_code = any (public._ylxb_bound_codes())
    or family_code = public._ylxb_my_family_code()
  );
drop policy if exists ev_insert on public.events;
create policy ev_insert on public.events for insert
  with check (family_code = public._ylxb_my_family_code());
drop policy if exists ev_delete on public.events;
create policy ev_delete on public.events for delete
  using (family_code = public._ylxb_my_family_code());

-- ---------- 7) announcements锛氬叕寮€鍙锛屽啓鍏ヤ粎缁?security definer RPC ----------
alter table public.announcements enable row level security;
drop policy if exists ann_select on public.announcements;
create policy ann_select on public.announcements for select
  using (deleted = false);

-- ---------- 8) app_settings锛氬叕寮€鍙锛岀鐞嗗憳锛圝WT 澹版槑锛夊彲鍐?----------
alter table public.app_settings enable row level security;
drop policy if exists as_select on public.app_settings;
create policy as_select on public.app_settings for select
  using (true);
drop policy if exists as_update on public.app_settings;
create policy as_update on public.app_settings for update
  using (public._ylxb_admin_level() in ('super','sub'))
  with check (public._ylxb_admin_level() in ('super','sub'));

-- ---------- 9) pending_approvals锛氭湰浜哄彲璇?鍙彂璧凤紝super 鍙壒澶?----------
alter table public.pending_approvals enable row level security;
drop policy if exists pa_select on public.pending_approvals;
create policy pa_select on public.pending_approvals for select
  using (
    operator = public._ylxb_sub()
    or public._ylxb_admin_level() = 'super'
  );
drop policy if exists pa_insert on public.pending_approvals;
create policy pa_insert on public.pending_approvals for insert
  with check (operator = public._ylxb_sub());
drop policy if exists pa_update on public.pending_approvals;
create policy pa_update on public.pending_approvals for update
  using (public._ylxb_admin_level() = 'super')
  with check (public._ylxb_admin_level() = 'super');

-- ---------- 10) 鍐呴儴琛細浠?service_role ----------
alter table public.maintenance_snapshot enable row level security;
alter table public.system_settings enable row level security;
