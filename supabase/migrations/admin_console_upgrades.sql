-- =====================================================================
-- 绠＄悊鍙板崌绾э細鎺堟潈瀹℃壒椤?+ 澶囦唤钀藉簱锛堥厤鍚堝墠绔級
-- 渚濊禆锛歴ecurity_session_tokens.sql锛坃adm_assert/_ylxb_sub/_adm_require_super锛塡n-- 骞傜瓑锛氬彲閲嶅鎵ц
-- =====================================================================

-- 1) 鍒楀嚭寰呭鎵瑰崟锛堜粎 super锛塡ncreate or replace function public.admin_list_pending(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_rows jsonb;
begin
  perform public._adm_require_super(caller);
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', p.id, 'token', p.token, 'operator', p.operator,
    'perm_key', p.perm_key, 'action_desc', p.action_desc,
    'payload', p.payload, 'created_at', p.created_at, 'expires_at', p.expires_at
  ) order by p.created_at desc), '[]'::jsonb)
  into v_rows
  from (
    select * from pending_approvals
    where status = 'pending'
    order by created_at desc
    limit 50
  ) p;
  return jsonb_build_object('ok', true, 'rows', v_rows);
end $$;

-- 2) 鎵瑰噯/鎷掔粷涓€寮犲緟瀹℃壒鍗曪紙浠?super锛夛紱鐢宠浜?10s 杞浼氳嚜鍔ㄧ敓鏁圽ncreate or replace function public.admin_resolve_approval(
  caller  text default null,
  p_token text default null,
  approve boolean default true
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_op text;
  v_perm text;
  v_payload jsonb;
  v_count int;
begin
  perform public._adm_require_super(caller);
  if p_token is null or p_token = '' then
    raise exception '缂哄皯瀹℃壒浠ょ墝';
  end if;
  update pending_approvals
    set status = case when approve then 'approved' else 'rejected' end,
        resolved_by = public._ylxb_sub(),
        resolved_at = now()
    where token = p_token and status = 'pending'
    returning operator, perm_key, payload into v_op, v_perm, v_payload;
  get diagnostics v_count = row_count;
  if v_count = 0 then
    raise exception '瀹℃壒鍗曚笉瀛樺湪鎴栧凡琚鐞?;
  end if;
  return jsonb_build_object('ok', true, 'approved', approve, 'operator', v_op, 'perm_key', v_perm, 'payload', v_payload);
end $$;

-- 3) 淇濆瓨澶囦唤鍒?system_settings锛堜粎 super锛屼笂闄?30MB锛塡ncreate or replace function public.admin_save_backup(
  caller text default null,
  data   text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_size int;
begin
  perform public._adm_require_super(caller);
  if data is null or length(data) < 2 then
    raise exception '澶囦唤鏁版嵁涓虹┖';
  end if;
  v_size := length(data);
  if v_size > 30000000 then
    raise exception '澶囦唤鏁版嵁瓒呰繃 30MB锛屾棤娉曚繚瀛?;
  end if;
  insert into system_settings (key, value, updated_at)
  values ('last_backup', jsonb_build_object('ts', now(), 'size', v_size, 'data', data)::text, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();
  return jsonb_build_object('ok', true, 'size', v_size, 'ts', now());
end $$;

-- 4) 璇诲彇涓婃澶囦唤锛堜粎 super锛塡ncreate or replace function public.admin_get_backup(
  caller text default null
) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_value text;
begin
  perform public._adm_require_super(caller);
  select value into v_value from system_settings where key = 'last_backup';
  if v_value is null then
    raise exception '灏氭棤宸蹭繚瀛樼殑澶囦唤';
  end if;
  return v_value::jsonb;
end $$;
