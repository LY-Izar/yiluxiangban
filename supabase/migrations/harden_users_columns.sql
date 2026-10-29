revoke select on public.users from authenticated;
grant select (
  id, family_code, role,
  bound_elder_code, bound_elder_codes,
  email, email_remind,
  is_admin, admin_level, sub_perms,
  created_at
) on public.users to authenticated;

select 'column-hardening-OK' as 閮ㄧ讲鏍囪;
