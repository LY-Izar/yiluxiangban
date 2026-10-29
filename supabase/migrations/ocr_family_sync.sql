create table if not exists public.family_ocr_rules (
  elder_username text primary key,
  rules jsonb not null default '[]'::jsonb,
  updated_by text,
  updated_at timestamptz default now()
);
alter table public.family_ocr_rules enable row level security;
drop policy if exists for_read on family_ocr_rules;
create policy for_read on public.family_ocr_rules for select
  using (elder_username = public._ylxb_sub() or public._can_read_user_data(elder_username));
drop policy if exists for_write on family_ocr_rules;
create policy for_write on public.family_ocr_rules for all
  using (public._can_read_user_data(elder_username))
  with check (public._can_read_user_data(elder_username));

select 'ocr-sync-OK' as 部署标记;
