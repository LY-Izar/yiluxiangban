grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to anon, authenticated, service_role;
grant all on all functions in schema public to anon, authenticated, service_role;
grant all on all sequences in schema public to anon, authenticated, service_role;

notify pgrst, 'reload schema';

select 'grants-restored' as 閮ㄧ讲鏍囪;
