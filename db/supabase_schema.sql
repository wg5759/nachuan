-- ============================================================================
-- 大模型聚合器 · 跨设备同步 Supabase Schema（内容指纹去重版）
-- ----------------------------------------------------------------------------
-- 同步范围（机主拍板 2026-06-27）：长期记忆 + 案例库 + 知识库。
--   不同步：对话历史、连接配置/API 密钥（BYOK 密钥绝不上云）。
-- 隔离：每个用户用自己的 Supabase Auth 账号登录，RLS 按 auth.uid() 行级隔离，
--       **只有同一账户的设备之间**才互相同步；不同账户完全隔离、互不可见。
--       自用与商用同一套（商用把 anon key 打进包，安全全靠 RLS）。
--
-- 幂等/去重：云端唯一键 = (user_id, content_hash)，content_hash = sha256(归一化内容)。
--   归一化 norm(s) = 把所有连续空白折叠成单空格再去首尾（前后端必须一致）。
--   各表 content_hash 取自：
--     memory     → norm(text)
--     cases      → norm(problem)
--     kb_docs    → norm(title) + '\n' + norm(source)
--     kb_chunks  → norm(text)
--   好处：同一条知识在多设备只存一份、天然去重、无需跨设备 id 映射、无回环。
-- 冲突：last-write-wins（updated_at 较新者胜）。删除：deleted=true 墓碑传播。
--
-- 用法：Supabase 项目 → SQL Editor 粘贴运行一次（可重复运行，幂等）。
-- ============================================================================

create or replace function public.touch_updated_at()
returns trigger language plpgsql as $$
begin
  if new.updated_at is null then new.updated_at := extract(epoch from now()); end if;
  return new;
end $$;

-- ── 长期记忆 ────────────────────────────────────────────────────────────────
create table if not exists public.memory (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  content_hash text not null,
  text         text not null,
  kind         text default 'fact',
  created_at   double precision,
  updated_at   double precision not null,
  deleted      boolean not null default false,
  unique (user_id, content_hash)
);
create index if not exists idx_memory_user_upd on public.memory(user_id, updated_at);

-- ── 案例库 ──────────────────────────────────────────────────────────────────
create table if not exists public.cases (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  content_hash text not null,
  problem      text not null,
  solution     text not null,
  model        text,
  created_at   double precision,
  updated_at   double precision not null,
  deleted      boolean not null default false,
  unique (user_id, content_hash)
);
create index if not exists idx_cases_user_upd on public.cases(user_id, updated_at);

-- ── 知识库·文档 ─────────────────────────────────────────────────────────────
create table if not exists public.kb_docs (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  content_hash text not null,
  title        text not null,
  source       text,
  status       text not null default 'active',
  created_at   double precision,
  updated_at   double precision not null,
  deleted      boolean not null default false,
  unique (user_id, content_hash)
);
-- 兼容 2026-08-13 以前已初始化、但尚无生命周期列的远端项目。
alter table public.kb_docs
  add column if not exists status text not null default 'active';
create index if not exists idx_kbdocs_user_upd on public.kb_docs(user_id, updated_at);

-- ── 知识库·分块（doc_hash 关联回 kb_docs.content_hash，跨设备重建 文档↔分块 关系）──
create table if not exists public.kb_chunks (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  content_hash text not null,
  doc_hash     text not null,
  title        text,
  text         text not null,
  updated_at   double precision not null,
  deleted      boolean not null default false,
  unique (user_id, content_hash)
);
create index if not exists idx_kbchunks_user_upd on public.kb_chunks(user_id, updated_at);

-- ── 行级安全：每个用户只能读写自己的行 ───────────────────────────────────────
do $$
declare t text;
begin
  foreach t in array array['memory','cases','kb_docs','kb_chunks'] loop
    execute format('alter table public.%I enable row level security;', t);
    begin
      execute format($p$create policy %I on public.%I for all
        using (auth.uid() = user_id) with check (auth.uid() = user_id);$p$, t || '_own', t);
    exception when duplicate_object then null;
    end;
    begin
      execute format('create trigger %I before insert on public.%I
        for each row execute function public.touch_updated_at();', t || '_touch', t);
    exception when duplicate_object then null;
    end;
  end loop;
end $$;

-- 验证：应返回 4 张表，其中 kb_docs.status 为 text / 'active'::text。
select table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in ('memory', 'cases', 'kb_docs', 'kb_chunks')
order by table_name;

select column_name, data_type, column_default, is_nullable
from information_schema.columns
where table_schema = 'public'
  and table_name = 'kb_docs'
  and column_name = 'status';
