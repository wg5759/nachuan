"""一次性建好视频工作室③的图床（Supabase Storage 公开桶 `studio-frames` + 权限）。

机主给 PAT（账户管理员 token）跑一次即可：建公开桶 + RLS policy
（authenticated 可 传/查/删，public 可读）。**select policy 必须有** —— Supabase 删对象
前要先能 SELECT 找到它，缺了删除会 403。
商用分发同理：终端用户用自己的 Supabase 时各跑一次（机主托管的项目里已建好则免）。

用法：
    PAT=sbp_xxx  .venv/Scripts/python.exe scripts/_setup_imagehost.py <project_ref>
"""

from __future__ import annotations

import os
import sys

import httpx

_SQL = """
insert into storage.buckets (id,name,public) values ('studio-frames','studio-frames',true)
  on conflict (id) do update set public=true;
drop policy if exists "studio_frames_insert" on storage.objects;
create policy "studio_frames_insert" on storage.objects for insert to authenticated with check (bucket_id='studio-frames');
drop policy if exists "studio_frames_select" on storage.objects;
create policy "studio_frames_select" on storage.objects for select to authenticated using (bucket_id='studio-frames');
drop policy if exists "studio_frames_delete" on storage.objects;
create policy "studio_frames_delete" on storage.objects for delete to authenticated using (bucket_id='studio-frames');
"""


def main() -> None:
    pat = os.getenv("PAT", "")
    ref = sys.argv[1] if len(sys.argv) > 1 else ""
    if not pat or not ref:
        print("用法：PAT=sbp_xxx .venv/Scripts/python.exe scripts/_setup_imagehost.py <project_ref>")
        return
    r = httpx.post(
        f"https://api.supabase.com/v1/projects/{ref}/database/query",
        headers={"Authorization": f"Bearer {pat}", "Content-Type": "application/json"},
        json={"query": _SQL},
        timeout=60,
    )
    print("建桶 + policy:", r.status_code, r.text[:200])
    print("完成后请到 supabase.com/dashboard/account/tokens 撤销该 PAT。")


if __name__ == "__main__":
    main()
