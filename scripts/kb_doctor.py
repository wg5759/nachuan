#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kb_doctor.py — 纳川知识库（knowledge.db）体检与检索回归评测。

用法:
  python scripts/kb_doctor.py [--db PATH] [--quiet] [--rebuild]   # 体检(默认 ./data/knowledge.db)
  python scripts/kb_doctor.py --eval [--eval-file PATH] [--quiet] # 临时库自建语料跑 recall@5

分级（风格对齐 D:\\AI知识库\\kb_doctor.py，exit 0 = 无 FAIL）:
  FAIL(退出码 1): 孤儿 chunks / active 文档同名冲突 / kb_fts 与 kb_chunks 行数不一致 /
                  评测 recall@5 低于阈值 0.8
  WARN(退出码 0): 0 chunk 空文档 / 缺 vec 的 chunk / 无 kb_fts(检索降级纯覆盖率) /
                  老库 kb_docs 缺 status 列
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 支持直接脚本运行

from orchestrator.knowledge import KnowledgeBase  # noqa: E402

EVAL_FILE = Path(__file__).with_name("kb_eval.jsonl")
DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "knowledge.db"
RECALL_K = 5
RECALL_THRESHOLD = 0.8


def check_db(db_path: str) -> tuple[list[str], list[str]]:
    """对 knowledge.db 做结构体检，返回 (fails, warns)。"""
    fails: list[str] = []
    warns: list[str] = []
    if not Path(db_path).is_file():
        warns.append(f"库文件不存在：{db_path}（引擎首次启动后自动生成）")
        return fails, warns
    con = sqlite3.connect(str(db_path))
    try:
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master")}
        if "kb_docs" not in tables or "kb_chunks" not in tables:
            fails.append("缺 kb_docs/kb_chunks 表（库结构未初始化）")
            return fails, warns
        orphan = con.execute(
            "SELECT COUNT(*) FROM kb_chunks c LEFT JOIN kb_docs d "
            "ON d.id=c.doc_id AND d.user_id=c.user_id WHERE d.id IS NULL"
        ).fetchone()[0]
        if orphan:
            fails.append(f"孤儿 chunks {orphan} 条（doc_id 无对应文档）")
        empty = con.execute(
            "SELECT COUNT(*) FROM kb_docs d LEFT JOIN kb_chunks c "
            "ON c.doc_id=d.id AND c.user_id=d.user_id WHERE c.id IS NULL"
        ).fetchone()[0]
        if empty:
            warns.append(f"0 chunk 空文档 {empty} 篇（疑似导入失败或云同步中间态）")
        doc_cols = {r[1] for r in con.execute("PRAGMA table_info(kb_docs)")}
        if "status" not in doc_cols:
            warns.append("kb_docs 缺 status 列（老库未迁移：用新版引擎打开一次即自动补列）")
        else:
            conflicts = con.execute(
                "SELECT user_id,title,COUNT(*) n FROM kb_docs WHERE status='active' "
                "GROUP BY user_id,title HAVING n>1"
            ).fetchall()
            for uid, title, n in conflicts:
                fails.append(f"active 文档同名冲突：{uid}《{title}》×{n}（写入闸应已挡住）")
        total = con.execute("SELECT COUNT(*) FROM kb_chunks").fetchone()[0]
        chunk_cols = {r[1] for r in con.execute("PRAGMA table_info(kb_chunks)")}
        if "vec" in chunk_cols:
            no_vec = con.execute(
                "SELECT COUNT(*) FROM kb_chunks WHERE vec IS NULL OR length(vec)=0"
            ).fetchone()[0]
            if no_vec:
                warns.append(f"缺 vec 的 chunk {no_vec}/{total}（embedder 降级或待首次检索懒回填）")
        if "kb_fts" not in tables:
            warns.append("无 kb_fts 索引：检索正降级纯覆盖率（老库用新版打开一次即建）")
        else:
            fts_n = con.execute("SELECT COUNT(*) FROM kb_fts").fetchone()[0]
            if fts_n != total:
                fails.append(
                    f"kb_fts 行数 {fts_n} ≠ kb_chunks 行数 {total}（索引过期/损坏）"
                    "——加 --rebuild 重建，或调用 KnowledgeBase.rebuild_fts()"
                )
    finally:
        con.close()
    return fails, warns


def run_eval(eval_file: str | Path, quiet: bool = False) -> float:
    """在临时库上自建语料跑检索回归：导入全部小文档，逐条提问，统计 recall@5。"""
    lines = [
        json.loads(ln)
        for ln in Path(eval_file).read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    # 评测语料不进生产库：临时文件库，跑完即弃
    db = Path(tempfile.mkdtemp(prefix="kb-eval-")) / "eval.db"
    kb = KnowledgeBase(str(db))
    try:
        for item in lines:
            kb.add_document("eval", item["doc_title"], item["doc_text"])
        ok = 0
        misses: list[str] = []
        for item in lines:
            hits = kb.search("eval", item["question"], k=RECALL_K)
            if any(h["title"] == item["expect"] for h in hits):
                ok += 1
            else:
                misses.append(f"{item['question']}（应命中《{item['expect']}》）")
    finally:
        kb.close()
    recall = ok / len(lines) if lines else 0.0
    if not quiet:
        print(
            f"[eval] 语料 {len(lines)} 条 · recall@{RECALL_K} = {recall:.3f}"
            f"（{ok}/{len(lines)}）· 阈值 {RECALL_THRESHOLD}"
        )
        for m in misses:
            print(f"  [MISS] {m}")
    return recall


def main(argv: list[str] | None = None) -> int:
    # Windows GBK 控制台打印 ✅/❌ 会 UnicodeEncodeError，先强制 utf-8（项目既有坑，见AI知识库 GBK 条目族）
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="纳川知识库体检与检索回归评测")
    ap.add_argument("--db", default=str(DEFAULT_DB), help="knowledge.db 路径")
    ap.add_argument("--eval", action="store_true", help="跑评测集回归（临时库自建语料）")
    ap.add_argument("--eval-file", default=str(EVAL_FILE), help="评测集 jsonl 路径")
    ap.add_argument("--rebuild", action="store_true", help="先重建 FTS 索引再体检")
    ap.add_argument("--quiet", action="store_true", help="只打印问题行")
    args = ap.parse_args(argv)

    fails: list[str] = []
    warns: list[str] = []
    if args.rebuild:
        kb = KnowledgeBase(args.db)
        try:
            n = kb.rebuild_fts()
        finally:
            kb.close()
        print(f"[rebuild] kb_fts 重建完成，共 {n} 行" if n is not None else "[rebuild] FTS5 不可用，跳过")
    if args.eval:
        recall = run_eval(args.eval_file, quiet=args.quiet)
        if recall < RECALL_THRESHOLD:
            fails.append(f"评测 recall@{RECALL_K}={recall:.3f} < 阈值 {RECALL_THRESHOLD}")
    else:
        fails, warns = check_db(args.db)

    if not args.quiet:
        mode = "评测" if args.eval else f"体检 {args.db}"
        print(f"kb_doctor · {mode}")
    for x in fails:
        print(f"  [FAIL] {x}")
    for x in warns:
        print(f"  [WARN] {x}")
    if not fails and not warns:
        print("  ✅ 全绿：结构/索引/评测全部合规")
    elif not fails:
        print(f"  ✅ 无 FAIL（{len(warns)} 条 WARN 供参考）")
    else:
        print(f"  ❌ {len(fails)} 条 FAIL — 修复后重跑")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
