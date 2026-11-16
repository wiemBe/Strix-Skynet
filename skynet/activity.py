"""Read-only, incremental public activity feed from Strix's existing message store.

Only assistant output_text and tool calls/results are exposed. Reasoning items,
user prompts, provider metadata and binary content are never included.
"""
from __future__ import annotations

import json
from contextlib import closing
import sqlite3
from pathlib import Path
from typing import Any

from .redact import Redactor

MAX_TEXT = 16_000


def _decode(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


IMAGE_WITHHELD = "[Screenshot withheld by Skynet: credentials or personal data inside images cannot be masked]"


def strip_images(value: Any) -> Any:
    """Replace image blocks (view_image output) with a placeholder; pixels and base64 data never leave Skynet."""
    if isinstance(value, list):
        return [{"type": "input_text", "text": IMAGE_WITHHELD}
                if isinstance(b, dict) and b.get("type") in ("input_image", "image", "output_image") else strip_images(b)
                for b in value]
    if isinstance(value, dict):
        return {k: strip_images(v) for k, v in value.items()}
    if isinstance(value, str) and value.startswith("data:image/"):
        return IMAGE_WITHHELD
    return value


def _text(value: Any, red: Redactor) -> tuple[str, bool]:
    value = red.obj(strip_images(_decode(value)), strict=True)
    raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
    # Mask before truncation: truncation must not split and expose a secret prefix.
    raw = red.text(raw, strict=True)
    return raw[:MAX_TEXT], len(raw) > MAX_TEXT


def read(run_dir: Path | None, red: Redactor, after: int = -1, agent_id: str | None = None,
         limit: int = 60) -> dict[str, Any]:
    result = {"available": False, "items": [], "cursor": max(0, after), "has_more": False}
    path = run_dir / ".state" / "agents.db" if run_dir else None
    if not path or not path.is_file():
        return result
    limit = min(100, max(1, limit))
    where = ("(json_extract(message_data,'$.type') IN ('function_call','function_call_output') OR "
             "(json_extract(message_data,'$.type')='message' AND json_extract(message_data,'$.role')='assistant'))")
    args: list[Any] = []
    if after >= 0:
        where += " AND id>?"
        args.append(after)
    if agent_id:
        where += " AND session_id=?"
        args.append(agent_id)
    order = "DESC" if after < 0 else "ASC"
    try:
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)) as c:
            rows = c.execute(f"SELECT id,session_id,message_data,created_at FROM agent_messages WHERE {where} "
                             f"ORDER BY id {order} LIMIT ?", [*args, limit + 1]).fetchall()
            result["has_more"] = after >= 0 and len(rows) > limit
            rows = rows[:limit]
            if after < 0:
                rows.reverse()
            # Tool names for outputs even when the matching call preceded this page.
            call_ids = []
            for _, _, raw, _ in rows:
                m = json.loads(raw)
                if m.get("type") == "function_call_output" and m.get("call_id"):
                    call_ids.append(str(m["call_id"]))
            names = {}
            if call_ids:
                names = dict(c.execute("SELECT json_extract(message_data,'$.call_id'), json_extract(message_data,'$.name') "
                                       "FROM agent_messages WHERE json_extract(message_data,'$.type')='function_call' "
                                       f"AND json_extract(message_data,'$.call_id') IN ({','.join('?' for _ in call_ids)})", call_ids))
        items = []
        for mid, aid, raw, at in rows:
            m = json.loads(raw)
            typ = m.get("type")
            tool = m.get("name") if typ == "function_call" else names.get(m.get("call_id"))
            if typ == "message":
                content = m.get("content") or []
                if not isinstance(content, list):
                    continue
                value = "\n".join(v["text"] for v in content if isinstance(v, dict)
                                  and v.get("type") == "output_text" and isinstance(v.get("text"), str))
                if not value.strip():
                    continue
                kind = "message"
            else:
                kind = "tool_call" if typ == "function_call" else "tool_result"
                value = m.get("arguments") if typ == "function_call" else m.get("output")
            text, truncated = _text(value, red)
            items.append({"id": mid, "agent_id": aid, "kind": kind, "tool": tool, "text": text,
                          "call_id": m.get("call_id"),
                          "truncated": truncated, "at": at.replace(" ", "T") + "Z" if at and "+" not in at and not at.endswith("Z") else at})
        result.update(available=True, items=items, cursor=max([mid for mid, *_ in rows], default=max(0, after)))
    except (sqlite3.Error, ValueError, TypeError):
        result["note"] = "The Strix activity store is temporarily unavailable."
    return result
