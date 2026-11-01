"""Preload native DuckDB UI SQL notebooks into an isolated, checkout-local UI store.

Uses the serialization-v3/table layout inspected in DuckDB UI's published frontend.
This is a version-sensitive adapter, not a public notebook import API. SQL files remain portable.
"""

import json
from pathlib import Path
import uuid

from workshop.behavioral import ROOT, literal

NOTEBOOK_EDITION = "k8s-enterprise-workshop-v4-binding-exercises"


def strip_leading_comments(sql):
    """Keep SQL text intact while removing introductory comments for presentation."""
    import re

    return re.sub(r"\A\s*(?:(?:--[^\n]*(?:\n|$)|/\*.*?\*/)\s*)*", "", sql, flags=re.S).strip()


def split_statements(sql):
    """Split outside SQL strings/comments, including semicolons inside teaching examples."""
    result, start, i, state = [], 0, 0, "normal"
    while i < len(sql):
        current, following = sql[i], sql[i:i + 2]
        if state == "line":
            if current == "\n":
                state = "normal"
        elif state == "block":
            if following == "*/":
                state = "normal"
                i += 1
        elif state in ("'", '"'):
            if current == state:
                if following == state * 2:
                    i += 1
                else:
                    state = "normal"
        elif following == "--":
            state = "line"
            i += 1
        elif following == "/*":
            state = "block"
            i += 1
        elif current in ("'", '"'):
            state = current
        elif current == ";":
            piece = sql[start:i + 1].strip()
            if strip_leading_comments(piece):
                result.append(piece)
            start = i + 1
        i += 1
    remainder = sql[start:].strip()
    if strip_leading_comments(remainder):
        result.append(remainder)
    return result


def seed_sql(database_name, directory=None):
    directory = Path(directory or ROOT / ".workshop")
    directory.mkdir(parents=True, exist_ok=True)
    sql = [f"ATTACH IF NOT EXISTS {literal(directory / 'ui.db')} AS _duckdb_ui",
           "CREATE TABLE IF NOT EXISTS _duckdb_ui.main.notebooks(id UUID PRIMARY KEY, name VARCHAR NOT NULL, created TIMESTAMP NOT NULL)",
           """CREATE TABLE IF NOT EXISTS _duckdb_ui.main.notebook_versions(
              notebook_id UUID NOT NULL, version INTEGER NOT NULL, title VARCHAR NOT NULL,
              json VARCHAR NOT NULL, created TIMESTAMP NOT NULL, expires TIMESTAMP,
              PRIMARY KEY(notebook_id,version))""",
           "CREATE TABLE IF NOT EXISTS _duckdb_ui.main.current_notebook_id(id UUID NOT NULL)",
           "CREATE TABLE IF NOT EXISTS _duckdb_ui.main.has_onboarded AS SELECT true AS has_onboarded"]
    first = None
    for path in sorted((ROOT / "notebooks" / "sql").glob("*.sql")):
        identity = str(uuid.uuid5(uuid.NAMESPACE_URL, NOTEBOOK_EDITION + "/" + database_name + "/" + path.name))
        first = first or identity
        cells = [{"cellId": i + 1, "query": query.strip(), "useDatabase": database_name}
                 for i, query in enumerate(path.read_text().split("-- %%")) if query.strip()]
        payload = {"notebookSerializationFormat": 3, "version": 1, "cells": cells,
                   "currentDatabase": database_name, "viewMode": {"mode": "default"}}
        title = path.stem.replace("_", " ") + " — explained"
        sql += [f"INSERT INTO _duckdb_ui.main.notebooks SELECT {literal(identity)}::UUID, {literal('workshop-explained-' + path.stem)}, current_timestamp WHERE NOT EXISTS (SELECT 1 FROM _duckdb_ui.main.notebooks WHERE id={literal(identity)}::UUID)",
                f"INSERT INTO _duckdb_ui.main.notebook_versions SELECT {literal(identity)}::UUID, 1, {literal(title)}, {literal(json.dumps(payload))}, current_timestamp, NULL WHERE NOT EXISTS (SELECT 1 FROM _duckdb_ui.main.notebook_versions WHERE notebook_id={literal(identity)}::UUID)"]
    if first:
        sql.append(f"INSERT INTO _duckdb_ui.main.current_notebook_id SELECT {literal(first)}::UUID WHERE NOT EXISTS (SELECT 1 FROM _duckdb_ui.main.current_notebook_id)")
    return sql
