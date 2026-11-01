"""Workshop SQL cell magic with isolated databases and a portable saved rule."""
import os
import json
from pathlib import Path
import re
import tempfile

from workshop.behavioral import ROOT
from workshop.engine import Database
from workshop.launch import setup_statements
from workshop.notebooks import split_statements, strip_leading_comments


class NotebookSession:
    def __init__(self, rule_file=None, statements=None):
        self._temporary = tempfile.TemporaryDirectory(prefix="workshop-notebook-")
        self.database = Path(self._temporary.name) / "workshop.duckdb"
        self.engine = Database(self.database)
        self.rule_file = Path(rule_file or os.environ.get("WORKSHOP_RULE_FILE", ROOT / "artifacts/participant_rule.sql"))
        self._loaded_rule = None
        try:
            self.engine.script(";\n".join(setup_statements() if statements is None else statements) + ";")
            self.refresh_rule()
        except Exception:
            self._temporary.cleanup()
            raise

    def refresh_rule(self):
        if self.rule_file.exists():
            sql = self.rule_file.read_text()
            if sql != self._loaded_rule:
                if not re.match(r"\s*CREATE\s+OR\s+REPLACE\s+VIEW\s+main\.workshop_alerts\s+AS\b", strip_leading_comments(sql), re.I):
                    raise ValueError("Saved rule uses the old format or an unsupported object. Rename the saved file to keep a copy, then rerun notebook 03 setup and save main.workshop_alerts as a SQL view.")
                self.engine.script(sql)
                self._loaded_rule = sql

    def execute(self, sql, save_rule=False, check_binding=None):
        self.refresh_rule()
        if '__TODO_' in sql:
            raise ValueError('Detection incomplete: replace each __TODO_...__ using the field hints, then rerun this cell.')
        if check_binding:
            from workshop.normalization import check_detection
            return check_detection(self.engine, check_binding, sql)
        if save_rule:
            statements = split_statements(sql)
            if len(statements) != 1 or not re.match(
                r"\s*CREATE\s+OR\s+REPLACE\s+VIEW\s+main\.workshop_alerts\s+AS\b", strip_leading_comments(sql), re.I
            ):
                raise ValueError("--save-rule requires one CREATE OR REPLACE VIEW main.workshop_alerts AS statement")
            self.engine.script(sql)  # A failing definition must never replace the saved rule.
            self.rule_file.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(mode="w", dir=self.rule_file.parent, delete=False) as handle:
                handle.write(sql)
                temporary = Path(handle.name)
            temporary.replace(self.rule_file)
            self._loaded_rule = sql
            print(f"Saved participant rule: {self.rule_file}")
            return []
        if len(split_statements(sql)) != 1:
            raise ValueError("Run one SQL statement per cell.")
        return self.engine.query(sql)

    def close(self):
        self._temporary.cleanup()


def json_result(rows, force=False):
    """Unwrap a nested single-column result for readable JSON inspection."""
    def nested(value):
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, (dict, list)):
                    return parsed
            except ValueError:
                pass
        return value

    values = [nested(next(iter(row.values()))) for row in rows if len(row) == 1]
    if rows and len(values) == len(rows) and all(isinstance(value, (dict, list)) for value in values):
        return True, values[0] if len(values) == 1 else values
    return force, rows


def load_ipython_extension(ipython):
    from itables import init_notebook_mode
    from itables import options
    options.style = "table-layout:auto;width:auto;margin:0;caption-side:bottom"
    init_notebook_mode(all_interactive=True, connected=False)

    def sql_magic(line, cell):
        option = line.strip()
        binding = re.fullmatch(r'--check-binding (eks|gke|aks|normalized|normalized-success)', option)
        if option not in ("", "--save-rule", "--json") and not binding:
            raise ValueError("Use %%sql, %%sql --json, %%sql --save-rule or %%sql --check-binding <eks|gke|aks|normalized|normalized-success>")
        session = ipython.user_ns.get("session")
        if not isinstance(session, NotebookSession):
            raise RuntimeError("Run the notebook setup cell first.")
        rows = session.execute(cell, save_rule=option == "--save-rule",
                               check_binding=binding.group(1) if binding else None)
        if rows:
            use_json, payload = json_result(rows, force=line.strip() == "--json")
            if use_json:
                from IPython.display import JSON
                return JSON(payload, expanded=True)
            import pandas as pd
            from itables import show
            show(pd.DataFrame(rows), connected=False, maxBytes=0,
                 pageLength=25, lengthMenu=[10, 25, 50, 100])
            return None
        print("Statement completed; no rows returned.")
    ipython.register_magic_function(sql_magic, magic_kind="cell", magic_name="sql")
