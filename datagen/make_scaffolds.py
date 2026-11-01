"""Derive the participant scaffold (labs/lab2_ocsf) from the solutions.

A solution line ending in `-- @todo[TYPE]: hint` has its expression replaced by a typed NULL,
so the scaffold still runs end to end and only the marked fields come out empty.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC, DST = ROOT / "solutions" / "lab2_ocsf", ROOT / "labs" / "lab2_ocsf"

TODO = re.compile(r"-- @todo\[(?P<type>[^\]]+)\]: (?P<hint>.*)$")
ASSIGN = re.compile(r"^(?P<indent>\s*)(?P<name>\w+) := .*?(?P<comma>,?)\s*$")    # struct field
ALIAS = re.compile(r"^(?P<indent>\s*).*? AS (?P<name>\w+)(?P<comma>,?)\s*$")     # select column


def scaffold_line(line):
    m = TODO.search(line)
    if not m:
        return line
    code = line[: m.start()]
    typed_null = f"NULL::{m['type']}"
    hint = f"-- TODO(lab2): {m['hint']}"
    if a := ASSIGN.match(code):
        return f"{a['indent']}{a['name']} := {typed_null}{a['comma']} {hint}"
    if a := ALIAS.match(code):
        return f"{a['indent']}{typed_null} AS {a['name']}{a['comma']} {hint}"
    raise ValueError(f"cannot scaffold: {line!r}")


def main():
    DST.mkdir(parents=True, exist_ok=True)
    for sql in sorted(SRC.glob("*.sql")):
        out = "\n".join(scaffold_line(l) for l in sql.read_text().splitlines()) + "\n"
        (DST / sql.name).write_text(out)
        print(f"{sql.name}: {out.count('TODO(lab2)')} TODOs")


if __name__ == "__main__":
    main()
