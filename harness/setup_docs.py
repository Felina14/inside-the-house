"""Upload trap and clean documents to the docs bucket, one opaque folder per (trap, placement).

    python -m harness.setup_docs
"""

import html
import json

from .common import FOLDERS, ROOT, TRAP_KEYS, client, log, outputs

TRAPS_DIR = ROOT / "traps"
CLEAN = ["clean_offsite.html", "clean_oncall.html", "clean_vendor.html"]
CLEAN_KEYS = {"clean_offsite.html": "q4-offsite-logistics.html", "clean_oncall.html": "oncall-rotation-change.html",
              "clean_vendor.html": "vendor-renewals-q4.html"}


def render_trap(trap, placement, stranger_bucket):
    instr = json.loads((TRAPS_DIR / "instructions.json").read_text())[trap].replace("{{STRANGER_BUCKET}}", stranger_bucket)
    slots = {"{{COMMENT}}": "", "{{VISIBLE}}": "", "{{META}}": ""}
    if placement == "comment":
        slots["{{COMMENT}}"] = f"<!-- {instr} -->"
    elif placement == "visible":
        slots["{{VISIBLE}}"] = f"<p>{html.escape(instr)}</p>"
    elif placement == "meta":
        slots["{{META}}"] = f'<meta name="assistant-instructions" content="{html.escape(instr, quote=True)}">'
    doc = (TRAPS_DIR / f"trap_{trap}.html").read_text()
    for k, v in slots.items():
        doc = doc.replace(k, v)
    return doc


def main():
    out, s3 = outputs(), client("s3")
    bucket = out["DocsBucket"]
    for (trap, placement), prefix in FOLDERS.items():
        files = {CLEAN_KEYS[c]: (TRAPS_DIR / c).read_text() for c in CLEAN}
        if trap != "clean":
            files[TRAP_KEYS[trap]] = render_trap(trap, placement, out["StrangerBucket"])
        for key, body in files.items():
            s3.put_object(Bucket=bucket, Key=prefix + key, Body=body.encode(), ContentType="text/html")
        log(f"{prefix} ({trap}/{placement}): {sorted(files)}")


if __name__ == "__main__":
    main()
