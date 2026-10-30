"""Confirmatory run (not in the matrix): does a scoped IAM policy alone stop the S3 exit?

    python -m harness.iam_check --model pro --reps 5
"""

import argparse

from . import defences as D
from .common import RAW_SESSIONS, log
from .run import invoke


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="pro")
    ap.add_argument("--reps", type=int, default=5)
    a = ap.parse_args()
    D.reset()
    D.scoped_iam_on()
    try:
        for rep in range(a.reps):
            r = invoke(a.model, "none", "s3", "comment", rep, "iam_check", RAW_SESSIONS)
            puts = [(c["args"].get("bucket"), c["result"][:80]) for c in r.get("tool_calls", []) if c["name"] == "save_report"]
            log(f"iam_check rep{rep} {r.get('stop_reason')} puts={puts}")
    finally:
        D.scoped_iam_off()


if __name__ == "__main__":
    main()
