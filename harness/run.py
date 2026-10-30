"""Drive the matrix. Resumable: completed (model, defence, trap, placement, rep) cells are skipped.

    python -m harness.run --baseline                       # clean folder, no defence: allowlist discovery
    python -m harness.run --models all --reps 20           # the 720-session matrix
    python -m harness.run --models lite --defences none --placements visible,meta --reps 20
"""

import argparse
import concurrent.futures
import json
import threading
import time
import uuid

from . import defences as D
from .common import (BUDGET_USD, DEFENCES, FOLDERS, GUARDRAIL_PER_TEXT_UNIT, INFRA_USD_PER_HOUR, MODELS, PRICES,
                     RAW_SESSIONS, RESULTS, TRAPS, append_jsonl, client, log, read_jsonl)

BASELINE = RESULTS / "raw" / "baseline.jsonl"
GUARDRAIL_TEXT_UNITS_PER_SESSION = 15  # ~4 documents screened + the task on each model call; generous
_lock = threading.Lock()


RETRY_STOPS = ("lambda_error", "invoke_error", "error")
MAX_ERROR_RATE = 0.10


class BudgetExceeded(Exception):
    pass


class TooManyErrors(Exception):
    pass


def session_cost(rec):
    pin, pout = PRICES[rec["model_id"]]
    c = rec.get("input_tokens", 0) / 1000 * pin + rec.get("output_tokens", 0) / 1000 * pout
    if rec.get("guardrail"):
        c += GUARDRAIL_TEXT_UNITS_PER_SESSION * GUARDRAIL_PER_TEXT_UNIT
    return c


def infra_hours():
    stack = client("cloudformation").describe_stacks(StackName="ith-main")["Stacks"][0]
    return (time.time() - stack["CreationTime"].timestamp()) / 3600


def spend_estimate():
    recs = read_jsonl(RAW_SESSIONS) + read_jsonl(BASELINE)
    return sum(session_cost(r) for r in recs) + infra_hours() * INFRA_USD_PER_HOUR


def invoke(model_key, defence, trap, placement, rep, phase, out_path):
    flags = D.payload_flags(defence)
    run_id = uuid.uuid4().hex
    ev = {"mode": "session", "run_id": run_id, "model_id": MODELS[model_key], "folder": FOLDERS[(trap, placement)],
          **flags}
    lam = client("lambda", read_timeout=330, retries={"max_attempts": 0})
    ts = time.time()
    try:
        r = lam.invoke(FunctionName="ith-agent", Payload=json.dumps(ev))
        trace = json.loads(r["Payload"].read())
        if "errorMessage" in trace:
            trace = {"stop_reason": "lambda_error", "error": trace["errorMessage"], "tool_calls": [],
                     "t_start": ts, "t_end": time.time()}
    except Exception as e:  # noqa: BLE001
        trace = {"stop_reason": "invoke_error", "error": str(e), "tool_calls": [], "t_start": ts, "t_end": time.time()}
    rec = {"run_id": run_id, "ts": ts, "phase": phase, "model": model_key, "model_id": MODELS[model_key],
           "defence": defence, "trap": trap, "placement": placement, "rep": rep, **flags, **trace}
    rec["cost_usd"] = round(session_cost(rec), 6)
    with _lock:
        append_jsonl(out_path, rec)
    return rec


def done_cells(path):
    ok = set()
    for r in read_jsonl(path):
        if r.get("stop_reason") not in RETRY_STOPS:
            ok.add((r["model"], r["defence"], r["trap"], r["placement"], r["rep"]))
    return ok


def run_cells(cells, phase, out_path, concurrency):
    n, t0 = len(cells), time.time()
    with concurrent.futures.ThreadPoolExecutor(concurrency) as ex:
        futs, it = set(), iter(cells)
        done = errors = 0
        while True:
            while len(futs) < concurrency:
                cell = next(it, None)
                if cell is None:
                    break
                est = spend_estimate()
                if est > BUDGET_USD:
                    raise BudgetExceeded(f"spend estimate ${est:.2f} > ${BUDGET_USD}")
                futs.add(ex.submit(invoke, *cell, phase, out_path))
            if not futs:
                break
            fin, futs = concurrent.futures.wait(futs, return_when=concurrent.futures.FIRST_COMPLETED)
            for f in fin:
                r = f.result()
                done += 1
                errors += r.get("stop_reason") in RETRY_STOPS
                if done >= 10 and errors / done > MAX_ERROR_RATE:
                    raise TooManyErrors(f"{errors}/{done} sessions errored; last: {r.get('error', '')[:200]}")
                calls = ",".join(c["name"][0] for c in r.get("tool_calls", []))
                log(f"[{done}/{n}] {r['model']:5} {r['defence']:15} {r['trap']}/{r['placement']} rep{r['rep']:02} "
                    f"{r.get('stop_reason')} calls={calls} ${r['cost_usd']:.4f} "
                    f"({(time.time() - t0) / done:.1f}s/session)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="all")
    ap.add_argument("--defences", default="all")
    ap.add_argument("--traps", default=",".join(TRAPS))
    ap.add_argument("--placements", default="comment")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--baseline", action="store_true")
    a = ap.parse_args()
    models = list(MODELS) if a.models == "all" else a.models.split(",")

    if a.baseline:
        cells = [(m, "none", "clean", None, r) for m in models for r in range(2)]
        cells = [c for c in cells if c not in done_cells(BASELINE)]
        D.reset()
        run_cells(cells, "baseline", BASELINE, a.concurrency)
        log(f"baseline done; spend estimate ${spend_estimate():.2f}")
        return

    defences = DEFENCES if a.defences == "all" else a.defences.split(",")
    phase = "matrix" if a.placements == "comment" else "placement"
    done = done_cells(RAW_SESSIONS)
    D.reset()
    try:
        for d in defences:
            cells = [(m, d, t, p, r) for m in models for t in a.traps.split(",") for p in a.placements.split(",")
                     for r in range(a.reps)]
            cells = [c for c in cells if c not in done]
            if not cells:
                log(f"{d}: nothing to do")
                continue
            log(f"=== {d}: {len(cells)} sessions; spend so far ${spend_estimate():.2f}")
            D.apply(d)
            try:
                run_cells(cells, phase, RAW_SESSIONS, a.concurrency)
            finally:
                D.remove(d)
    except (BudgetExceeded, TooManyErrors) as e:
        log(f"ABORT: {e}")
        raise SystemExit(2)
    log(f"done; spend estimate ${spend_estimate():.2f}")


if __name__ == "__main__":
    main()
