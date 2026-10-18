"""ONE command that regenerates every number, table and figure in the paper.

    python3 reproduce.py            # everything (~45 min on 2 cores)
    python3 reproduce.py --quick    # skip the scaling study and the second reproducibility run (~15 min)

Order (each step reads only files written by earlier steps):
  1 run_all.py                 main pipeline -> out/results.json (r*, certificates, Tables 4-5, 7-8 data,
                               Algorithm 1, sensitivity, zero burn, small-instance enumeration, emulation)
  2 tables.py, l2_stats.py,    tables, paired emulation statistics, figures, named values
    charts.py, vals.py
  3 validate_contributions.py  reference simulator, draw rates, STIX, paper values, four passes,
                               NP-hardness reduction -> out/validation.json
  4 extra_experiments.py       robust heuristics + persona rotation -> out/extra_e13.json,
                               horizon scaling -> out/extra_e2.json
    ablation.py                per-gap ablations G1-G4 (Section 7.8, Table 15) -> out/ablation.json
  5 test_pb.py, test_encoding_vs_checker.py, test_consistency.py -> out/tests.json
  6 check_reproducible.py      second run of step 1, compared with the first -> out/repro.json
Every number in the paper is read from these out/*.json files by make_paper_docx.py.
"""
import os, subprocess, sys, time

QUICK = "--quick" in sys.argv
STEPS = [
    ["run_all.py"], ["tables.py"], ["l2_stats.py"], ["charts.py"], ["vals.py"],
    ["validate_contributions.py"],
    ["extra_experiments.py", "e1", "e3"],
    ["ablation.py"],
    *([] if QUICK else [["extra_experiments.py", "e2"]]),
    ["test_pb.py"], ["test_encoding_vs_checker.py"], ["test_consistency.py"],
    *([] if QUICK else [["check_reproducible.py"]]),
]
ENV = {"extra_experiments.py e1 e3": "out/extra_e13.json", "extra_experiments.py e2": "out/extra_e2.json"}


def main():
    t_all = time.time()
    import shutil
    shutil.rmtree("out", ignore_errors=True)   # start from an empty output folder
    os.makedirs("out")
    for step in STEPS:
        key = " ".join(step)
        env = dict(os.environ)
        if key in ENV:
            env["EXTRA_OUT"] = ENV[key]
        t0 = time.time()
        print(f"[reproduce] {key} ...", flush=True)
        r = subprocess.run([sys.executable, *step], env=env, stdout=subprocess.DEVNULL)
        if r.returncode != 0:
            print(f"[reproduce] FAILED: {key} (exit {r.returncode})"); return r.returncode
        print(f"[reproduce] {key} done in {time.time() - t0:.0f} s", flush=True)
    print(f"[reproduce] all steps passed in {(time.time() - t_all) / 60:.1f} min")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
