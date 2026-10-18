"""Per-gap ablations (writes out/ablation.json).

Each ablation removes ONE capability that closes a gap of Table 2b, re-solves with the same
procedure as the main result (exact max-min search, ties broken by the highest Q-med), and the
resulting schedule is then judged exactly like every other schedule in the paper: the independent
rule checker and the common evaluator on the FULL model, minimum-change repair if it breaks a rule,
and the L2 socket emulation with common random numbers, compared pairwise with the ZSTP max-min
schedule (worst-profile mean difference, 95% paired bootstrap, 10,000 replicates).

  A1  G1 recognition    planner is recognition-blind: tau_d = tau_dp = beyond the horizon for every
                        profile (no type or fingerprint burn in the model); all hard rules kept.
  A2  G2 identity       planner is identity-blind: identity rules C12/C14 removed and no fingerprint
                        burn (tau_dp beyond the horizon); type burn and all other rules kept.
  A3  G3 temporal       planner re-solves one slot at a time (slots before t fixed, later slots empty)
                        without the inter-slot rules C8, C10a, C10b; burn and identity kept.
  A3h G3 temporal       (supplementary) full horizon, but C8, C10a, C10b removed.
  A4  G4 assurance      objective replaced by the expected payoff under a uniform prior over the four
                        profiles (sum of Q_theta, one RC2 call); full model and every rule kept.

The ablation encoder below is a copy of encoder.Enc._build with switches; encoder.py is unchanged.
"""
import copy, hashlib, json, math, os, random, time
import instance, encoder, solvers, evaluator, baselines, emulation_l2 as em
from encoder import Enc, TRUE, FALSE

OUT = "out"
N_EP = 100
B_REPS, SEED = 10000, 20261003


class AblEnc(Enc):
    def __init__(self, inst, drop=()):
        self.drop = set(drop)
        super().__init__(inst)

    def _build(self):
        I = self.inst
        K, Z, H, P = I["K"], I["Z"], I["H"], I["P"]
        fp = I["fingerprint"]
        X = {(i, z, t, r): self.v("x", i, z, t, r) for i in K for z in Z for t in range(H) for r in P}
        self.X = X
        for (i, z, t, r), x in X.items():
            if not I["slot_valid"][t]:
                self.hard.append([-x])
        for (i, z, t, r), x in X.items():
            if z in I["air_gapped"] and i in I["air_gap_crossing_types"]:
                self.hard.append([-x])
            elif not (i in I["type_zone_ok"].get(z, []) and i in I["role_types"][r] and z in I["role_zones"][r]):
                self.hard.append([-x])
        for t in range(H):
            self.atmost([X[(i, z, t, r)] for i in K for z in Z for r in P], I["B_t"])
            for z in Z:
                self.atmost([X[(i, z, t, r)] for i in K for r in P], I["B_z"])
        pres = {(i, z, t): self.OR(("pres", i, z, t), [X[(i, z, t, r)] for r in P]) for i in K for z in Z for t in range(H)}
        fps = sorted(set(fp.values()))
        used = {(f, t): self.OR(("used", f, t), [X[(i, z, t, r)] for i in K for z in Z for r in P if fp[r] == f])
                for f in fps for t in range(H)}
        for a, b in I["conflicts"]:
            for z in Z:
                for t in range(H):
                    pa, pb = pres[(a, z, t)], pres[(b, z, t)]
                    if pa is not FALSE and pb is not FALSE:
                        self.hard.append([-pa, -pb])
        if "C8" not in self.drop:
            for i in K:
                for z in Z:
                    for r in P:
                        chs = []
                        for t in range(1, H):
                            a, b = X[(i, z, t, r)], X[(i, z, t - 1, r)]
                            c = self.v("ch", i, z, r, t)
                            self.hard += [[-c, a, b], [-c, -a, -b], [c, -a, b], [c, a, -b]]
                            chs.append(c)
                        self.atmost(chs, I["churn_max"])
        for pn, p in I["paths"].items():
            hz, hj, _ = p["hops"][p["critical"]]
            y = [self.OR(("y", pn, t), [X[(i, hz, t, r)] for i in K for r in P if hj in I["trap_techniques"][i]]) for t in range(H)]
            if "C10a" not in self.drop:
                self.atleast(y, math.ceil(p["rho"] * H))
            if "C10b" not in self.drop:
                W = I["W_gap"]
                for t in range(H - W + 1):
                    self.hard.append([l for l in [y[s] for s in range(t, t + W)] if l is not FALSE])
        for t in range(H):
            for f in fps:
                if "C14" not in self.drop:
                    self.atmost([X[(i, z, t, r)] for i in K for z in Z for r in P if fp[r] == f], 1)
                if "C12" not in self.drop:
                    for z in Z:
                        self.atmost([X[(i, z, t, r)] for i in K for r in P if fp[r] == f], 1)
        for th in I["profiles"]:
            c = I["coef"][th]
            u = {}
            for i in K:
                for z in Z:
                    td = I["tau_d"][th][z]
                    for t in range(H):
                        u[(i, z, t)] = FALSE if t < td else self.AND(("u", th, i, z, t), [pres[(i, z, s)] for s in range(t - td, t)])
            tp = I["tau_dp"][th]
            vv = {(f, t): FALSE if t < tp else self.AND(("v", th, f, t), [used[(f, s)] for s in range(t - tp, t)])
                  for f in fps for t in range(H)}
            d = {k: self.AND(("d", th) + k, [x, self.NEG(u[k[:3]]), self.NEG(vv[(fp[k[3]], k[2])])]) for k, x in X.items()}
            terms = []
            for pn, p in I["paths"].items():
                n = len(p["hops"])
                for t in range(H):
                    covs = []
                    for hi, (hz, hj, _) in enumerate(p["hops"]):
                        cv = self.OR(("cov", th, pn, hi, t), [d[(i, hz, t, r)] for i in K for r in P if hj in I["trap_techniques"][i]])
                        covs.append(cv)
                        if cv is not FALSE:
                            terms.append(("L3", c["L3"][f"{pn}|{hi}|{t}"], cv))
                    e = self.OR(("e", th, pn, t), covs[:n - 1])
                    if e is not FALSE:
                        terms.append(("L4", c["L4"][f"{pn}|{t}"], e))
            g = {}
            for j in I["techniques"]:
                g[j] = self.OR(("g", th, j), [d[k] for k in X if j in I["trap_techniques"][k[0]]])
                if g[j] is not FALSE:
                    terms.append(("L2", c["L2_tech"][j], g[j]))
            for fam in I["families"]:
                fv = self.OR(("fam", th, fam), [g[j] for j in I["techniques"] if I["techniques"][j]["family"] == fam])
                if fv is not FALSE:
                    terms.append(("L2", c["L2_fam"][fam], fv))
            for k, dl in d.items():
                if dl is not FALSE:
                    terms.append(("L1", c["L1"][f"{k[0]}|{k[3]}"], dl))
            self.terms[th] = terms


def blind(inst, type_burn=True, fp_burn=True):
    b = copy.deepcopy(inst)
    for th in b["profiles"]:
        if not type_burn:
            b["tau_d"][th] = {z: 99 for z in b["Z"]}
        if not fp_burn:
            b["tau_dp"][th] = 99
    return b


def maxmin_schedule(enc):
    mm = solvers.maxmin(enc)
    tb = solvers.maxmin_tiebreak(enc, mm["r_star_int"], "med")
    return tb["schedule"], mm["r_star_int"]


def myopic(inst, drop):
    """Re-solve one slot at a time: earlier slots fixed, later slots empty, objective = max-min of
    the credit earned so far (burn from earlier slots included)."""
    fixed = []
    for t in range(inst["H"]):
        enc = AblEnc(inst, drop)
        keep = set(fixed)
        for (i, z, tt, r), x in enc.X.items():
            if tt < t:
                enc.hard.append([x] if (i, z, tt, r) in keep else [-x])
            elif tt > t:
                enc.hard.append([-x])
        sched, _ = maxmin_schedule(enc)
        fixed = sorted(set(fixed) | {d for d in sched if d[2] == t})
    return fixed


def expected_payoff(inst):
    """Exact maximum of sum_theta Q_theta (uniform prior), by the same SAT threshold search used for
    r* applied to the single summed objective; the optimum is cross-checked with CP-SAT."""
    enc = encoder.Enc(inst)
    per_profile = enc.terms
    enc.terms = {"sum": [t for th in per_profile for t in per_profile[th]]}
    res = solvers.maxmin(enc)
    enc.terms = per_profile
    return res["schedule"], res["r_star_int"]


def expected_payoff_prior(inst, prior):
    """Exact maximum of sum_theta prior_theta * Q_theta for an integer prior (same SAT search)."""
    enc = encoder.Enc(inst)
    per_profile = enc.terms
    enc.terms = {"sum": [(L, w * prior[th], l) for th in per_profile for (L, w, l) in per_profile[th] if prior[th] > 0]}
    res = solvers.maxmin(enc)
    enc.terms = per_profile
    return res["schedule"]


PRIORS = {th: {t2: (7 if t2 == th else 1) for t2 in ("low", "med", "high", "burst")} for th in ("low", "med", "high", "burst")}


def expected_payoff_cpsat(inst, secs=1800):
    import cross_check
    m, x, Q, _ = cross_check.build(inst)
    m.Maximize(sum(Q.values()))
    s, st = cross_check._solve(m, secs)
    return {"status": st, "objective_int": int(s.ObjectiveValue()), "bound_int": int(s.BestObjectiveBound())}


def emulate_all(inst, sched):
    seed_key = f"{inst['hash']}|L2"
    return {th: em.emulate(inst, sched, th, N_EP, False, seed_key) for th in inst["profiles"]}


def paired(qa, qb):
    """Worst-profile mean difference A - B with 95% paired bootstrap (same as l2_stats.py)."""
    rnd = random.Random(SEED)
    n = len(next(iter(qa.values())))
    def wm(q, idx):
        return min(sum(q[th][i] for i in idx[th]) / len(idx[th]) for th in q)
    full = {th: list(range(n)) for th in qa}
    d0 = wm(qa, full) - wm(qb, full)
    ds = []
    for _ in range(B_REPS):
        idx = {th: [rnd.randrange(n) for _ in range(n)] for th in qa}
        ds.append(wm(qa, idx) - wm(qb, idx))
    ds.sort()
    return {"diff": d0, "ci95": [ds[int(0.025 * B_REPS)], ds[int(0.975 * B_REPS) - 1]]}


def describe(inst, sched, emu, ref_q):
    ev = evaluator.evaluate_all(inst, sched)
    st = evaluator.static_metrics(inst, sched)
    viol = evaluator.check(inst, sched)
    q = {th: emu[th]["Q_list"] for th in emu}
    pb = paired(ref_q, q) if ref_q is not None else None
    return {
        "schedule": [list(d) for d in evaluator.norm(sched)], "deployments": len(evaluator.norm(sched)),
        "violations": {k: len(v) for k, v in viol.items()}, "feasible": not viol,
        "model": {th: v["Q"] for th, v in ev["per_profile"].items()}, "worst_case": ev["r_min"], "worst_profile": ev["worst_profile"],
        "burn_burst_pct": ev["per_profile"]["burst"]["Burn_any_pct"], "pburn_burst_pct": ev["per_profile"]["burst"]["PBurn_pct"],
        "tburn_burst_pct": ev["per_profile"]["burst"]["TBurn_pct"],
        "C14_leaks": st["C14_leaks"], "path_persistence_pct": st["path_persistence_pct"],
        "early_intercept_med_pct": ev["per_profile"]["med"]["early_intercept_pct"],
        "hop_coverage_med_pct": ev["per_profile"]["med"]["hop_coverage_pct"],
        "emulated": {th: emu[th]["Q_mean"] for th in emu}, "emulated_worst_mean": min(emu[th]["Q_mean"] for th in emu),
        "emulated_recognized_pct": {th: emu[th]["recognized_pct_mean"] for th in emu},
        "paired_vs_maxmin": pb,
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    inst = instance.build_xlarge()
    enc = encoder.Enc(inst)
    ref, rstar = maxmin_schedule(enc)
    ref_emu = emulate_all(inst, ref)
    ref_q = {th: ref_emu[th]["Q_list"] for th in ref_emu}
    same = AblEnc(inst)
    res = {"meta": {"instance_hash": inst["hash"], "episodes": N_EP, "bootstrap": B_REPS, "seed": SEED,
                    "r_star": rstar / inst["scale"],
                    "ablation_encoder_identical_when_nothing_removed": same.hard == enc.hard and same.terms == enc.terms,
                    "hard_clauses": len(enc.hard)},
           "ZSTP max-min": describe(inst, ref, ref_emu, None)}
    abl = {
        "A1 recognition-blind (G1)": lambda: maxmin_schedule(AblEnc(blind(inst, False, False)))[0],
        "A2 identity-blind (G2)": lambda: maxmin_schedule(AblEnc(blind(inst, True, False), drop={"C12", "C14"}))[0],
        "A3 per-slot re-solve, no inter-slot rules (G3)": lambda: myopic(inst, {"C8", "C10a", "C10b"}),
        "A3h full horizon, no inter-slot rules (G3, supplementary)": lambda: maxmin_schedule(AblEnc(inst, drop={"C8", "C10a", "C10b"}))[0],
        "A4 expected payoff, uniform prior (G4)": lambda: expected_payoff(inst)[0],
    }
    for th, pr in PRIORS.items():
        abl[f"A4-{th} expected payoff, prior 0.7 on theta_{th} (G4)"] = (lambda pr=pr: expected_payoff_prior(inst, pr))
    for name, fn in abl.items():
        ts = time.time()
        sched = fn()
        rec = describe(inst, sched, emulate_all(inst, sched), ref_q)
        rec["solve_seconds"] = round(time.time() - ts, 1)
        if not rec["feasible"]:
            rep, info = baselines.repair(inst, sched, enc)
            rr = describe(inst, rep, emulate_all(inst, rep), ref_q)
            rr["repair_changes"] = info["changes"]
            rec["repaired"] = rr
        res[name] = rec
        print(name, rec["feasible"], rec["violations"], round(rec["worst_case"], 2), round(rec["emulated_worst_mean"]),
              rec["paired_vs_maxmin"], ("repaired", round(rec["repaired"]["worst_case"], 2), rec["repaired"]["paired_vs_maxmin"]) if "repaired" in rec else "", flush=True)
    sched4, sum_int = expected_payoff(inst)
    res["meta"]["A4_sum_optimum_int"] = sum_int
    res["meta"]["A4_cpsat_check"] = expected_payoff_cpsat(inst)
    print("A4 cross-check", sum_int, res["meta"]["A4_cpsat_check"], flush=True)
    res["meta"]["seconds"] = round(time.time() - t0, 1)
    json.dump(res, open(f"{OUT}/ablation.json", "w"), indent=1)
    print("done", res["meta"]["seconds"])


if __name__ == "__main__":
    main()
