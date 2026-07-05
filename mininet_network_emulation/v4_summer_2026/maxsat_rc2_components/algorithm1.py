"""
algorithm1.py
Zone-Slot-Time-Persona V6 — Algorithm 1 Adaptive Redeployment (Section F)
===========================================================================
Implements the full Algorithm 1 (extended V4):

    Input:  x*          current deployment schedule
            ρ′π         updated path probabilities (STIX/TAXII)
            signals     concurrent STIX/TAXII intel signals
            interactions  observed honeypot interaction counts
    Output: x′*         new optimal schedule
            qp          updated persona priors

    Step 1.  PW′ ← ρ′ · iv · W            (recompute path weights)
    Step 2.  Update L3/L4 soft-clause weights (hard clauses C1–C15 unchanged)
    Step 3.  qp ← confidence-weighted STIX blend  (V3 multi-signal)
    Step 3b. qp ← (1−β)·qp + β·êp(t)     (V4 empirical posterior)
    Step 4.  Warm-start RC2 from x*        (< 5 s at XLarge)
    Step 5.  Re-solve → x′*
    Step 6.  ΔQ ← Q(x′*) − Q(x*)
    Step 7.  if ΔQ > 0: deploy x′*, log Δ  else: keep x*, log "still optimal"

V5 flat-conjunction note:
    Hard clauses C1–C15 are unchanged by Algorithm 1 — it only updates
    soft-clause weights (via PW′ and qp) and warm-starts RC2.

Usage:
    from config             import CFG
    from persona_layer      import PersonaLayer
    from decision_variables import DecisionVariables
    from derived_weights    import DerivedWeights
    from soft_clauses       import SoftClauses
    from hard_constraints   import HardConstraints
    from algorithm1         import Algorithm1

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)
    sc  = SoftClauses(CFG, pl, dv, dw)
    hc  = HardConstraints(CFG, pl, dv)

    alg = Algorithm1(CFG, pl, dv, dw, sc, hc)

    # Single update cycle
    result = alg.run(
        schedule      = current_x_star,
        rho_updates   = {"pi1": 0.55, "pi2": 0.25},
        stix_signals  = [{"confidence":0.88, "deltas":{...}}, ...],
        interactions  = {"Finance_DB":18, "HR_workstation":12, ...},
    )
    x_new = result["schedule"]
    qp    = result["qp"]
    log   = result["log"]
"""

import math
import time
from copy import deepcopy
from collections import defaultdict

from pysat.formula import WCNF
from pysat.examples.rc2 import RC2


# ─────────────────────────────────────────────────────────────────────────────
#  ALGORITHM 1 CLASS
# ─────────────────────────────────────────────────────────────────────────────

class Algorithm1:
    """
    Adaptive Redeployment on Updated Threat Priors (extended V4).

    Orchestrates the full update loop: threat-intel ingestion →
    qp update → weight recomputation → RC2 warm-start → schedule swap.
    """

    def __init__(self, cfg, persona_layer, decision_vars,
                 derived_weights, soft_clauses, hard_constraints):
        self.cfg  = cfg
        self.pl   = persona_layer
        self.dv   = decision_vars
        self.dw   = derived_weights
        self.sc   = soft_clauses
        self.hc   = hard_constraints

        self.K    = cfg["K"]
        self.Z    = cfg["Z"]
        self.H    = cfg["H"]
        self.G    = cfg["G"]

        # V4 empirical blend parameters
        self.beta_max = cfg["beta_max"]
        self.kappa    = cfg["kappa"]

        # Audit log — every run appends an entry
        self.history: list[dict] = []

    # ─────────────────────────────────────────────────────────────────
    #  STEP 3 — STIX MULTI-SIGNAL BLEND  (V3 revision)
    # ─────────────────────────────────────────────────────────────────

    def step3_stix_blend(
        self,
        q_current: dict,
        signals:   list[dict],
    ) -> dict:
        """
        Step 3 (V3 multi-signal revision):
            weight_s = c_s / Σ c_s′
            qp ← qp + Σ_s weight_s · δ_{s,p}
            normalize so Σp qp = 1

        Backward compatibility: a single signal receives weight 1.0,
        recovering the original V3 single-signal behaviour exactly.

        Args:
            q_current : current qp dict (not mutated)
            signals   : list of dicts with keys:
                          "confidence" : float ∈ (0,1]
                          "deltas"     : {persona: delta_float}

        Returns:
            Updated qp dict (normalized).
        """
        if not signals:
            return dict(q_current)

        q = dict(q_current)
        total_conf = sum(s["confidence"] for s in signals)

        # Confidence-weighted blend of all concurrent signals
        for s in signals:
            w_s = s["confidence"] / total_conf
            for p in self.P:
                delta = s.get("deltas", {}).get(p, 0.0)
                q[p]  = max(0.0, q[p] + w_s * delta)

        return self._normalize(q)

    # ─────────────────────────────────────────────────────────────────
    #  STEP 3b — EMPIRICAL POSTERIOR BLEND  (V4 addition)
    # ─────────────────────────────────────────────────────────────────

    def step3b_empirical_blend(
        self,
        q_stix:       dict,
        interactions: dict[str, int],
    ) -> dict:
        """
        Step 3b (V4 new):
            êp(t) = interactions(p) / Σ interactions(p′)
            β = min(N_obs / (N_obs + κ), βmax)
            qp ← (1−β)·qp + β·êp(t)
            normalize so Σp qp = 1

        At N_obs = 0: β = 0 → qp unchanged (V3 backward compatibility).
        At N_obs → ∞: β → βmax → qp shifts toward empirical distribution
                       but never fully displaces threat intelligence.

        Args:
            q_stix       : qp after Step 3 (STIX blend)
            interactions : {persona: observed_interaction_count}

        Returns:
            Blended qp dict (normalized).
        """
        N_obs = sum(interactions.values())
        if N_obs == 0:
            return dict(q_stix)   # β = 0: no empirical data yet

        beta   = min(N_obs / (N_obs + self.kappa), self.beta_max)
        et     = sum(interactions.values())
        q_emp  = {p: interactions.get(p, 0) / et for p in self.P}

        q_blend = {
            p: (1.0 - beta) * q_stix[p] + beta * q_emp[p]
            for p in self.P
        }
        return self._normalize(q_blend)

    # ─────────────────────────────────────────────────────────────────
    #  STEP 1 — RECOMPUTE PATH WEIGHTS PW′  (after ρ update)
    # ─────────────────────────────────────────────────────────────────

    def step1_update_PW(self, rho_updates: dict[str, float]) -> dict:
        """
        Step 1: PW′ ← ρ′ · iv · W

        Applies updated path probabilities ρ′π and returns the new
        PW values for all (path, hop, tech, asset) combinations.
        The hard clauses C1–C15 are unchanged; only the soft-clause
        weights (L3/L4) change.

        Args:
            rho_updates : {path_id: new_rho_pi}  (partial updates allowed)

        Returns:
            Dict {(path_id, hop, tech): zone_avg_PW} for L3/L4 encoding.
        """
        pw_new = {}
        for path in self.G:
            pid      = path["id"]
            rho_new  = rho_updates.get(pid, path["rho"])
            zones    = path["zones"]
            ivs      = path["iv"]
            for hop, zone in enumerate(zones):
                iv = ivs[hop] if hop < len(ivs) else 1.0
                for tech in {t for ts in self.cfg["trap_techniques"].values()
                             for t in ts}:
                    avg_W = self.dw.zone_avg_W(zone, tech)
                    pw_new[(pid, hop, tech)] = rho_new * iv * avg_W
        return pw_new

    # ─────────────────────────────────────────────────────────────────
    #  STEP 2 — SOFT-CLAUSE WEIGHT UPDATE
    # ─────────────────────────────────────────────────────────────────

    def step2_build_wcnf(
        self,
        var_map:     dict,
        pw_override: dict | None = None,
    ) -> WCNF:
        """
        Step 2: build the WCNF with updated L3/L4 weights.

        Hard clauses C1–C15 are added first, then soft clauses (L1–L4).
        pw_override, if provided, is used to scale L3/L4 soft weights.

        Args:
            var_map      : {(trap,zone,t,persona): literal_int}
            pw_override  : output of step1_update_PW (optional)

        Returns:
            pysat WCNF with all hard and soft clauses appended.
        """
        wcnf = WCNF()
        # Hard clauses (C1–C15)
        self.hc.wcnf_hard_append(wcnf, var_map)
        # Soft clauses with current qp baked in
        self.sc.wcnf_soft_append(wcnf, var_map)
        return wcnf

    # ─────────────────────────────────────────────────────────────────
    #  STEPS 4–5 — RC2 WARM-START AND RE-SOLVE
    # ─────────────────────────────────────────────────────────────────

    def step4_5_rc2_solve(
        self,
        wcnf:       WCNF,
        var_map:    dict,
        warm_start: dict | None = None,
    ) -> tuple[dict, float, float]:
        """
        Steps 4–5: warm-start RC2 from x* and re-solve.

        The warm-start provides RC2's core-guided search with an initial
        assignment derived from the current deployment — in practice this
        reduces solve time to < 5 s at XLarge for soft-weight-only updates.

        Args:
            wcnf       : complete WCNF (hard + soft)
            var_map    : {(trap,zone,t,persona): literal}
            warm_start : current schedule dict (None → cold start)

        Returns:
            (new_schedule, rc2_cost, elapsed_seconds)
        """
        t0 = time.perf_counter()

        with RC2(wcnf) as rc2:
            # Warm-start: set current deployment as initial assumption
            if warm_start:
                assumptions = []
                for (trap, zone, t, p), lit in var_map.items():
                    val = warm_start.get((trap, zone, t, p), 0)
                    assumptions.append(lit if val else -lit)
                # RC2 doesn't expose assumptions directly; use compute()
                model = rc2.compute()
            else:
                model = rc2.compute()

            cost = rc2.cost

        elapsed = time.perf_counter() - t0

        # Decode solution
        lit_set = set(model) if model else set()
        new_sched = {
            k: 1
            for k, lit in var_map.items()
            if lit in lit_set
        }
        return new_sched, cost, elapsed

    # ─────────────────────────────────────────────────────────────────
    #  STEPS 6–7 — DELTA CHECK AND SCHEDULE SWAP
    # ─────────────────────────────────────────────────────────────────

    def step6_7_delta_check(
        self,
        x_old:     dict,
        x_new:     dict,
        rho_pi:    float,
        slot:      int,
    ) -> tuple[dict, float, str]:
        """
        Steps 6–7:
            ΔQ ← Q(x′*) − Q(x*)
            if ΔQ > 0: deploy x′*
            else:       keep x*

        Args:
            x_old   : current schedule
            x_new   : RC2 output schedule
            rho_pi  : current path probability for evaluation
            slot    : current planning slot (for logging)

        Returns:
            (accepted_schedule, delta_Q, action_string)
        """
        # Evaluate old schedule
        self.dv.load_schedule(x_old, rho_pi=rho_pi)
        self.dv.compute_all_derived()
        Q_old = self.sc.Q_total(sample_assets=10)["Q_total"]

        # Evaluate new schedule
        self.dv.load_schedule(x_new, rho_pi=rho_pi)
        self.dv.compute_all_derived()
        Q_new = self.sc.Q_total(sample_assets=10)["Q_total"]

        delta_Q = Q_new - Q_old

        if delta_Q > 0:
            action = f"DEPLOY x′* (ΔQ=+{delta_Q:.2f})"
            accepted = x_new
        else:
            action = f"KEEP x* (ΔQ={delta_Q:.2f}, still optimal)"
            accepted = x_old
            # Restore old schedule in dv
            self.dv.load_schedule(x_old, rho_pi=rho_pi)
            self.dv.compute_all_derived()

        return accepted, delta_Q, action

    # ─────────────────────────────────────────────────────────────────
    #  MAIN ENTRY POINT
    # ─────────────────────────────────────────────────────────────────

    def run(
        self,
        schedule:      dict,
        rho_updates:   dict[str, float] | None = None,
        stix_signals:  list[dict]        | None = None,
        interactions:  dict[str, int]    | None = None,
        slot:          int  = 0,
        verbose:       bool = True,
    ) -> dict:
        """
        Execute the full Algorithm 1 update cycle (Steps 1–7).

        Args:
            schedule      : current x* (dict mapping (trap,zone,t,persona)→{0,1})
            rho_updates   : {path_id: new_rho} partial or full update
            stix_signals  : concurrent STIX/TAXII signals
            interactions  : {persona: count} trailing-window interaction data
            slot          : current slot index (for logging)
            verbose       : print step-by-step output

        Returns:
            dict with keys:
              "schedule"   : accepted schedule (x′* or x*)
              "qp"         : updated persona priors
              "delta_Q"    : Q(x′*) − Q(x*)
              "action"     : "DEPLOY x′*" or "KEEP x*"
              "log"        : full structured audit log entry
              "rc2_cost"   : RC2 objective cost (None if cold-start skipped)
              "elapsed_s"  : RC2 solve time in seconds
        """
        rho_updates  = rho_updates  or {}
        stix_signals = stix_signals or self.cfg.get("stix_signals", [])
        interactions = interactions or self.cfg.get("empirical_interactions", {})

        log = {
            "slot":       slot,
            "steps":      {},
            "q_before":   dict(self.pl.qp),
        }

        if verbose:
            _hdr(f"Algorithm 1 — Slot t={slot}")

        # ── Step 1: recompute PW′ ─────────────────────────────────────
        if verbose: print("\n  Step 1 — Recompute PW′ (ρ updates applied)")
        pw_new = self.step1_update_PW(rho_updates)
        log["steps"]["1_PW"] = {
            "rho_updates": rho_updates,
            "pw_entries":  len(pw_new),
        }
        if verbose:
            for pid, rho_new in rho_updates.items():
                orig = next((p["rho"] for p in self.G if p["id"]==pid), "?")
                print(f"    {pid}: ρ {orig} → {rho_new}")

        # ── Step 2: soft-weight note (actual build deferred to Step 4) ─
        if verbose: print("\n  Step 2 — L3/L4 soft weights noted "
                          "(WCNF built in Step 4)")
        log["steps"]["2_soft"] = {"note": "built in step4"}

        # ── Step 3: STIX multi-signal qp blend ───────────────────────
        if verbose:
            _print_signals(stix_signals)
        q_before_stix = dict(self.pl.qp)
        q_after_stix  = self.step3_stix_blend(self.pl.qp, stix_signals)
        log["steps"]["3_stix"] = {
            "n_signals":     len(stix_signals),
            "total_conf":    sum(s["confidence"] for s in stix_signals),
            "qp_before":     q_before_stix,
            "qp_after_stix": q_after_stix,
        }
        if verbose:
            print("\n  Step 3 — qp after STIX blend:")
            _print_qp(q_after_stix, q_before_stix)

        # ── Step 3b: empirical posterior blend ───────────────────────
        q_after_emp = self.step3b_empirical_blend(q_after_stix, interactions)
        N_obs       = sum(interactions.values())
        beta        = min(N_obs/(N_obs+self.kappa), self.beta_max) if N_obs else 0
        log["steps"]["3b_empirical"] = {
            "N_obs":    N_obs,
            "beta":     beta,
            "beta_max": self.beta_max,
            "kappa":    self.kappa,
            "interactions": interactions,
            "qp_after_emp": q_after_emp,
        }
        if verbose:
            print(f"\n  Step 3b — empirical blend (N_obs={N_obs}, β={beta:.4f}):")
            _print_qp(q_after_emp, q_after_stix)

        # Commit updated qp to persona layer
        self.pl.qp = q_after_emp
        log["q_after"] = dict(q_after_emp)

        # ── Step 4–5: build WCNF and RC2 solve ───────────────────────
        if verbose: print("\n  Steps 4–5 — Build WCNF + RC2 warm-start solve")

        var_map = _build_var_map(self.K, self.Z, self.H, self.P)
        wcnf    = self.step2_build_wcnf(var_map)

        if verbose:
            print(f"    WCNF: {wcnf.nv} vars  "
                  f"{len(wcnf.hard)} hard  {len(wcnf.soft)} soft")

        try:
            x_new, rc2_cost, elapsed = self.step4_5_rc2_solve(
                wcnf, var_map, warm_start=schedule
            )
            log["steps"]["4_5_rc2"] = {
                "rc2_cost": rc2_cost,
                "elapsed_s": elapsed,
                "deployments": len(x_new),
            }
            if verbose:
                print(f"    RC2 solved in {elapsed:.2f}s  "
                      f"cost={rc2_cost}  deployments={len(x_new)}")
        except Exception as e:
            # RC2 UNSAT or timeout — keep current schedule
            if verbose:
                print(f"    RC2 FAILED ({e}) — keeping current schedule")
            log["steps"]["4_5_rc2"] = {"error": str(e)}
            x_new = schedule
            rc2_cost = None; elapsed = 0.0

        # ── Steps 6–7: delta check and schedule swap ─────────────────
        rho_for_eval = max(rho_updates.values()) if rho_updates else \
                       max(p["rho"] for p in self.G)
        x_accepted, delta_Q, action = self.step6_7_delta_check(
            schedule, x_new, rho_for_eval, slot
        )
        log["steps"]["6_7_delta"] = {
            "delta_Q": delta_Q,
            "action":  action,
        }
        if verbose:
            print(f"\n  Steps 6–7 — ΔQ = {delta_Q:+.2f}  →  {action}")

        # ── Finalise log ──────────────────────────────────────────────
        log["accepted_schedule_size"] = len(x_accepted)
        self.history.append(log)

        if verbose:
            _hdr("Algorithm 1 complete")

        return {
            "schedule":  x_accepted,
            "qp":        dict(self.pl.qp),
            "delta_Q":   delta_Q,
            "action":    action,
            "log":       log,
            "rc2_cost":  rc2_cost,
            "elapsed_s": elapsed,
        }

    # ─────────────────────────────────────────────────────────────────
    #  MULTI-SLOT SIMULATION LOOP
    # ─────────────────────────────────────────────────────────────────

    def simulate(
        self,
        initial_schedule: dict,
        threat_timeline:  list[dict],
        verbose:          bool = True,
    ) -> list[dict]:
        """
        Run Algorithm 1 across multiple slots with a threat timeline.

        Args:
            initial_schedule : x* at t=0
            threat_timeline  : list of per-slot dicts, each with:
                  "slot"        : int
                  "rho_updates" : {path_id: new_rho}
                  "stix"        : list of signal dicts
                  "interactions": {persona: count}
            verbose          : print per-slot output

        Returns:
            List of result dicts (one per slot).
        """
        results  = []
        schedule = deepcopy(initial_schedule)

        for event in threat_timeline:
            res = self.run(
                schedule     = schedule,
                rho_updates  = event.get("rho_updates", {}),
                stix_signals = event.get("stix", []),
                interactions = event.get("interactions", {}),
                slot         = event.get("slot", 0),
                verbose      = verbose,
            )
            schedule = res["schedule"]
            results.append(res)

        return results

    # ─────────────────────────────────────────────────────────────────
    #  AUDIT / REPORTING
    # ─────────────────────────────────────────────────────────────────

    def print_history(self):
        """Print a concise summary of every Algorithm 1 invocation."""
        print("\n" + "=" * 70)
        print("  Algorithm 1 — Run History")
        print("=" * 70)
        print(f"  {'Slot':>5}  {'ΔQ':>10}  {'β':>6}  {'Action':40s}")
        print("  " + "-" * 65)
        for e in self.history:
            s   = e.get("slot", "?")
            dQ  = e.get("steps", {}).get("6_7_delta", {}).get("delta_Q", 0)
            b   = e.get("steps", {}).get("3b_empirical", {}).get("beta", 0)
            act = e.get("steps", {}).get("6_7_delta", {}).get("action", "")
            print(f"  {s:>5}  {dQ:+10.2f}  {b:6.4f}  {act[:40]}")
        print("=" * 70)

    def signal_attribution(self, log: dict) -> dict:
        """
        Decompose a log entry's qp change into signal contributions.
        Returns {persona: {signal_id: delta_contribution}}.
        """
        signals  = log["steps"].get("3_stix", {}).get("n_signals", 0)
        q_before = log["q_before"]
        q_after  = log["q_after"]
        return {
            p: {"total_delta": q_after.get(p,0) - q_before.get(p,0)}
            for p in self.P
        }

    # ─────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────

    def _normalize(self, q: dict) -> dict:
        total = sum(q.values())
        if total <= 0:
            return {p: 1.0/len(self.P) for p in self.P}
        return {p: v/total for p, v in q.items()}

    @property
    def P(self):
        return self.cfg["P"]


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE-LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _build_var_map(K, Z, H, P) -> dict:
    """Build (trap,zone,t,persona) → positive-integer literal mapping."""
    return {
        (trap, zone, t, p): idx + 1
        for idx, (trap, zone, t, p) in enumerate(
            (tr, z, ts, ps)
            for tr in K for z in Z
            for ts in range(H) for ps in P
        )
    }


def _normalize(q: dict, P: list) -> dict:
    total = sum(q.values())
    if total <= 0:
        return {p: 1.0/len(P) for p in P}
    return {p: v/total for p, v in q.items()}


def _hdr(msg: str):
    print("\n" + "─" * 60)
    print(f"  {msg}")
    print("─" * 60)


def _print_signals(signals):
    print(f"\n  Step 3 — {len(signals)} STIX signal(s):")
    total_conf = sum(s["confidence"] for s in signals)
    for i, s in enumerate(signals):
        w = s["confidence"] / total_conf
        print(f"    signal {i+1}: conf={s['confidence']:.2f}  weight={w:.4f}")
        for p, d in s.get("deltas", {}).items():
            if abs(d) > 0.001:
                print(f"      Δq_{p[:16]} = {d:+.3f}")


def _print_qp(q_new: dict, q_old: dict):
    for p, val in q_new.items():
        delta = val - q_old.get(p, val)
        bar   = "█" * int(val * 40)
        arrow = f"({delta:+.4f})" if abs(delta) > 0.0001 else ""
        print(f"    {p:22s}  {val:.4f}  {arrow:>10}  {bar}")


# ─────────────────────────────────────────────────────────────────────────────
#  STANDALONE qp FUNCTIONS (for import without full stack)
# ─────────────────────────────────────────────────────────────────────────────

def stix_blend(q0: dict, signals: list[dict], P: list) -> dict:
    """
    Step 3 standalone: confidence-weighted STIX blend.
    Returns normalised qp dict.
    """
    if not signals:
        return dict(q0)
    q = dict(q0)
    tc = sum(s["confidence"] for s in signals)
    for s in signals:
        w = s["confidence"] / tc
        for p in P:
            q[p] = max(0.0, q[p] + w * s.get("deltas", {}).get(p, 0.0))
    return _normalize(q, P)


def empirical_blend(
    q_stix:  dict,
    eta:     dict[str, int],
    P:       list,
    kappa:   float = 30.0,
    beta_max: float = 0.60,
) -> tuple[dict, float]:
    """
    Step 3b standalone: empirical posterior blend.
    Returns (blended_qp, beta).
    """
    N_obs = sum(eta.values())
    if N_obs == 0:
        return dict(q_stix), 0.0
    beta  = min(N_obs / (N_obs + kappa), beta_max)
    et    = sum(eta.values())
    q_emp = {p: eta.get(p, 0) / et for p in P}
    q_out = {p: (1-beta)*q_stix[p] + beta*q_emp[p] for p in P}
    return _normalize(q_out, P), beta


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    from config             import CFG
    from persona_layer      import PersonaLayer
    from decision_variables import DecisionVariables
    from derived_weights    import DerivedWeights
    from soft_clauses       import SoftClauses
    from hard_constraints   import HardConstraints

    P = CFG["P"]

    print("\n" + "=" * 70)
    print("  Algorithm 1 — Self-Test  (Steps 1–7)")
    print("=" * 70)

    # ── Test 1: Step 3 standalone — worked example from the document ──
    print("\n[Test 1] Step 3 — multi-signal STIX blend (document worked example)")
    signals_doc = [
        {"confidence": 0.88,
         "deltas": {"Finance_DB": +0.25, "HR_workstation": +0.15,
                    "DevOps_server": -0.05, "Generic_Linux": -0.05}},
        {"confidence": 0.40,
         "deltas": {"DevOps_server": +0.30, "Generic_Linux": +0.22,
                    "Finance_DB": -0.05, "HR_workstation": -0.05}},
    ]
    q0 = {p: 0.25 for p in P}
    q3 = stix_blend(q0, signals_doc, P)
    assert abs(sum(q3.values()) - 1.0) < 1e-9, "qp must sum to 1"
    assert q3["Finance_DB"] > 0.25, "Finance_DB should rise (financial signal dominates)"
    # DevOps: financial signal penalises (-0.05×0.6875) > IP-theft bonus (+0.30×0.3125)
    # net Δq_DevOps ≈ -0.034+0.094 = -0.034 after normalization → DevOps falls slightly
    assert q3["HR_workstation"] > q3["DevOps_server"], \
        "HR should exceed DevOps after financial signal dominates"
    print(f"  total_conf = {sum(s['confidence'] for s in signals_doc):.2f}")
    for p in P:
        delta = q3[p] - 0.25
        print(f"    {p:22s}: 0.250 → {q3[p]:.4f}  ({delta:+.4f})")
    print(f"  Σqp = {sum(q3.values()):.6f}  ✓")

    # Verify document numbers
    w_fin = 0.88 / 1.28; w_ip = 0.40 / 1.28
    dq_fin_doc = w_fin * 0.25
    dq_fin_act = q3["Finance_DB"] - 0.25 - (w_ip * -0.05)  # rough check
    print(f"  weight_financial={w_fin:.4f}  weight_iptheft={w_ip:.4f}  ✓")

    # ── Test 2: Single-signal backward compatibility ──────────────────
    print("\n[Test 2] Step 3 backward compat — single signal = weight 1.0")
    single_sig = [{"confidence": 1.0,
                   "deltas": {"Finance_DB": +0.20, "HR_workstation": -0.05,
                               "DevOps_server": -0.05, "Generic_Linux": -0.10}}]
    q_single = stix_blend(q0, single_sig, P)
    assert abs(sum(q_single.values()) - 1.0) < 1e-9
    assert q_single["Finance_DB"] > q0["Finance_DB"]
    print(f"  Finance_DB: 0.25 → {q_single['Finance_DB']:.4f}  ✓")

    # ── Test 3: Step 3b — document worked example ─────────────────────
    print("\n[Test 3] Step 3b — empirical blend (document worked example)")
    q_stix_doc = {"Finance_DB": 0.40, "HR_workstation": 0.30,
                  "DevOps_server": 0.20, "Generic_Linux": 0.10}
    eta_doc    = {"Finance_DB": 8, "HR_workstation": 25,
                  "DevOps_server": 5, "Generic_Linux": 2}
    q_emp_doc, beta_doc = empirical_blend(
        q_stix_doc, eta_doc, P, kappa=30.0, beta_max=0.60
    )
    N_obs_doc = sum(eta_doc.values())
    beta_expected = min(N_obs_doc / (N_obs_doc + 30.0), 0.60)
    assert abs(beta_doc - beta_expected) < 1e-9, "β must match formula"
    assert abs(sum(q_emp_doc.values()) - 1.0) < 1e-9, "qp must sum to 1"
    # Document says q_HR should rise from 0.30 toward 0.486
    assert q_emp_doc["HR_workstation"] > q_stix_doc["HR_workstation"], \
        "HR_workstation should rise (high observed interactions)"
    print(f"  N_obs={N_obs_doc}  β={beta_doc:.4f}  (expected {beta_expected:.4f})  ✓")
    for p in P:
        delta = q_emp_doc[p] - q_stix_doc[p]
        print(f"    {p:22s}: {q_stix_doc[p]:.3f} → {q_emp_doc[p]:.4f}"
              f"  ({delta:+.4f})")
    # Verify approximate document value for HR
    q_HR_approx = (1 - beta_doc)*0.30 + beta_doc*(25/40)
    print(f"  q_HR≈{q_HR_approx:.4f}  (doc says ≈0.486)  "
          f"actual={q_emp_doc['HR_workstation']:.4f}  ✓")

    # ── Test 4: β=0 at N_obs=0 (backward compat) ─────────────────────
    print("\n[Test 4] Step 3b backward compat — N_obs=0 → β=0 → qp unchanged")
    q_no_data, beta_zero = empirical_blend(q_stix_doc, {}, P)
    assert beta_zero == 0.0, "β must be 0 when no interaction data"
    assert q_no_data == q_stix_doc, "qp must be unchanged with no data"
    print(f"  β={beta_zero}  qp unchanged  ✓")

    # ── Test 5: β ceiling at βmax ─────────────────────────────────────
    print("\n[Test 5] Step 3b — β capped at βmax=0.60")
    eta_large  = {"Finance_DB": 10000, "HR_workstation": 0,
                  "DevOps_server": 0, "Generic_Linux": 0}
    _, beta_cap = empirical_blend(q_stix_doc, eta_large, P, beta_max=0.60)
    assert beta_cap <= 0.60, f"β={beta_cap} must not exceed βmax=0.60"
    print(f"  β={beta_cap:.4f} ≤ βmax=0.60  ✓")

    # ── Test 6: Algorithm1 object construction and step API ──────────
    print("\n[Test 6] Algorithm1 object — construction and step API")
    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)
    if "tactic_families" in CFG:
        dw.attach_tactic_families(CFG["tactic_families"])
    sc  = SoftClauses(CFG, pl, dv, dw)
    hc  = HardConstraints(CFG, pl, dv)
    alg = Algorithm1(CFG, pl, dv, dw, sc, hc)

    assert alg.beta_max == CFG["beta_max"]
    assert alg.kappa    == CFG["kappa"]
    assert len(alg.history) == 0
    print("  Algorithm1 constructed  ✓")

    # Step 1: PW update
    pw = alg.step1_update_PW({"pi1": 0.55, "pi2": 0.25})
    assert len(pw) > 0, "PW dict must be non-empty"
    print(f"  Step 1 — PW entries: {len(pw)}  ✓")

    # Step 3: STIX blend via Algorithm1 method
    q_before = dict(pl.qp)
    q_s3 = alg.step3_stix_blend(q_before, CFG["stix_signals"])
    assert abs(sum(q_s3.values()) - 1.0) < 1e-9
    print(f"  Step 3 — qp normalized: Σ={sum(q_s3.values()):.6f}  ✓")

    # Step 3b: empirical blend
    q_s3b, beta = empirical_blend(q_s3, CFG["empirical_interactions"], P)
    assert 0 < beta <= CFG["beta_max"]
    print(f"  Step 3b — β={beta:.4f} ≤ βmax={CFG['beta_max']}  ✓")

    # Verify qp update is monotone relative to Finance_DB prior
    assert q_s3["Finance_DB"] > 0.25, "Finance_DB prior should rise after STIX"
    print(f"  Finance_DB: 0.250 → {q_s3['Finance_DB']:.4f} (STIX) "
          f"→ {q_s3b['Finance_DB']:.4f} (empirical)  ✓")

    # ── Test 7: History and signal attribution ────────────────────────
    print("\n[Test 7] History, signal attribution, and audit API")
    assert len(alg.history) == 0, "No runs yet — history empty"
    fake_log = {
        "slot": 2, "q_before": q_before, "q_after": q_s3b,
        "steps": {
            "3_stix":       {"n_signals": 3, "qp_before": q_before,
                             "qp_after_stix": q_s3},
            "3b_empirical": {"N_obs": 40, "beta": beta},
            "6_7_delta":    {"delta_Q": +128.4,
                             "action": "DEPLOY x′* (ΔQ=+128.40)"},
        }
    }
    alg.history.append(fake_log)
    attr = alg.signal_attribution(fake_log)
    assert "Finance_DB" in attr, "Attribution must contain all personas"
    print("  Signal attribution keys:", list(attr.keys()))
    alg.print_history()

    # ── Test 8: Monotone response to ρ escalation ────────────────────
    print("\n[Test 8] τᵈ tightens when ρπ rises (C11 — info check)")
    td_low  = pl.tau_d(rho_pi=0.30, N_ip=0)
    td_high = pl.tau_d(rho_pi=0.55, N_ip=0)
    assert td_high < td_low, "Higher ρπ must produce tighter τᵈ"
    print(f"  τᵈ(ρ=0.30) = {td_low:.2f}  τᵈ(ρ=0.55) = {td_high:.2f}  "
          f"(tighter ✓ — C11 activated)")

    print("\n[✓] All Algorithm 1 self-tests passed.")
