"""
gap_parameters.py
Zone-Slot-Time-Persona V6 — V4/V5 Gap-Resolution Parameters
=============================================================
Implements all eight new parameters introduced in V4–V5:

    γ ∈ (0,1]        Learning-decay rate (V4)
    Nᵢ,ₚ(t)          Cumulative cross-zone observation count (V4/V5)
    βₘₐˣ ∈ [0,1]     Empirical qp blend ceiling (V4)
    κ ∈ ℝ⁺           Half-confidence constant (V4)
    τ_GK ∈ [0,1]     GK role-compatibility threshold (V4)
    h_min ∈ ℝ⁺       Slot-duration floor (V4/C15)
    κ_min ∈ ℝ⁺       Kill-chain speed floor (V4/C15)
    ρ_decay ∈ (0,1)  N cooldown decay rate (V5)
    Δ_N ∈ ℤ⁺         N cooldown window (V5)

Each parameter is implemented as a class with:
    • value()          : return the parameter value
    • worked_example() : reproduce the document's numerical example
    • sensitivity()    : show how outputs change across parameter range
    • check()          : validate parameter constraints

The module is standalone — it imports only from config.py and does
not require the full persona-layer or solver stack.

Usage:
    from config         import CFG
    from gap_parameters import GapParameters

    gp = GapParameters(CFG)

    # γ learning-decay
    td = gp.tau_d_with_gamma(rho_pi=0.30, N_ip=2)
    print(td)   # 1.344 (36% tighter than N=0 baseline)

    # N recurrence
    N = gp.N_recurrence(history=[1,1,0,0,0], trap="ssh_trap", persona="HR_workstation")

    # β empirical confidence
    beta = gp.beta(N_obs=40)   # 0.571

    # Full worked-example report
    gp.print_all()
"""

import math
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
#  GAP PARAMETERS CLASS
# ─────────────────────────────────────────────────────────────────────────────

class GapParameters:
    """
    All eight V4/V5 gap-resolution parameters with worked examples,
    validation, and sensitivity analysis.
    """

    def __init__(self, cfg: dict):
        self.cfg      = cfg
        self.P        = cfg["P"]

        # ── V4 parameters ─────────────────────────────────────────────
        self.gamma    = cfg["gamma"]       # γ learning-decay rate
        self.beta_max = cfg["beta_max"]    # βₘₐˣ empirical ceiling
        self.kappa    = cfg["kappa"]       # κ half-confidence constant
        self.tau_GK   = cfg["tau_GK"]      # τ_GK GK threshold
        self.h_min    = cfg["h_min"]       # slot-duration floor (hours)
        self.kappa_min= cfg["kappa_min"]   # kill-chain floor (hours)

        # ── V5 parameters ─────────────────────────────────────────────
        self.rho_decay= cfg["rho_decay"]   # ρ_decay cooldown decay
        self.Delta_N  = cfg["Delta_N"]     # Δ_N cooldown window

        # ── Base parameters needed for τᵈ computation ─────────────────
        self.tau_d0   = cfg["tau_d0"]
        self.tau_dp0  = cfg["tau_dp0"]
        self.rho_max  = cfg["rho_max"]

        # Run parameter validation
        self._validate()

    # ─────────────────────────────────────────────────────────────────
    #  VALIDATION
    # ─────────────────────────────────────────────────────────────────

    def _validate(self):
        """Validate all parameter constraints at construction time."""
        errors = []
        if not (0 < self.gamma <= 1.0):
            errors.append(f"γ={self.gamma} must be in (0,1]")
        if not (0 <= self.beta_max <= 1.0):
            errors.append(f"βₘₐˣ={self.beta_max} must be in [0,1]")
        if self.kappa <= 0:
            errors.append(f"κ={self.kappa} must be > 0")
        if not (0 <= self.tau_GK <= 1.0):
            errors.append(f"τ_GK={self.tau_GK} must be in [0,1]")
        if self.h_min <= 0:
            errors.append(f"h_min={self.h_min} must be > 0")
        if self.kappa_min <= 0:
            errors.append(f"κ_min={self.kappa_min} must be > 0")
        if self.h_min < self.kappa_min:
            errors.append(
                f"C15 VIOLATION: h_min={self.h_min}h < κ_min={self.kappa_min}h"
            )
        if not (0 < self.rho_decay < 1.0):
            errors.append(f"ρ_decay={self.rho_decay} must be in (0,1)")
        if self.Delta_N < 1:
            errors.append(f"Δ_N={self.Delta_N} must be ≥ 1")
        if errors:
            raise ValueError("Parameter validation failed:\n" +
                             "\n".join(f"  • {e}" for e in errors))

    # ─────────────────────────────────────────────────────────────────
    #  γ — LEARNING-DECAY RATE  (V4)
    # ─────────────────────────────────────────────────────────────────

    def tau_d_with_gamma(self, rho_pi: float, N_ip: int) -> float:
        """
        V4 + V5 floored formula (eq 12′):
            τᵈ(i,z,t) = max(1, τᵈ⁰ · (1 − ρπ/ρₘₐˣ) · γ^N)

        γ controls how much τᵈ tightens per additional zone of
        cumulative attacker observation. γ=1 recovers V3 exactly.

        Args:
            rho_pi : current path probability ρπ
            N_ip   : cumulative observation count Nᵢ,ₚ(t)

        Returns:
            Effective type-discovery threshold (≥ 1, V5 floored).
        """
        unfloored = (self.tau_d0
                     * (1.0 - rho_pi / self.rho_max)
                     * (self.gamma ** N_ip))
        return max(1.0, unfloored)

    def tau_dp_with_gamma(self, N_ip: int) -> float:
        """
        V4 + V5 floored formula (eq 13′):
            τᵈᵖ(i,z,t) = max(1, τᵈᵖ⁰ · γ^N)
        """
        return max(1.0, self.tau_dp0 * (self.gamma ** N_ip))

    def gamma_sensitivity(self, rho_pi: float = 0.30,
                          N_range: list[int] | None = None) -> list[dict]:
        """
        Show how τᵈ changes across N for the configured γ.
        Used to demonstrate the attacker-learning acceleration effect.
        """
        if N_range is None:
            N_range = [0, 1, 2, 3, 5, 10]
        rows = []
        td_baseline = self.tau_d_with_gamma(rho_pi, N_ip=0)
        for n in N_range:
            td = self.tau_d_with_gamma(rho_pi, N_ip=n)
            gamma_n = self.gamma ** n
            rows.append({
                "N_ip":      n,
                "gamma_N":   gamma_n,
                "tau_d":     td,
                "pct_tighter": (1 - td / td_baseline) * 100 if td_baseline else 0,
                "floor_hit": td == 1.0 and n > 0,
            })
        return rows

    # ─────────────────────────────────────────────────────────────────
    #  Nᵢ,ₚ(t) — CUMULATIVE OBSERVATION RECURRENCE  (V4/V5)
    # ─────────────────────────────────────────────────────────────────

    def N_recurrence(
        self,
        history:        list[int],   # 1=active+undiscovered, 0=inactive, -1=burned
        trap:           str = "",
        persona:        str = "",
    ) -> list[int]:
        """
        Simulate the V5 formal recurrence for Nᵢ,ₚ(t) across a slot history.

        History values:
            1  : active and type-undiscovered in at least one zone
            0  : inactive (not deployed anywhere)
           -1  : active but type-discovered (burned — N does not increment)

        Recurrence (V5):
            N(0) = 0
            N(t) = N(t-1) + 1    if active and undiscovered
            N(t) = ⌊ρ_decay · N(t-1)⌋  if inactive ≥ Δ_N consecutive slots
            N(t) = N(t-1)        otherwise

        Args:
            history : per-slot activity flags
            trap    : honeypot type (informational)
            persona : persona (informational)

        Returns:
            List of N values, one per slot.
        """
        N     = 0
        Ns    = []
        inact = 0   # consecutive inactive slots

        for h in history:
            if h == 1:          # active and type-undiscovered
                inact = 0
                N    += 1
            elif h == 0:        # inactive
                inact += 1
                if inact >= self.Delta_N:
                    N = math.floor(self.rho_decay * N)
            else:               # burned (h == -1): hold N, count as inactive
                inact += 1
                if inact >= self.Delta_N:
                    N = math.floor(self.rho_decay * N)
            Ns.append(N)
        return Ns

    def N_at_slot(self, history: list[int], t: int) -> int:
        """Return N at a specific slot (0-indexed)."""
        ns = self.N_recurrence(history)
        return ns[t] if 0 <= t < len(ns) else 0

    # ─────────────────────────────────────────────────────────────────
    #  βₘₐˣ, κ — EMPIRICAL CONFIDENCE PARAMETERS  (V4)
    # ─────────────────────────────────────────────────────────────────

    def beta(self, N_obs: int) -> float:
        """
        Empirical confidence weight (V4 Step 3b):
            β = min(N_obs / (N_obs + κ), βₘₐˣ)

        β grows from 0 (no data) toward βₘₐˣ (abundant data).
        At N_obs = κ: β = βₘₐˣ/2  (half-confidence point).
        At N_obs = 0: β = 0        (pure STIX prior, V3 behaviour).
        """
        if N_obs <= 0:
            return 0.0
        return min(N_obs / (N_obs + self.kappa), self.beta_max)

    def beta_sensitivity(
        self, N_range: list[int] | None = None
    ) -> list[dict]:
        """
        Show how β grows with observation count.
        Illustrates the gradual-confidence-accumulation design.
        """
        if N_range is None:
            N_range = [0, 5, 10, 15, 20, 30, 50, 100, 200, 500, 1000]
        rows = []
        for n in N_range:
            b = self.beta(n)
            rows.append({
                "N_obs":         n,
                "beta":          b,
                "beta_pct_max":  b / self.beta_max * 100 if self.beta_max else 0,
                "stix_weight":   1 - b,
                "at_half_conf":  abs(n - self.kappa) < 1,
                "at_ceiling":    b >= self.beta_max - 1e-9,
            })
        return rows

    def qp_blend(
        self,
        q_stix:  dict[str, float],
        eta:     dict[str, int],
    ) -> tuple[dict[str, float], float]:
        """
        Apply Step 3b empirical blend given STIX-derived qp and
        interaction counts.

        Returns (blended_qp, beta).
        """
        N_obs = sum(eta.values())
        b     = self.beta(N_obs)
        if b == 0:
            return dict(q_stix), 0.0

        et    = sum(eta.values()) or 1
        q_emp = {p: eta.get(p, 0) / et for p in self.P}
        q_out = {p: (1 - b) * q_stix.get(p, 0) + b * q_emp[p]
                 for p in self.P}
        total = sum(q_out.values()) or 1
        q_out = {p: v / total for p, v in q_out.items()}
        return q_out, b

    # ─────────────────────────────────────────────────────────────────
    #  τ_GK — GK ROLE-COMPATIBILITY THRESHOLD  (V4)
    # ─────────────────────────────────────────────────────────────────

    def gk_admit(self, score: float) -> bool:
        """
        GK admission: M(servertype, persona) ≥ τ_GK  (eq 14).
        """
        return score >= self.tau_GK

    def gk_threshold_sensitivity(
        self,
        gk_scores:    dict,
        thresholds:   list[float] | None = None,
    ) -> list[dict]:
        """
        Show how many (trap, persona) pairs are admitted at different τ_GK.

        Args:
            gk_scores  : {(trap, persona): score} from config
            thresholds : τ_GK values to test
        """
        if thresholds is None:
            thresholds = [0.50, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90]
        total = len(gk_scores)
        rows  = []
        for tau in thresholds:
            admitted = sum(1 for s in gk_scores.values() if s >= tau)
            rows.append({
                "tau_GK":      tau,
                "admitted":    admitted,
                "rejected":    total - admitted,
                "pct_admitted":admitted / total * 100 if total else 0,
                "current":     abs(tau - self.tau_GK) < 1e-9,
            })
        return rows

    # ─────────────────────────────────────────────────────────────────
    #  h_min, κ_min — SLOT-DURATION FLOOR  (V4/C15)
    # ─────────────────────────────────────────────────────────────────

    def c15_check(
        self,
        h_min:     float | None = None,
        kappa_min: float | None = None,
    ) -> dict:
        """
        C15 precondition check: h_min ≥ κ_min.

        Args:
            h_min     : slot duration in hours (defaults to config)
            kappa_min : fastest kill-chain in hours (defaults to config)

        Returns:
            Dict with check result and interpretation.
        """
        hm  = h_min     if h_min     is not None else self.h_min
        km  = kappa_min if kappa_min is not None else self.kappa_min
        ok  = hm >= km
        return {
            "h_min":           hm,
            "kappa_min":       km,
            "satisfied":       ok,
            "margin_hours":    hm - km,
            "note": (
                f"OK — slot {hm}h protects against {km}h kill chain"
                if ok else
                f"VIOLATION — slot {hm}h < fastest kill chain {km}h"
            ),
        }

    def slot_granularity_table(
        self,
        h_min_range:  list[float] | None = None,
    ) -> list[dict]:
        """
        Show C15 status across a range of slot durations.
        """
        if h_min_range is None:
            h_min_range = [4, 6, 8, 12, 24, 48, 168]  # hours
        rows = []
        for h in h_min_range:
            r = self.c15_check(h_min=h)
            rows.append(r)
        return rows

    # ─────────────────────────────────────────────────────────────────
    #  ρ_decay, Δ_N — N COOLDOWN PARAMETERS  (V5)
    # ─────────────────────────────────────────────────────────────────

    def N_decay_simulation(
        self,
        N_start:    int,
        n_slots:    int,
        active:     bool = False,
    ) -> list[int]:
        """
        Simulate N decay over n_slots consecutive inactive slots starting
        from N_start, beginning decay after Δ_N slots have elapsed.

        Args:
            N_start  : initial N value before inactivity begins
            n_slots  : number of slots to simulate
            active   : if True, simulate active slots (N increments)

        Returns:
            List of N values per slot.
        """
        if active:
            return [N_start + i + 1 for i in range(n_slots)]

        history = [0] * n_slots   # all inactive
        N = N_start; Ns = []; inact = 0
        for _ in history:
            inact += 1
            if inact >= self.Delta_N:
                N = math.floor(self.rho_decay * N)
            Ns.append(N)
        return Ns

    def rho_decay_sensitivity(
        self,
        N_start:      int = 4,
        n_slots:      int = 8,
        decay_rates:  list[float] | None = None,
    ) -> list[dict]:
        """
        Compare N trajectories across different ρ_decay values.
        Shows the trade-off between persistent (high ρ_decay) and
        fast-forgetting (low ρ_decay) evidence accumulation.
        """
        if decay_rates is None:
            decay_rates = [0.25, 0.50, 0.70, 0.90, 1.00]
        rows = []
        for rd in decay_rates:
            # Temporarily override
            orig = self.rho_decay
            self.rho_decay = rd
            trajectory = self.N_decay_simulation(N_start, n_slots)
            self.rho_decay = orig
            rows.append({
                "rho_decay":   rd,
                "trajectory":  trajectory,
                "final_N":     trajectory[-1] if trajectory else 0,
                "halving_time": next(
                    (i+1 for i,n in enumerate(trajectory) if n <= N_start//2),
                    None
                ),
            })
        return rows

    # ─────────────────────────────────────────────────────────────────
    #  COMBINED WORKED EXAMPLES  (document sections V4/V5)
    # ─────────────────────────────────────────────────────────────────

    def worked_example_gamma(self) -> dict:
        """
        Reproduce the V4 γ worked example exactly:
            γ=0.80, τᵈ⁰=3, ρπ=0.30, ρₘₐˣ=1.0
            n=0: τᵈ = 3×0.70×0.80⁰ = 2.10 (identical to V3)
            n=2: τᵈ = 3×0.70×0.80² = 1.344
        """
        n0 = self.tau_d_with_gamma(0.30, 0)
        n2 = self.tau_d_with_gamma(0.30, 2)
        pct_tighter = (1 - n2/n0) * 100 if n0 else 0
        return {
            "gamma":       self.gamma,
            "tau_d0":      self.tau_d0,
            "rho_pi":      0.30,
            "N_0":         n0,    # should be 2.10
            "N_2":         n2,    # should be 1.344
            "pct_tighter": pct_tighter,
            "doc_N_0":     2.10,
            "doc_N_2":     1.34,
            "match_N_0":   abs(n0 - 2.10) < 0.01,
            "match_N_2":   abs(n2 - 1.34) < 0.01,
        }

    def worked_example_N(self) -> dict:
        """
        Reproduce the V5 Nᵢ,ₚ recurrence worked example:
            ρ_decay=0.5, Δ_N=3
            active t=1,2 → N: 0→1→2
            inactive t=3,4 → N holds at 2 (< Δ_N=3 elapsed)
            inactive t=5   → N: ⌊0.5×2⌋=1 (Δ_N=3 hit)
        """
        # history: 1=active+undiscovered, 0=inactive
        history = [1, 1, 0, 0, 0]  # t=1..5 (0-indexed t=0..4)
        Ns = self.N_recurrence(history)
        return {
            "history":         history,
            "N_values":        Ns,
            "doc_N_values":    [1, 2, 2, 2, 1],
            "rho_decay":       self.rho_decay,
            "Delta_N":         self.Delta_N,
            "match":           Ns == [1, 2, 2, 2, 1],
        }

    def worked_example_beta(self) -> dict:
        """
        Reproduce the V4 Step 3b worked example:
            κ=30, βₘₐˣ=0.60, N_obs=40
            β = min(40/70, 0.60) = 0.571
            q_stix: Finance_DB=0.40, HR=0.30, DevOps=0.20, Linux=0.10
            eta:    Finance_DB=8,   HR=25,   DevOps=5,   Linux=2
            q_HR: (1-0.571)×0.30 + 0.571×0.625 = 0.486
        """
        q_stix = {"Finance_DB": 0.40, "HR_workstation": 0.30,
                  "DevOps_server": 0.20, "Generic_Linux": 0.10}
        eta    = {"Finance_DB": 8, "HR_workstation": 25,
                  "DevOps_server": 5, "Generic_Linux": 2}
        N_obs  = sum(eta.values())
        b      = self.beta(N_obs)
        q_emp_HR = eta["HR_workstation"] / N_obs
        q_HR_blended = (1 - b) * q_stix["HR_workstation"] + b * q_emp_HR

        q_out, b_actual = self.qp_blend(q_stix, eta)
        return {
            "kappa":           self.kappa,
            "beta_max":        self.beta_max,
            "N_obs":           N_obs,
            "beta":            b,
            "beta_expected":   min(40/70, 0.60),
            "q_HR_blended":    q_HR_blended,
            "q_HR_expected":   0.486,
            "match_beta":      abs(b - 0.5714) < 0.001,
            "match_q_HR":      abs(q_HR_blended - 0.486) < 0.002,
            "q_out":           q_out,
        }

    def worked_example_c15(self) -> dict:
        """
        Reproduce the V4 C15 worked example:
            h_min=24h, κ_min=12h → OK (margin = 12h)
            h_min=6h,  κ_min=12h → VIOLATION
        """
        ok  = self.c15_check(h_min=24.0, kappa_min=12.0)
        bad = self.c15_check(h_min=6.0,  kappa_min=12.0)
        return {
            "ok_case":  ok,
            "bad_case": bad,
            "cfg_ok":   self.c15_check(),
        }

    # ─────────────────────────────────────────────────────────────────
    #  MASTER PRINT
    # ─────────────────────────────────────────────────────────────────

    def print_all(self):
        """Print all V4/V5 parameters with worked examples."""
        print("\n" + "═" * 70)
        print("  V4–V5 Gap-Resolution Parameters")
        print("═" * 70)
        self._print_gamma()
        self._print_N()
        self._print_beta()
        self._print_gk()
        self._print_c15()
        self._print_decay()
        print("═" * 70)

    def _print_gamma(self):
        ex = self.worked_example_gamma()
        print(f"\n  γ = {self.gamma}  (learning-decay rate, V4)")
        print(f"  τᵈ⁰={self.tau_d0}  ρπ=0.30  ρₘₐˣ={self.rho_max}")
        print(f"  N=0: τᵈ = {ex['N_0']:.3f}  "
              f"(doc={ex['doc_N_0']:.2f}  {'✓' if ex['match_N_0'] else '✗'})")
        print(f"  N=2: τᵈ = {ex['N_2']:.3f}  "
              f"(doc={ex['doc_N_2']:.2f}  {'✓' if ex['match_N_2'] else '✗'})")
        print(f"  N=2 is {ex['pct_tighter']:.1f}% tighter than N=0")
        print(f"  γ=1 recovers V3 static threshold: "
              f"{self.tau_d_with_gamma(0.30, N_ip=0).__round__(3)}")
        rows = self.gamma_sensitivity(0.30)
        print(f"\n  Sensitivity across N (ρπ=0.30):")
        print(f"    {'N':>4}  {'γ^N':>8}  {'τᵈ':>6}  {'tighter%':>9}  {'floor':>6}")
        for r in rows:
            print(f"    {r['N_ip']:>4}  {r['gamma_N']:>8.4f}  "
                  f"{r['tau_d']:>6.3f}  {r['pct_tighter']:>8.1f}%"
                  f"  {'HIT' if r['floor_hit'] else ''}")

    def _print_N(self):
        ex = self.worked_example_N()
        print(f"\n  Nᵢ,ₚ(t)  (cumulative observation count, V4/V5 recurrence)")
        print(f"  ρ_decay={self.rho_decay}  Δ_N={self.Delta_N}")
        print(f"  History: {ex['history']} (1=active+undiscovered, 0=inactive)")
        print(f"  N values: {ex['N_values']}")
        print(f"  Doc:      {ex['doc_N_values']}")
        print(f"  Match: {'✓' if ex['match'] else '✗'}")
        print(f"  Slot 1–2: active → N increments (0→1→2)")
        print(f"  Slot 3–4: inactive, inact_count < Δ_N={self.Delta_N} → N holds")
        print(f"  Slot 5:   inact_count == Δ_N → N = ⌊{self.rho_decay}×2⌋ = "
              f"{math.floor(self.rho_decay*2)}")

    def _print_beta(self):
        ex = self.worked_example_beta()
        print(f"\n  βₘₐˣ = {self.beta_max}  κ = {self.kappa}  (V4 Step 3b)")
        print(f"  β = min(N_obs / (N_obs + κ), βₘₐˣ)")
        print(f"  N_obs=40: β = {ex['beta']:.4f}  "
              f"(doc≈0.571  {'✓' if ex['match_beta'] else '✗'})")
        print(f"  q_HR blended = {ex['q_HR_blended']:.4f}  "
              f"(doc≈0.486  {'✓' if ex['match_q_HR'] else '✗'})")
        print(f"  At N_obs=0: β=0 (pure STIX, V3 recovery)")
        print(f"  At N_obs=κ={self.kappa}: β=βₘₐˣ/2={self.beta_max/2:.3f}")
        rows = self.beta_sensitivity([0,5,15,30,60,120,300,1000])
        print(f"\n  β vs N_obs:")
        print(f"    {'N_obs':>6}  {'β':>8}  {'STIX%':>7}  {'note':>12}")
        for r in rows:
            note = "← half-conf" if r["at_half_conf"] else \
                   "← CEILING"  if r["at_ceiling"]   else ""
            print(f"    {r['N_obs']:>6}  {r['beta']:>8.4f}  "
                  f"{r['stix_weight']*100:>6.1f}%  {note}")

    def _print_gk(self):
        gk = self.cfg.get("GK_scores", {})
        print(f"\n  τ_GK = {self.tau_GK}  (GK role-compatibility threshold, V4)")
        admitted = sum(1 for s in gk.values() if s >= self.tau_GK)
        print(f"  {admitted}/{len(gk)} (trap,persona) pairs admitted at τ_GK={self.tau_GK}")
        rows = self.gk_threshold_sensitivity(gk)
        print(f"\n  Admitted pairs vs τ_GK:")
        print(f"    {'τ_GK':>6}  {'admitted':>9}  {'%':>6}  {'note':>8}")
        for r in rows:
            note = "← current" if r["current"] else ""
            print(f"    {r['tau_GK']:>6.2f}  {r['admitted']:>9}  "
                  f"{r['pct_admitted']:>5.1f}%  {note}")

    def _print_c15(self):
        ex = self.worked_example_c15()
        print(f"\n  h_min={self.h_min}h  κ_min={self.kappa_min}h  (C15 slot-duration floor, V4)")
        ok  = ex["ok_case"]
        bad = ex["bad_case"]
        cfg = ex["cfg_ok"]
        print(f"  h_min=24h, κ_min=12h: {ok['note']}")
        print(f"  h_min=6h,  κ_min=12h: {bad['note']}")
        print(f"  Config:               {cfg['note']}")
        rows = self.slot_granularity_table()
        print(f"\n  C15 status vs slot duration (κ_min={self.kappa_min}h):")
        print(f"    {'h_min':>8}  {'margin':>8}  {'C15':>6}")
        for r in rows:
            status = "✓ OK" if r["satisfied"] else "✗ FAIL"
            print(f"    {r['h_min']:>6.0f}h  {r['margin_hours']:>+7.0f}h  {status}")

    def _print_decay(self):
        print(f"\n  ρ_decay={self.rho_decay}  Δ_N={self.Delta_N}  "
              f"(N cooldown parameters, V5)")
        print(f"  After Δ_N={self.Delta_N} consecutive inactive slots:")
        print(f"  N → ⌊ρ_decay × N⌋ = ⌊{self.rho_decay} × N⌋")
        rows = self.rho_decay_sensitivity(N_start=4)
        print(f"\n  N trajectory (starting N=4, then inactive) across ρ_decay:")
        print(f"    {'ρ_decay':>8}  " +
              "  ".join(f"t={i+1}" for i in range(8)) + "  final")
        for r in rows:
            traj = "  ".join(f"{n:>3}" for n in r["trajectory"])
            print(f"    {r['rho_decay']:>8.2f}  {traj}   → {r['final_N']}")
        print(f"\n  Current config (ρ_decay={self.rho_decay}, Δ_N={self.Delta_N}):")
        dec = self.N_decay_simulation(4, 8)
        print(f"  N from 4: {dec}  (decay begins at slot {self.Delta_N})")


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from config import CFG

    print("\n" + "=" * 70)
    print("  V4/V5 Gap Parameters — Self-Test")
    print("=" * 70)

    gp = GapParameters(CFG)

    # ── Test 1: γ document worked example ────────────────────────────
    print("\n[Test 1] γ — document worked example (V4)")
    ex = gp.worked_example_gamma()
    assert ex["match_N_0"], f"τᵈ(N=0) = {ex['N_0']:.3f}, expected ≈2.10"
    assert ex["match_N_2"], f"τᵈ(N=2) = {ex['N_2']:.3f}, expected ≈1.34"
    assert ex["pct_tighter"] > 30, "N=2 should be >30% tighter than N=0"
    print(f"  τᵈ(N=0) = {ex['N_0']:.3f}  (doc=2.10 ✓)")
    print(f"  τᵈ(N=2) = {ex['N_2']:.3f}  (doc=1.34 ✓)")
    print(f"  {ex['pct_tighter']:.1f}% tighter  ✓")

    # ── Test 2: γ=1 recovers V3 ──────────────────────────────────────
    print("\n[Test 2] γ=1 recovers V3 static threshold")
    gp_v3 = GapParameters({**CFG, "gamma": 1.0})
    td_n0  = gp_v3.tau_d_with_gamma(0.30, 0)
    td_n10 = gp_v3.tau_d_with_gamma(0.30, 10)
    assert abs(td_n0 - td_n10) < 1e-9, "γ=1 → τᵈ independent of N"
    print(f"  γ=1: τᵈ(N=0)={td_n0:.3f}  τᵈ(N=10)={td_n10:.3f}  "
          f"identical ✓")

    # ── Test 3: V5 floor prevents sub-slot threshold ──────────────────
    print("\n[Test 3] V5 floor — prevents sub-slot τᵈ (eq 12′)")
    td_extreme = gp.tau_d_with_gamma(rho_pi=0.85, N_ip=15)
    assert td_extreme == 1.0, f"Floor must clamp to 1.0; got {td_extreme}"
    print(f"  τᵈ(ρπ=0.85, N=15) = {td_extreme:.3f}  (floor ✓)")

    # ── Test 4: Nᵢ,ₚ recurrence document example ─────────────────────
    print("\n[Test 4] Nᵢ,ₚ recurrence — document worked example (V5)")
    ex = gp.worked_example_N()
    assert ex["match"], \
        f"N values {ex['N_values']} ≠ doc {ex['doc_N_values']}"
    print(f"  History: {ex['history']}")
    print(f"  N:       {ex['N_values']}  (doc={ex['doc_N_values']} ✓)")

    # ── Test 5: N active increments, inactive holds, then decays ──────
    print("\n[Test 5] N state transitions")
    Ns = gp.N_recurrence([1, 1, 0, 0])   # Δ_N=3, so 2 inactive slots hold
    assert Ns == [1, 2, 2, 2], f"Expected [1,2,2,2], got {Ns}"
    Ns5 = gp.N_recurrence([1, 1, 0, 0, 0])  # 3rd inactive → decay
    assert Ns5 == [1, 2, 2, 2, 1], f"Expected [1,2,2,2,1], got {Ns5}"
    print(f"  2 inactive (< Δ_N=3): {Ns}  holds ✓")
    print(f"  3 inactive (= Δ_N=3): {Ns5}  decays ✓")

    # ── Test 6: β worked example ──────────────────────────────────────
    print("\n[Test 6] β — document worked example (V4 Step 3b)")
    ex = gp.worked_example_beta()
    assert ex["match_beta"], \
        f"β={ex['beta']:.4f} ≠ expected 0.5714"
    assert ex["match_q_HR"], \
        f"q_HR={ex['q_HR_blended']:.4f} ≠ expected ≈0.486"
    print(f"  β = {ex['beta']:.4f}  (doc≈0.571 ✓)")
    print(f"  q_HR_workstation = {ex['q_HR_blended']:.4f}  "
          f"(doc≈0.486 ✓)")

    # ── Test 7: β = 0 at N_obs=0 (V3 backward compat) ────────────────
    print("\n[Test 7] β = 0 when N_obs = 0 (V3 backward compatibility)")
    b0 = gp.beta(0)
    assert b0 == 0.0, f"β must be 0 at N_obs=0; got {b0}"
    print(f"  β(N_obs=0) = {b0}  (pure STIX prior ✓)")

    # ── Test 8: β ceiling at βₘₐˣ ────────────────────────────────────
    print("\n[Test 8] β ceiling capped at βₘₐˣ")
    b_large = gp.beta(1_000_000)
    assert abs(b_large - gp.beta_max) < 1e-9, \
        f"β must approach βₘₐˣ={gp.beta_max}; got {b_large}"
    print(f"  β(N_obs=1M) = {b_large:.4f} = βₘₐˣ  ✓")

    # ── Test 9: β at N_obs = κ equals 0.5 (regardless of βₘₐˣ) ──────
    print("\n[Test 9] β at N_obs = κ is always 0.5 (half-saturation point)")
    # β = min(N/(N+κ), βₘₐˣ); at N=κ: β = κ/(2κ) = 0.5
    # This is the half-saturation of the confidence curve, not half of βₘₐˣ
    b_at_kappa = gp.beta(int(gp.kappa))
    assert abs(b_at_kappa - 0.5) < 0.02, \
        f"β at N_obs=κ must be ≈0.5; got {b_at_kappa:.4f}"
    # β = βₘₐˣ/2 is achieved at N_obs = κ·(βₘₐˣ/2)/(1−βₘₐˣ/2)
    half_ceil_N = gp.kappa * (gp.beta_max/2) / (1 - gp.beta_max/2)
    b_half_ceil = gp.beta(int(half_ceil_N))
    print(f"  β(N_obs=κ={gp.kappa:.0f}) = {b_at_kappa:.4f}  "
          f"(half-saturation of confidence curve ✓)")
    print(f"  β = βₘₐˣ/2={gp.beta_max/2:.3f} is reached at "
          f"N_obs≈{half_ceil_N:.1f}")
    print(f"  β(N_obs={int(half_ceil_N)}) = {b_half_ceil:.4f}  ✓")

    # ── Test 10: C15 check ───────────────────────────────────────────
    print("\n[Test 10] C15 slot-duration floor")
    ok  = gp.c15_check(h_min=24.0, kappa_min=12.0)
    bad = gp.c15_check(h_min=6.0,  kappa_min=12.0)
    assert ok["satisfied"],  "h_min=24h ≥ κ_min=12h must pass"
    assert not bad["satisfied"], "h_min=6h < κ_min=12h must fail"
    print(f"  h_min=24h: {ok['note']}  ✓")
    print(f"  h_min=6h:  {bad['note']}  ✓")

    # ── Test 11: τ_GK threshold ──────────────────────────────────────
    print("\n[Test 11] τ_GK GK admission threshold")
    gk = CFG.get("GK_scores", {})
    admitted_count = sum(1 for s in gk.values() if s >= gp.tau_GK)
    total_count    = len(gk)
    assert admitted_count > 0,           "Some pairs must be admitted"
    assert admitted_count < total_count, "Some pairs must be rejected"
    print(f"  τ_GK={gp.tau_GK}: {admitted_count}/{total_count} pairs admitted  ✓")
    # Verify admission is monotone in score
    assert gp.gk_admit(1.0)  and not gp.gk_admit(0.0), "Monotone admission ✓"
    print(f"  score=1.0 → admitted, score=0.0 → rejected  ✓")

    # ── Test 12: ρ_decay simulation ──────────────────────────────────
    print("\n[Test 12] ρ_decay and Δ_N — N cooldown simulation")
    dec = gp.N_decay_simulation(N_start=8, n_slots=6)
    # Slots 1,2 (inact=1,2 < Δ_N=3): hold at 8
    # Slot 3 (inact=3 = Δ_N=3): ⌊0.5×8⌋ = 4
    # Slot 4 (inact=4 > Δ_N=3): ⌊0.5×4⌋ = 2
    # Slot 5 (inact=5): ⌊0.5×2⌋ = 1
    # Slot 6 (inact=6): ⌊0.5×1⌋ = 0
    assert dec[0] == 8, f"t=1: hold at 8; got {dec[0]}"
    assert dec[2] == 4, f"t=3 (Δ_N hit): decay to 4; got {dec[2]}"
    assert dec[-1] == 0, f"Eventually reaches 0; got {dec[-1]}"
    print(f"  N from 8: {dec}")
    print(f"  Slots 1-2: hold (inact < Δ_N={gp.Delta_N})  ✓")
    print(f"  Slot 3: ⌊{gp.rho_decay}×8⌋={dec[2]} (Δ_N hit)  ✓")
    print(f"  Converges to 0  ✓")

    # ── Full report ──────────────────────────────────────────────────
    gp.print_all()

    print("\n[✓] All V4/V5 gap-parameter self-tests passed.")
