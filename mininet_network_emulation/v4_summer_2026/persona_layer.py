"""
persona_layer.py
Zone-Slot-Time-Persona V6 — Persona Layer
==========================================
Implements every new persona-layer parameter from Section A:

    P, GK_{i,p}, H, τᵈ, τᵈᵖ, τᵈ⁰, Δ, Δₚ, qₚ, ρₘₐˣ

Covers:
  • Persona catalogue P and GK plausibility (C5b)
  • Type-discovery flag  u_{i,z,t}         (C9)
  • Persona-discovery flag u_{i,z,t,p}     (C13)
  • Threat-adaptive τᵈ(i,z,t)              (C11, eq 12′ V5 floored)
  • Persona τᵈᵖ(i,z,t)                     (C13, eq 13′ V5 floored)
  • Churn tracking Δ / Δₚ                  (C8)
  • qₚ update: STIX Step 3a + empirical Step 3b (Algorithm 1 V3/V4)
  • Nᵢ,ₚ(t) recurrence with ρ_decay / Δ_N  (V5)
  • C8/C13 compatibility pre-check          (V5 eq 15)
  • C14 cross-zone persona uniqueness check (V3)

Usage:
    from config import CFG
    from persona_layer import PersonaLayer

    pl = PersonaLayer(CFG)
    pl.update_qp()                        # Algorithm 1 Steps 3a + 3b
    u_type    = pl.type_discovery_flags(schedule)
    u_persona = pl.persona_discovery_flags(schedule)
    sched_ok  = pl.validate_schedule(schedule)
    pl.print_summary()
"""

import math
from copy import deepcopy
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  PERSONA LAYER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class PersonaLayer:
    """
    Encapsulates all persona-layer state and computations for the V6 formulation.

    Parameters are loaded from CFG (config.py) once at construction.
    All mutation happens through named methods that mirror the document's
    equations exactly — no hidden state changes.
    """

    def __init__(self, cfg: dict):
        # ── Structural sets ───────────────────────────────────────────────
        self.K    = cfg["K"]                  # honeypot types
        self.Z    = cfg["Z"]                  # zones
        self.P    = cfg["P"]                  # persona catalogue
        self.H    = cfg["H"]                  # planning horizon

        # ── GK role-compatibility ─────────────────────────────────────────
        self.GK_scores   = cfg["GK_scores"]  # (trap,persona) → score ∈ [0,1]
        self.tau_GK      = cfg["tau_GK"]     # admission threshold
        self._gk_cache   = {}                # memoised admission decisions

        # ── Discovery thresholds (base values) ───────────────────────────
        self.tau_d0      = cfg["tau_d0"]     # τᵈ⁰ — type baseline
        self.tau_dp0     = cfg["tau_dp0"]    # τᵈᵖ⁰ — persona baseline
        self.rho_max     = cfg["rho_max"]    # ρₘₐˣ

        # ── Churn budgets ─────────────────────────────────────────────────
        self.Delta       = cfg["Delta"]      # Δ  — type churn cap (C8)
        self.Delta_p     = cfg["Delta_p"]    # Δₚ — persona churn cap

        # ── Persona priors qₚ  (mutable; updated by Algorithm 1) ─────────
        self.qp          = deepcopy(cfg["q"])   # working copy

        # ── V4 parameters ─────────────────────────────────────────────────
        self.gamma       = cfg["gamma"]      # γ   — learning decay
        self.beta_max    = cfg["beta_max"]   # βₘₐˣ
        self.kappa       = cfg["kappa"]      # κ   — half-confidence constant

        # ── V5 parameters ─────────────────────────────────────────────────
        self.rho_decay   = cfg["rho_decay"]  # ρ_decay
        self.Delta_N     = cfg["Delta_N"]    # Δ_N — cooldown window

        # ── STIX signals and empirical interaction data ───────────────────
        self.stix_signals            = cfg["stix_signals"]
        self.empirical_interactions  = cfg["empirical_interactions"]

        # ── Nᵢ,ₚ(t) cumulative observation state ─────────────────────────
        #    Indexed (trap, persona) → int
        self._N_ip          = defaultdict(int)    # Nᵢ,ₚ current value
        self._inactive_slots= defaultdict(int)    # consecutive inactive slots

        # ── Churn tracking ────────────────────────────────────────────────
        #    _churn_type[(trap,zone,persona)]    → #type-state changes
        #    _churn_persona[(trap,zone)]         → #persona changes
        self._churn_type    = defaultdict(int)
        self._churn_persona = defaultdict(int)
        self._prev_x        = {}   # (trap,zone,persona) → {0,1} at t-1

        # ── Precondition checks (run once at construction) ────────────────
        self._check_preconditions()

    # ─────────────────────────────────────────────────────────────────────
    #  PRECONDITION CHECKS  (C15 + C8/C13 compatibility)
    # ─────────────────────────────────────────────────────────────────────

    def _check_preconditions(self):
        """
        C8/C13 compatibility (eq 15, V5):
            Δ ≥ ⌈H / τᵈᵖ⌉ − 1
        Raises ValueError if violated.
        """
        min_rots = math.ceil(self.H / self.tau_dp0) - 1
        if self.Delta < min_rots:
            raise ValueError(
                f"C8/C13 INFEASIBLE: Δ={self.Delta} < "
                f"⌈{self.H}/{self.tau_dp0}⌉−1={min_rots}. "
                "Raise Δ or τᵈᵖ before solving."
            )
        print(f"[PersonaLayer] C8/C13 compat: Δ={self.Delta} ≥ {min_rots} ✓")

    # ─────────────────────────────────────────────────────────────────────
    #  P — PERSONA CATALOGUE
    # ─────────────────────────────────────────────────────────────────────

    def personas(self) -> list:
        """Return the full persona catalogue P."""
        return list(self.P)

    def persona_count(self) -> int:
        """Return |P|."""
        return len(self.P)

    # ─────────────────────────────────────────────────────────────────────
    #  GKᵢ,ₚ — ROLE-COMPATIBILITY (C5b, eq 14)
    # ─────────────────────────────────────────────────────────────────────

    def gk_score(self, trap: str, persona: str) -> float:
        """
        M(servertype(trap), persona) — raw compatibility score ∈ [0,1].
        Returns 0.0 for unknown pairs.
        """
        return self.GK_scores.get((trap, persona), 0.0)

    def gk_admitted(self, trap: str, persona: str) -> bool:
        """
        True iff M(servertype(trap), persona) ≥ τ_GK  (eq 14).
        Results are memoised since the matrix is static.
        """
        key = (trap, persona)
        if key not in self._gk_cache:
            self._gk_cache[key] = self.gk_score(trap, persona) >= self.tau_GK
        return self._gk_cache[key]

    def valid_personas(self, trap: str) -> list:
        """Return all personas admitted for this trap type (GK filter)."""
        return [p for p in self.P if self.gk_admitted(trap, p)]

    def gk_matrix(self) -> dict:
        """Return the full GK admission matrix as {(trap,persona): bool}."""
        return {(tr, p): self.gk_admitted(tr, p) for tr in self.K for p in self.P}

    # ─────────────────────────────────────────────────────────────────────
    #  τᵈ — THREAT-ADAPTIVE TYPE-DISCOVERY THRESHOLD  (C11, eq 12′)
    # ─────────────────────────────────────────────────────────────────────

    def tau_d(self, rho_pi: float, N_ip: int = 0) -> float:
        """
        Equation 12′ (V5 floored, supersedes eq 12):
            τᵈ(i,z,t) = max(1, τᵈ⁰ · (1 − ρπ/ρₘₐˣ) · γ^{Nᵢ,ₚ(t)})

        Args:
            rho_pi : current path probability ρπ (from STIX/TAXII or config)
            N_ip   : Nᵢ,ₚ(t) cumulative cross-zone observation count (V5)

        Returns:
            Effective type-discovery threshold (always ≥ 1).
        """
        unfloored = self.tau_d0 * (1.0 - rho_pi / self.rho_max) * (self.gamma ** N_ip)
        return max(1.0, unfloored)

    def tau_dp(self, N_ip: int = 0) -> float:
        """
        Equation 13′ (V5 floored, supersedes eq 13):
            τᵈᵖ(i,z,t) = max(1, τᵈᵖ⁰ · γ^{Nᵢ,ₚ(t)})

        Args:
            N_ip : Nᵢ,ₚ(t) cumulative observation count

        Returns:
            Effective persona-discovery threshold (always ≥ 1).
        """
        return max(1.0, self.tau_dp0 * (self.gamma ** N_ip))

    # ─────────────────────────────────────────────────────────────────────
    #  Nᵢ,ₚ(t) — CUMULATIVE OBSERVATION COUNT RECURRENCE  (V5)
    # ─────────────────────────────────────────────────────────────────────

    def step_N(
        self,
        trap: str,
        persona: str,
        active_any_zone: bool,
        type_burned_any_zone: bool,
    ) -> int:
        """
        Advance Nᵢ,ₚ(t) by one slot using the V5 formal recurrence:

            N(0)   = 0
            N(t)   = N(t−1) + 1   if active and type-undiscovered in any zone
            N(t)   = ⌊ρ_decay · N(t−1)⌋  if inactive ≥ Δ_N consecutive slots
            N(t)   = N(t−1)        otherwise

        Updates internal state and returns new Nᵢ,ₚ(t).
        """
        key = (trap, persona)
        N_prev = self._N_ip[key]

        if active_any_zone:
            self._inactive_slots[key] = 0
            if not type_burned_any_zone:
                self._N_ip[key] = N_prev + 1
            # if type burned, hold N (no new evidence accumulates)
        else:
            self._inactive_slots[key] += 1
            if self._inactive_slots[key] >= self.Delta_N:
                self._N_ip[key] = math.floor(self.rho_decay * N_prev)
            # else hold N until cooldown window expires

        return self._N_ip[key]

    def get_N(self, trap: str, persona: str) -> int:
        """Return current Nᵢ,ₚ(t) without advancing it."""
        return self._N_ip[(trap, persona)]

    def reset_N(self, trap: str, persona: str):
        """Reset Nᵢ,ₚ and inactive counter (e.g. when restarting a solve cycle)."""
        key = (trap, persona)
        self._N_ip[key] = 0
        self._inactive_slots[key] = 0

    def reset_all_N(self):
        """Reset Nᵢ,ₚ state for all (trap, persona) pairs."""
        self._N_ip.clear()
        self._inactive_slots.clear()

    # ─────────────────────────────────────────────────────────────────────
    #  TYPE-DISCOVERY FLAGS  u_{i,z,t}  (C9)
    # ─────────────────────────────────────────────────────────────────────

    def type_discovery_flags(
        self,
        schedule: dict,
        rho_pi: float = 0.30,
    ) -> dict:
        """
        Compute u_{i,z,t} for all (trap, zone, slot) triples.

        C9: u_{i,z,t} = 1 if the same type i has been active in zone z
            for τᵈ consecutive slots under *any* persona.

        Note (V5): C9 and C13 are independent — persona rotation does NOT
        reset the type-discovery clock (Section D, C9/C13 independence).

        Args:
            schedule : dict mapping (trap, zone, slot, persona) → {0,1}
            rho_pi   : current path probability used to compute τᵈ

        Returns:
            dict (trap, zone, slot) → bool  — True if type is discovered
        """
        u = {}
        for trap in self.K:
            for zone in self.Z:
                for t in range(self.H):
                    N_ip = self.get_N(trap, _most_used_persona(schedule, trap, zone, t))
                    td = self.tau_d(rho_pi, N_ip)
                    # Count consecutive active slots ending at t (any persona)
                    window_start = t - math.ceil(td) + 1
                    if window_start < 0:
                        u[(trap, zone, t)] = False
                        continue
                    consec = sum(
                        1
                        for s in range(window_start, t + 1)
                        if any(schedule.get((trap, zone, s, p), 0) for p in self.P)
                    )
                    u[(trap, zone, t)] = consec >= math.ceil(td)
        return u

    # ─────────────────────────────────────────────────────────────────────
    #  PERSONA-DISCOVERY FLAGS  u_{i,z,t,p}  (C13)
    # ─────────────────────────────────────────────────────────────────────

    def persona_discovery_flags(self, schedule: dict) -> dict:
        """
        Compute u_{i,z,t,p} for all (trap, zone, slot, persona) tuples.

        C13: u_{i,z,t,p} = 1 if persona p has been active at (i,z) for
             τᵈᵖ consecutive slots.

        Note (V5): independent of C9 — rotating personas does not offset
        the type-discovery clock, and vice versa.

        Args:
            schedule : dict (trap, zone, slot, persona) → {0,1}

        Returns:
            dict (trap, zone, slot, persona) → bool
        """
        u = {}
        for trap in self.K:
            for zone in self.Z:
                for persona in self.P:
                    for t in range(self.H):
                        N_ip = self.get_N(trap, persona)
                        tdp = self.tau_dp(N_ip)
                        window_start = t - math.ceil(tdp) + 1
                        if window_start < 0:
                            u[(trap, zone, t, persona)] = False
                            continue
                        consec = sum(
                            1
                            for s in range(window_start, t + 1)
                            if schedule.get((trap, zone, s, persona), 0)
                        )
                        u[(trap, zone, t, persona)] = consec >= math.ceil(tdp)
        return u

    # ─────────────────────────────────────────────────────────────────────
    #  DUAL DISCOVERY GUARD  (1−u_type)·(1−u_persona)  (Section E)
    # ─────────────────────────────────────────────────────────────────────

    def credit_guard(
        self,
        trap: str,
        zone: str,
        t: int,
        persona: str,
        u_type: dict,
        u_persona: dict,
    ) -> int:
        """
        Dual discovery guard from equations 6–11:
            (1 − u_{i,z,t}) · (1 − u_{i,z,t,p})
        Returns 1 (earn credit) or 0 (credit zeroed — either flag set).
        """
        ut = u_type.get((trap, zone, t), False)
        up = u_persona.get((trap, zone, t, persona), False)
        return int(not ut) * int(not up)

    # ─────────────────────────────────────────────────────────────────────
    #  Δ, Δₚ — CHURN TRACKING  (C8)
    # ─────────────────────────────────────────────────────────────────────

    def record_churn(self, schedule: dict):
        """
        Compute churn counts from a complete schedule.
        Updates internal _churn_type and _churn_persona counters.

        C8 definition:
            Σ_t |x_{i,z,t,p} − x_{i,z,t−1,p}| ≤ Δ  ∀i,z,p
        """
        self._churn_type.clear()
        self._churn_persona.clear()
        prev = {}

        for t in range(self.H):
            for trap in self.K:
                for zone in self.Z:
                    prev_p = prev.get((trap, zone))
                    cur_p = None
                    for persona in self.P:
                        if schedule.get((trap, zone, t, persona), 0):
                            cur_p = persona
                            break
                    # Type-state change: was active/inactive flip?
                    was_active = prev_p is not None
                    is_active  = cur_p  is not None
                    if t > 0 and was_active != is_active:
                        key = (trap, zone, prev_p or cur_p)
                        self._churn_type[key] += 1
                    # Persona change (same trap, same zone, different persona)
                    if t > 0 and was_active and is_active and prev_p != cur_p:
                        self._churn_persona[(trap, zone)] += 1
                    prev[(trap, zone)] = cur_p

    def churn_violations(self) -> dict:
        """
        Return dict of churn violations after record_churn() has been called.
        Keys are (trap, zone[, persona]) tuples where Δ or Δₚ is exceeded.
        """
        violations = {}
        for key, count in self._churn_type.items():
            if count > self.Delta:
                violations[("type_churn", key)] = {
                    "count": count, "limit": self.Delta
                }
        for key, count in self._churn_persona.items():
            if count > self.Delta_p:
                violations[("persona_churn", key)] = {
                    "count": count, "limit": self.Delta_p
                }
        return violations

    def churn_ok(self, schedule: dict) -> bool:
        """True if the schedule satisfies both Δ and Δₚ caps everywhere."""
        self.record_churn(schedule)
        return len(self.churn_violations()) == 0

    # ─────────────────────────────────────────────────────────────────────
    #  qₚ — PERSONA PRIORS  (Algorithm 1 Steps 3a + 3b)
    # ─────────────────────────────────────────────────────────────────────

    def update_qp(
        self,
        stix_signals: list | None = None,
        empirical: dict | None = None,
        n_obs: int | None = None,
    ) -> dict:
        """
        Algorithm 1 — Update persona priors qₚ.

        Step 3a (V3): confidence-weighted STIX blend.
            weight_s = c_s / Σ c_s′
            qₚ ← qₚ + Σ_s weight_s · δ_{s,p}
            normalize so Σₚ qₚ = 1

        Step 3b (V4): empirical interaction posterior blend.
            êₚ(t) = interactions(p) / Σ interactions(p′)
            β = min(N_obs / (N_obs + κ), βₘₐˣ)
            qₚ ← (1−β)·qₚ + β·êₚ(t)
            normalize so Σₚ qₚ = 1

        Args:
            stix_signals : list of signal dicts (defaults to config signals)
            empirical    : {persona: count} interaction data (defaults to config)
            n_obs        : total observation count (defaults to sum of empirical)

        Returns:
            Updated qₚ dict (also updates self.qp in place).
        """
        signals = stix_signals or self.stix_signals
        eta     = empirical    or self.empirical_interactions
        N_obs   = n_obs        if n_obs is not None else sum(eta.values())

        # ── Step 3a: STIX confidence-weighted blend ──────────────────────
        total_conf = sum(s["confidence"] for s in signals)
        if total_conf > 0:
            for persona in self.P:
                delta = sum(
                    (s["confidence"] / total_conf) * s["deltas"].get(persona, 0.0)
                    for s in signals
                )
                self.qp[persona] = max(0.0, self.qp[persona] + delta)
        self._normalise_qp()

        # ── Step 3b: empirical interaction posterior blend ────────────────
        if N_obs > 0:
            beta      = min(N_obs / (N_obs + self.kappa), self.beta_max)
            eta_total = sum(eta.values()) or 1
            for persona in self.P:
                q_emp = eta.get(persona, 0) / eta_total
                self.qp[persona] = (1.0 - beta) * self.qp[persona] + beta * q_emp
            self._normalise_qp()

        return dict(self.qp)

    def _normalise_qp(self):
        total = sum(self.qp.values())
        if total > 0:
            for p in self.P:
                self.qp[p] /= total

    def reset_qp(self, q_new: dict | None = None):
        """Reset qₚ to uniform (default) or to a provided dict."""
        if q_new:
            self.qp = {p: q_new.get(p, 1.0 / len(self.P)) for p in self.P}
        else:
            self.qp = {p: 1.0 / len(self.P) for p in self.P}
        self._normalise_qp()

    # ─────────────────────────────────────────────────────────────────────
    #  C14 — CROSS-ZONE PERSONA UNIQUENESS VALIDATION  (V3)
    # ─────────────────────────────────────────────────────────────────────

    def c14_violations(self, schedule: dict) -> list:
        """
        Identify all C14 violations in a schedule.

        C14: ¬x_{i,z,t,p} ∨ ¬x_{l,z′,t,p}  ∀i,l∈K, z≠z′∈Z, ∀t, ∀p
        i.e., the same persona p cannot appear in two different zones
        in the same slot t.

        Returns:
            List of dicts describing each violation:
            {slot, persona, zones, deployments}
        """
        violations = []
        for t in range(self.H):
            for persona in self.P:
                # Collect every (trap,zone) deploying this persona at slot t
                active = [
                    (trap, zone)
                    for trap in self.K
                    for zone in self.Z
                    if schedule.get((trap, zone, t, persona), 0)
                ]
                # Group by zone
                zones_used = list({zone for _, zone in active})
                if len(zones_used) > 1:
                    violations.append({
                        "slot":        t,
                        "persona":     persona,
                        "zones":       zones_used,
                        "deployments": active,
                    })
        return violations

    def c14_ok(self, schedule: dict) -> bool:
        """True if the schedule has no C14 cross-zone persona collisions."""
        return len(self.c14_violations(schedule)) == 0

    # ─────────────────────────────────────────────────────────────────────
    #  C12 — PERSONA CONFLICT WITHIN ZONE  (same-zone uniqueness)
    # ─────────────────────────────────────────────────────────────────────

    def c12_violations(self, schedule: dict) -> list:
        """
        Identify C12 violations: two distinct trap types wearing the same
        persona in the same zone at the same slot.

        C12: ¬x_{i,z,t,p} ∨ ¬x_{l,z,t,p}  ∀i≠l, ∀z,t,p
        """
        violations = []
        for t in range(self.H):
            for zone in self.Z:
                for persona in self.P:
                    traps_active = [
                        trap for trap in self.K
                        if schedule.get((trap, zone, t, persona), 0)
                    ]
                    if len(traps_active) > 1:
                        violations.append({
                            "slot":    t,
                            "zone":    zone,
                            "persona": persona,
                            "traps":   traps_active,
                        })
        return violations

    # ─────────────────────────────────────────────────────────────────────
    #  FULL SCHEDULE VALIDATION
    # ─────────────────────────────────────────────────────────────────────

    def validate_schedule(
        self,
        schedule: dict,
        rho_pi: float = 0.30,
        verbose: bool = True,
    ) -> bool:
        """
        Run all persona-layer constraint checks against a candidate schedule.
        Returns True if all checks pass.

        Checks:
            C5b  — GK plausibility (every (trap,persona) pair must be admitted)
            C12  — persona conflict within zone
            C14  — cross-zone persona uniqueness
            C8   — type and persona churn budgets
        """
        ok = True

        # C5b
        c5b_fails = [
            (trap, zone, t, p)
            for (trap, zone, t, p), v in schedule.items()
            if v and not self.gk_admitted(trap, p)
        ]
        if c5b_fails:
            ok = False
            if verbose:
                print(f"[C5b] {len(c5b_fails)} GK violations (first 3):")
                for f in c5b_fails[:3]:
                    print(f"  trap={f[0]}  persona={f[3]}  "
                          f"score={self.gk_score(f[0],f[3]):.2f} < τ_GK={self.tau_GK}")

        # C12
        c12 = self.c12_violations(schedule)
        if c12:
            ok = False
            if verbose:
                print(f"[C12] {len(c12)} persona-conflict violations:")
                for v in c12[:3]:
                    print(f"  slot={v['slot']} zone={v['zone']} "
                          f"persona={v['persona']} traps={v['traps']}")

        # C14
        c14 = self.c14_violations(schedule)
        if c14:
            ok = False
            if verbose:
                print(f"[C14] {len(c14)} cross-zone persona violations:")
                for v in c14[:3]:
                    print(f"  slot={v['slot']} persona={v['persona']} "
                          f"zones={v['zones']}")

        # C8 churn
        churn_v = None
        if not self.churn_ok(schedule):
            ok = False
            churn_v = self.churn_violations()
            if verbose:
                print(f"[C8]  {len(churn_v)} churn-budget violations:")
                for key, info in list(churn_v.items())[:3]:
                    print(f"  {key}: count={info['count']} > limit={info['limit']}")

        if verbose and ok:
            print("[✓] Schedule passes all persona-layer constraints (C5b,C12,C14,C8)")
        return ok

    # ─────────────────────────────────────────────────────────────────────
    #  SUMMARY / DIAGNOSTICS
    # ─────────────────────────────────────────────────────────────────────

    def print_summary(self):
        """Print a human-readable summary of current persona-layer state."""
        print("\n" + "=" * 65)
        print("  Persona Layer — State Summary")
        print("=" * 65)

        # P
        print(f"\n[P] Persona catalogue  |P| = {len(self.P)}")
        for p in self.P:
            print(f"    {p}")

        # H
        print(f"\n[H] Planning horizon   H = {self.H} slots")

        # GK
        admitted = [(tr,p) for tr in self.K for p in self.P if self.gk_admitted(tr,p)]
        total    = len(self.K) * len(self.P)
        print(f"\n[GK] τ_GK = {self.tau_GK}  →  "
              f"{len(admitted)}/{total} (trap,persona) pairs admitted")
        print("     Admitted pairs:")
        for tr,p in admitted:
            print(f"       ({tr:14s}, {p:18s})  score={self.gk_score(tr,p):.2f}")

        # Discovery thresholds
        print(f"\n[τᵈ/τᵈᵖ]  τᵈ⁰={self.tau_d0}  τᵈᵖ⁰={self.tau_dp0}  ρₘₐˣ={self.rho_max}")
        for rho in [0.15, 0.30, 0.55, 0.85]:
            td  = self.tau_d(rho,  N_ip=0)
            tdp = self.tau_dp(N_ip=0)
            print(f"     ρπ={rho:.2f}  →  τᵈ={td:.2f}  τᵈᵖ={tdp:.2f}  "
                  f"(V5 floor applied if < 1)")

        # Churn budgets
        print(f"\n[Δ/Δₚ]  Δ={self.Delta}  Δₚ={self.Delta_p}")
        min_rots = math.ceil(self.H / self.tau_dp0) - 1
        print(f"     C8/C13 compat: Δ={self.Delta} ≥ "
              f"⌈{self.H}/{self.tau_dp0}⌉−1={min_rots}  ✓")

        # qₚ
        print(f"\n[qₚ]  Σₚ qₚ = {sum(self.qp.values()):.4f}")
        for p in self.P:
            bar = "█" * int(self.qp[p] * 40)
            print(f"     {p:20s}  {self.qp[p]:.4f}  {bar}")

        # Nᵢ,ₚ state
        active_N = {k: v for k, v in self._N_ip.items() if v > 0}
        if active_N:
            print(f"\n[Nᵢ,ₚ]  ρ_decay={self.rho_decay}  Δ_N={self.Delta_N}")
            for (trap, persona), n in active_N.items():
                inact = self._inactive_slots[(trap, persona)]
                print(f"     ({trap:14s}, {persona:18s})  "
                      f"N={n}  inactive_slots={inact}")
        else:
            print("\n[Nᵢ,ₚ]  All zero (no slots processed yet)")

        print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _most_used_persona(schedule, trap, zone, t_end):
    """
    Utility: return the persona most used by (trap,zone) up to slot t_end.
    Used to select the representative N_ip for τᵈ computation in C9.
    """
    counts = defaultdict(int)
    for t in range(t_end + 1):
        for p in schedule:
            if len(p) == 4:
                tr, z, ts, pe = p
                if tr == trap and z == zone and ts == t:
                    counts[pe] += schedule[p]
    return max(counts, key=counts.get) if counts else ""


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST  ── python persona_layer.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    try:
        from config import CFG
    except ImportError:
        print("[WARN] config.py not found — using inline minimal config")
        CFG = {
            "K": ["ssh_trap","db_trap","scada_trap","ad_trap","dns_trap","web_trap","generic_trap","smb_trap"],
            "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
            "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
            "H": 4,
            "GK_scores": {
                ("ssh_trap","HR_workstation"):0.85, ("ssh_trap","DevOps_server"):0.90,
                ("ssh_trap","Finance_DB"):0.40,     ("ssh_trap","Generic_Linux"):0.75,
                ("db_trap","HR_workstation"):0.50,  ("db_trap","DevOps_server"):0.70,
                ("db_trap","Finance_DB"):0.95,      ("db_trap","Generic_Linux"):0.60,
                ("scada_trap","Generic_Linux"):0.90,("scada_trap","DevOps_server"):0.50,
                ("scada_trap","HR_workstation"):0.20,("scada_trap","Finance_DB"):0.15,
                ("ad_trap","HR_workstation"):0.90,  ("ad_trap","DevOps_server"):0.75,
                ("ad_trap","Finance_DB"):0.60,      ("ad_trap","Generic_Linux"):0.40,
                ("dns_trap","HR_workstation"):0.55, ("dns_trap","DevOps_server"):0.80,
                ("dns_trap","Finance_DB"):0.40,     ("dns_trap","Generic_Linux"):0.85,
                ("web_trap","HR_workstation"):0.65, ("web_trap","DevOps_server"):0.85,
                ("web_trap","Finance_DB"):0.50,     ("web_trap","Generic_Linux"):0.80,
                ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
                ("generic_trap","Finance_DB"):0.50, ("generic_trap","Generic_Linux"):0.80,
                ("smb_trap","HR_workstation"):0.80, ("smb_trap","DevOps_server"):0.70,
                ("smb_trap","Finance_DB"):0.55,     ("smb_trap","Generic_Linux"):0.45,
            },
            "tau_GK": 0.65, "tau_d0": 3, "tau_dp0": 2, "rho_max": 1.0,
            "Delta": 2, "Delta_p": 2,
            "q": {"HR_workstation":0.25,"DevOps_server":0.25,"Finance_DB":0.25,"Generic_Linux":0.25},
            "gamma": 0.80, "beta_max": 0.60, "kappa": 30.0,
            "rho_decay": 0.5, "Delta_N": 3,
            "stix_signals": [
                {"confidence":0.88,"deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,"DevOps_server":-0.05,"Generic_Linux":-0.05}},
                {"confidence":0.45,"deltas":{"DevOps_server":+0.20,"Generic_Linux":+0.10,"Finance_DB":-0.05,"HR_workstation":-0.05}},
            ],
            "empirical_interactions": {"Finance_DB":18,"HR_workstation":12,"DevOps_server":7,"Generic_Linux":3},
            "h_min": 24.0, "kappa_min": 12.0,
        }

    print("\n" + "=" * 65)
    print("  Persona Layer — Self-Test")
    print("=" * 65)

    pl = PersonaLayer(CFG)

    # ── Test 1: GK admission ─────────────────────────────────────────────
    print("\n[Test 1] GK admission")
    assert pl.gk_admitted("db_trap",    "Finance_DB"),       "db_trap/Finance_DB should be admitted"
    assert not pl.gk_admitted("scada_trap","Finance_DB"),    "scada_trap/Finance_DB should be rejected"
    assert pl.gk_admitted("ssh_trap",   "HR_workstation"),   "ssh_trap/HR should be admitted"
    print("  All GK admission checks pass ✓")

    # ── Test 2: τᵈ floor ────────────────────────────────────────────────
    print("\n[Test 2] τᵈ V5 floor (eq 12′)")
    td_low  = pl.tau_d(rho_pi=0.30, N_ip=0)
    td_high = pl.tau_d(rho_pi=0.85, N_ip=15)
    assert td_low  > 1.0, "τᵈ at low threat should be > 1"
    assert td_high == 1.0, "τᵈ floor must clamp to 1 at extreme conditions"
    print(f"  ρπ=0.30 N=0  → τᵈ={td_low:.3f}  (above floor) ✓")
    print(f"  ρπ=0.85 N=15 → τᵈ={td_high:.3f}  (floor activated) ✓")

    # ── Test 3: τᵈᵖ floor ───────────────────────────────────────────────
    print("\n[Test 3] τᵈᵖ V5 floor (eq 13′)")
    tdp_norm  = pl.tau_dp(N_ip=0)
    tdp_floor = pl.tau_dp(N_ip=20)
    assert tdp_norm  == 2.0, "τᵈᵖ at N=0 should equal τᵈᵖ⁰=2"
    assert tdp_floor == 1.0, "τᵈᵖ floor must clamp to 1 after many observations"
    print(f"  N=0  → τᵈᵖ={tdp_norm:.3f}  ✓")
    print(f"  N=20 → τᵈᵖ={tdp_floor:.3f}  (floor activated) ✓")

    # ── Test 4: Nᵢ,ₚ recurrence ─────────────────────────────────────────
    print("\n[Test 4] Nᵢ,ₚ(t) recurrence (V5)")
    pl.reset_N("ssh_trap","HR_workstation")
    n1 = pl.step_N("ssh_trap","HR_workstation", active_any_zone=True,  type_burned_any_zone=False)
    n2 = pl.step_N("ssh_trap","HR_workstation", active_any_zone=True,  type_burned_any_zone=False)
    n3 = pl.step_N("ssh_trap","HR_workstation", active_any_zone=False, type_burned_any_zone=False)
    n4 = pl.step_N("ssh_trap","HR_workstation", active_any_zone=False, type_burned_any_zone=False)
    n5 = pl.step_N("ssh_trap","HR_workstation", active_any_zone=False, type_burned_any_zone=False)  # Δ_N=3 hit → decay
    assert n1 == 1 and n2 == 2, "N should increment when active"
    assert n3 == 2 and n4 == 2, "N should hold during cooldown window"
    assert n5 == math.floor(0.5 * 2) == 1, "N should decay after Δ_N inactive slots"
    print(f"  N: 0→{n1}→{n2} (active×2)  hold {n3}→{n4} (inactive×2)  decay→{n5} (Δ_N=3 hit) ✓")

    # ── Test 5: qₚ update Algorithm 1 ───────────────────────────────────
    print("\n[Test 5] qₚ update (Algorithm 1 Steps 3a + 3b)")
    pl.reset_qp()
    q_before = dict(pl.qp)
    q_after  = pl.update_qp()
    assert abs(sum(q_after.values()) - 1.0) < 1e-9, "qₚ must sum to 1 after update"
    assert q_after["Finance_DB"] > q_before["Finance_DB"], \
        "Finance_DB should rise after financial STIX signal"
    print(f"  Finance_DB: {q_before['Finance_DB']:.3f} → {q_after['Finance_DB']:.3f}  ✓")
    print(f"  Σₚ qₚ = {sum(q_after.values()):.6f}  ✓")

    # ── Test 6: C12 and C14 checks ───────────────────────────────────────
    print("\n[Test 6] C12 / C14 constraint checks")
    # Good schedule: one trap per zone per slot, distinct personas
    good_schedule = {
        ("ssh_trap",  "DMZ",      0, "HR_workstation"):  1,
        ("db_trap",   "Internal", 0, "Finance_DB"):       1,
        ("dns_trap",  "Cloud",    0, "DevOps_server"):    1,
        ("scada_trap","OT",       0, "Generic_Linux"):    1,
    }
    assert pl.c12_violations(good_schedule) == [], "Good schedule: no C12 violations"
    assert pl.c14_violations(good_schedule) == [], "Good schedule: no C14 violations"
    print("  Good schedule: C12=0, C14=0 ✓")

    # Bad schedule: same persona in two zones (C14 violation)
    bad_schedule = {
        ("ssh_trap", "DMZ",      0, "HR_workstation"): 1,
        ("ad_trap",  "Internal", 0, "HR_workstation"): 1,  # C14 violation
    }
    c14_v = pl.c14_violations(bad_schedule)
    assert len(c14_v) == 1, "Should detect exactly one C14 violation"
    print(f"  Bad schedule: C14={len(c14_v)} violation detected ✓")

    # ── Test 7: Full validation ──────────────────────────────────────────
    print("\n[Test 7] Full schedule validation")
    ok = pl.validate_schedule(good_schedule, verbose=True)
    assert ok, "Good schedule should pass all persona-layer checks"

    # ── Summary ──────────────────────────────────────────────────────────
    pl.print_summary()

    print("\n[✓] All persona-layer self-tests passed.")
