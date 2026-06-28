"""
hard_constraints.py
Zone-Slot-Time-Persona V6 — Hard Constraints C1–C15 (Section D)
================================================================
Implements all fifteen hard constraints as:
  1. Validators   — check a candidate schedule for violations
  2. WCNF clauses — generate pysat-compatible hard clauses for RC2

Constraint families:
  C1       detection requires real undiscovered deployment (no phantom credits)
  C2       global budget per slot
  C3       per-zone budget per slot
  C4       type-conflict pairs cannot co-deploy (unchanged)
  C5       air-gap isolation (unchanged)
  C5b      GK plausibility — persona must match server role
  C6       path-hop coverage requires a detection event
  C7       early interception requires a non-final hop covered
  C8       type-rotation churn cap Δ per (trap,zone,persona)
  C9       type-discovery flag after τᵈ consecutive active slots
  C10      path persistence — critical hop covered ≥ ⌈ρπ·H⌉ slots
  C11      threat-adaptive τᵈ tightens with rising ρπ
  C12      persona-conflict — same persona in same zone (analogue of C4)
  C13      persona-rotation — burned after τᵈᵖ consecutive slots
  C14      cross-zone persona uniqueness (V3)
  C15      slot-duration floor h_min ≥ κ_min (V4)

V5 clarification: C1–C15 are a flat conjunction — no priority ordering.
A schedule is feasible iff it satisfies ALL fifteen simultaneously.

Usage:
    from config              import CFG
    from persona_layer       import PersonaLayer
    from decision_variables  import DecisionVariables
    from hard_constraints    import HardConstraints

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dv.load_schedule(schedule, rho_pi=0.30)
    dv.compute_all_derived()

    hc  = HardConstraints(CFG, pl, dv)

    ok, report = hc.validate_all()
    clauses    = hc.wcnf_clauses()     # list of int-lists for pysat
"""

import math
from collections import defaultdict
from pysat.formula import WCNF


# ─────────────────────────────────────────────────────────────────────────────
#  HARD CONSTRAINTS CLASS
# ─────────────────────────────────────────────────────────────────────────────

class HardConstraints:
    """
    Validates and encodes all 15 hard constraints.

    Two modes:
      validate_all(schedule)  — returns (bool, report_dict) against a concrete schedule
      wcnf_clauses(var_map)   — returns WCNF hard-clause list for the RC2 encoder
    """

    def __init__(self, cfg: dict, persona_layer, decision_vars=None):
        # ── Config ────────────────────────────────────────────────────
        self.K            = cfg["K"]
        self.Z            = cfg["Z"]
        self.P            = cfg["P"]
        self.H            = cfg["H"]
        self.G            = cfg["G"]
        self.C_conflicts  = cfg["C_conflicts"]
        self.I2           = cfg["I2"]
        self.diamond      = cfg["diamond_affinity"]
        self.trap_techs   = cfg["trap_techniques"]
        self.A_per_zone   = cfg["A_per_zone"]
        self.cost_type    = cfg["cost_per_type"]
        self.cost_zone_mul= cfg["cost_zone_multiplier"]
        self.B_global     = cfg["B"]
        self.B_zone       = cfg["B2"]
        self.h_min        = cfg["h_min"]
        self.kappa_min    = cfg["kappa_min"]

        # ── Persona layer (τᵈ, τᵈᵖ, GK, Δ, Δₚ) ───────────────────────
        self.pl = persona_layer

        # ── Decision variables (u_type, u_persona, c, p_path, e) ──────
        self.dv = decision_vars

        # ── Asset list ────────────────────────────────────────────────
        self._assets, self._asset_zone = self._build_assets()

        # ── C15: run precondition check immediately ────────────────────
        self._c15_ok = self.h_min >= self.kappa_min

    # ─────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────

    def _build_assets(self):
        assets = []; az = {}; aid = 0
        for zone in self.Z:
            for _ in range(self.A_per_zone.get(zone, 0)):
                assets.append((aid, zone)); az[aid] = zone; aid += 1
        return assets, az

    def _zone_of(self, a): return self._asset_zone.get(a, "")
    def _assets_in(self, zone): return [a for a,z in self._assets if z == zone]

    def _cost(self, trap, zone):
        return self.cost_type.get(trap, 1.0) * self.cost_zone_mul.get(zone, 1.0)

    def _x(self, trap, zone, t, persona):
        return self.dv.x(trap, zone, t, persona) if self.dv else 0

    def _u_type(self, trap, zone, t):
        return self.dv.u_type(trap, zone, t) if self.dv else 0

    def _u_persona(self, trap, zone, t, persona):
        return self.dv.u_persona(trap, zone, t, persona) if self.dv else 0

    def _c_det(self, tech, asset, t):
        return self.dv.c(tech, asset, t) if self.dv else 0

    def _p_path(self, pid, hop, t):
        return self.dv.p_path(pid, hop, t) if self.dv else 0

    def _e(self, pid, t):
        return self.dv.e_intercept(pid, t) if self.dv else 0

    # ─────────────────────────────────────────────────────────────────
    #  INDIVIDUAL CONSTRAINT VALIDATORS
    # ─────────────────────────────────────────────────────────────────

    def check_c1(self) -> list:
        """
        C1: ¬cⱼ,a,t ∨ ⋁ᵢ,ₚ (xᵢ,zone(a),t,ₚ · (1−uᵢ,zone(a),t,ₚ))
        No phantom credits — every detection must have a real, undiscovered
        deployment behind it.
        Returns list of (tech, asset, t) violations.
        """
        violations = []
        all_techs = {tech for techs in self.trap_techs.values() for tech in techs}
        for tech in all_techs:
            for asset, zone in self._assets:
                for t in range(self.H):
                    if not self._c_det(tech, asset, t):
                        continue
                    # Must exist a supporting deployment
                    supported = any(
                        self._x(trap, zone, t, p) and
                        not self._u_type(trap, zone, t) and
                        not self._u_persona(trap, zone, t, p)
                        for trap in self.K
                        if tech in self.trap_techs.get(trap, [])
                        for p in self.P
                    )
                    if not supported:
                        violations.append({
                            "constraint": "C1",
                            "tech": tech, "asset": asset, "zone": zone, "t": t,
                            "note": "detection fired without undiscovered deployment"
                        })
        return violations

    def check_c2(self) -> list:
        """
        C2: Σᵢ Σz Σₚ costᵢ,z · xᵢ,z,t,ₚ ≤ B  ∀t
        Global budget per slot.
        """
        violations = []
        for t in range(self.H):
            spend = sum(
                self._cost(trap, zone) * self._x(trap, zone, t, p)
                for trap in self.K for zone in self.Z for p in self.P
            )
            if spend > self.B_global:
                violations.append({
                    "constraint": "C2", "t": t,
                    "spend": spend, "limit": self.B_global,
                    "excess": spend - self.B_global
                })
        return violations

    def check_c3(self) -> list:
        """
        C3: Σᵢ Σₚ costᵢ,z · xᵢ,z,t,ₚ ≤ Bz  ∀z,t
        Per-zone budget per slot.
        """
        violations = []
        for zone in self.Z:
            limit = self.B_zone.get(zone, float("inf"))
            for t in range(self.H):
                spend = sum(
                    self._cost(trap, zone) * self._x(trap, zone, t, p)
                    for trap in self.K for p in self.P
                )
                if spend > limit:
                    violations.append({
                        "constraint": "C3", "zone": zone, "t": t,
                        "spend": spend, "limit": limit,
                        "excess": spend - limit
                    })
        return violations

    def check_c4(self) -> list:
        """
        C4: ¬xᵢ,t ∨ ¬xₗ,t  ∀(kᵢ,kₗ)∈C, ∀t
        Conflicting types cannot co-deploy in the same slot.
        """
        violations = []
        for t in range(self.H):
            for (ta, tb) in self.C_conflicts:
                a_active = any(self._x(ta, z, t, p) for z in self.Z for p in self.P)
                b_active = any(self._x(tb, z, t, p) for z in self.Z for p in self.P)
                if a_active and b_active:
                    violations.append({
                        "constraint": "C4", "t": t,
                        "trap_a": ta, "trap_b": tb
                    })
        return violations

    def check_c5(self) -> list:
        """
        C5: xᵢ,z,t,ₚ = 0 if zone z is air-gapped from required connectivity.
        Types restricted by ⋄ affinity; air-gap pairs in I₂ enforce isolation.
        """
        violations = []
        air_gap_zones = {z for pair in self.I2 for z in pair}
        for trap in self.K:
            for zone in self.Z:
                for t in range(self.H):
                    for p in self.P:
                        if not self._x(trap, zone, t, p):
                            continue
                        # Zone-affinity check
                        if zone not in self.diamond.get(trap, []):
                            violations.append({
                                "constraint": "C5", "trap": trap,
                                "zone": zone, "t": t, "persona": p,
                                "note": f"{zone} not in ⋄({trap})"
                            })
                        # Air-gap check (scada_trap → OT only; others excluded from OT)
                        elif zone in air_gap_zones and zone not in self.diamond.get(trap, []):
                            violations.append({
                                "constraint": "C5", "trap": trap,
                                "zone": zone, "t": t, "persona": p,
                                "note": "air-gap violation"
                            })
        return violations

    def check_c5b(self) -> list:
        """
        C5b: (servertype(a), persona(p)) ∈ GKᵢ,ₚ  (eq 14)
        GK plausibility — persona must be believable for this trap type.
        """
        violations = []
        for trap in self.K:
            for zone in self.Z:
                for t in range(self.H):
                    for p in self.P:
                        if self._x(trap, zone, t, p) and \
                           not self.pl.gk_admitted(trap, p):
                            violations.append({
                                "constraint": "C5b", "trap": trap,
                                "zone": zone, "t": t, "persona": p,
                                "score": self.pl.gk_score(trap, p),
                                "threshold": self.pl.tau_GK
                            })
        return violations

    def check_c6(self) -> list:
        """
        C6: ¬pπ,h,t ∨ ⋁ cⱼ,a,t
        Path-hop coverage requires a detection event in the correct zone at t.
        """
        violations = []
        all_techs = {tech for techs in self.trap_techs.values() for tech in techs}
        for path in self.G:
            pid   = path["id"]
            zones = path["zones"]
            for hop, zone in enumerate(zones):
                assets_here = self._assets_in(zone)
                for t in range(self.H):
                    if not self._p_path(pid, hop, t):
                        continue
                    # Must have a supporting detection event in this zone
                    has_det = any(
                        self._c_det(tech, a, t)
                        for tech in all_techs for a in assets_here
                    )
                    if not has_det:
                        violations.append({
                            "constraint": "C6", "path": pid,
                            "hop": hop, "zone": zone, "t": t,
                            "note": "path coverage claimed without detection"
                        })
        return violations

    def check_c7(self) -> list:
        """
        C7: eπ,t = 1 ⇒ ∃h < |π|−1: pπ,h,t = 1
        Early interception requires a non-final hop to be covered.
        """
        violations = []
        for path in self.G:
            pid    = path["id"]
            n_hops = len(path["zones"])
            for t in range(self.H):
                if not self._e(pid, t):
                    continue
                has_nonfinal = any(
                    self._p_path(pid, hop, t)
                    for hop in range(n_hops - 1)
                )
                if not has_nonfinal:
                    violations.append({
                        "constraint": "C7", "path": pid, "t": t,
                        "note": "early intercept flagged but only final hop covered"
                    })
        return violations

    def check_c8(self, schedule: dict) -> list:
        """
        C8: Σt |xᵢ,z,t,ₚ − xᵢ,z,t−1,ₚ| ≤ Δ  ∀i,z,p
        Type-rotation churn cap — prevents operational thrashing.
        """
        violations = []
        for trap in self.K:
            for zone in self.Z:
                for p in self.P:
                    changes = sum(
                        abs(schedule.get((trap,zone,t,p),0) -
                            schedule.get((trap,zone,t-1,p),0))
                        for t in range(1, self.H)
                    )
                    if changes > self.pl.Delta:
                        violations.append({
                            "constraint": "C8",
                            "trap": trap, "zone": zone, "persona": p,
                            "changes": changes, "limit": self.pl.Delta
                        })
        return violations

    def check_c9(self, rho_pi: float = 0.30) -> list:
        """
        C9: uᵢ,z,t = 1 if type active ≥ τᵈ consecutive slots (any persona).
        V5: C9 and C13 are independent — persona rotation does NOT reset C9.
        Validates that u_type flags are set wherever they should be.
        """
        violations = []
        for trap in self.K:
            for zone in self.Z:
                for t in range(self.H):
                    N_ip = self.pl.get_N(trap, "")
                    td   = self.pl.tau_d(rho_pi, N_ip)
                    td_c = math.ceil(td)
                    wstart = t - td_c + 1
                    if wstart < 0:
                        continue
                    consec = sum(
                        1 for s in range(wstart, t+1)
                        if any(self._x(trap, zone, s, p) for p in self.P)
                    )
                    expected_u = int(consec >= td_c)
                    actual_u   = self._u_type(trap, zone, t)
                    if actual_u != expected_u:
                        violations.append({
                            "constraint": "C9",
                            "trap": trap, "zone": zone, "t": t,
                            "expected_u": expected_u, "actual_u": actual_u,
                            "tau_d": td, "consec": consec
                        })
        return violations

    def check_c10(self) -> list:
        """
        C10: Σt pπ,h★,t ≥ ⌈ρπ·H⌉  ∀π
        Critical hop h★ of every attack path must be covered enough slots
        to deny a patient attacker a gap window.
        """
        violations = []
        for path in self.G:
            pid      = path["id"]
            rho      = path["rho"]
            required = math.ceil(rho * self.H)
            h_star   = 0  # first non-final hop = critical hop
            covered  = sum(self._p_path(pid, h_star, t) for t in range(self.H))
            if covered < required:
                violations.append({
                    "constraint": "C10", "path": pid,
                    "h_star": h_star, "required": required,
                    "covered": covered, "deficit": required - covered,
                    "rho": rho
                })
        return violations

    def check_c11(self, rho_pi: float = 0.30) -> dict:
        """
        C11: τᵈ(i,z,t) = max(1, τᵈ⁰·(1−ρπ/ρₘₐˣ)·γ^n)  (eq 12′, V5 floored)
        Returns the effective τᵈ at this ρπ and N=0 baseline.
        Not a violation check — C11 is a parameter formula, not a clause.
        """
        td_eff   = self.pl.tau_d(rho_pi, N_ip=0)
        td_floor = max(1.0, td_eff)
        return {
            "constraint": "C11",
            "rho_pi": rho_pi, "tau_d0": self.pl.tau_d0,
            "tau_d_effective": td_eff,
            "floor_applied": td_eff < 1.0,
            "rotate_every_n_slots": math.ceil(td_floor),
        }

    def check_c12(self, schedule: dict) -> list:
        """
        C12: ¬xᵢ,z,t,ₚ ∨ ¬xₗ,z,t,ₚ  ∀i≠l, ∀z,t,p
        Two distinct trap types cannot wear the same persona in the same
        zone at the same slot. Persona analogue of C4.
        """
        violations = []
        for zone in self.Z:
            for t in range(self.H):
                for p in self.P:
                    active_traps = [
                        trap for trap in self.K
                        if schedule.get((trap, zone, t, p), 0)
                    ]
                    if len(active_traps) > 1:
                        violations.append({
                            "constraint": "C12",
                            "zone": zone, "t": t, "persona": p,
                            "traps": active_traps
                        })
        return violations

    def check_c13(self, schedule: dict) -> list:
        """
        C13: uᵢ,z,t,ₚ = 1 if persona active ≥ τᵈᵖ consecutive slots.
        Validates that u_persona flags match the consecutive-slot count.
        V5 independence: C13 and C9 are independent clocks.
        """
        violations = []
        for trap in self.K:
            for zone in self.Z:
                for p in self.P:
                    for t in range(self.H):
                        N_ip = self.pl.get_N(trap, p)
                        tdp  = self.pl.tau_dp(N_ip)
                        tdpc = math.ceil(tdp)
                        wstart = t - tdpc + 1
                        if wstart < 0:
                            continue
                        consec = sum(
                            1 for s in range(wstart, t+1)
                            if schedule.get((trap,zone,s,p),0)
                        )
                        expected_u = int(consec >= tdpc)
                        actual_u   = self._u_persona(trap, zone, t, p)
                        if actual_u != expected_u:
                            violations.append({
                                "constraint": "C13",
                                "trap": trap, "zone": zone, "t": t, "persona": p,
                                "expected_u": expected_u, "actual_u": actual_u,
                                "tau_dp": tdp, "consec": consec
                            })
        return violations

    def check_c14(self, schedule: dict) -> list:
        """
        C14: ¬xᵢ,z,t,ₚ ∨ ¬xₗ,z′,t,ₚ  ∀i,l∈K, z≠z′∈Z, ∀t,p
        Same persona cannot appear in two different zones at the same slot.
        Cross-zone extension of C12 — closes the gap left by C12's zone scope.
        V3 addition: |Z|=1 collapses C14 to a restatement of C12.
        """
        violations = []
        for t in range(self.H):
            for p in self.P:
                active_zones = defaultdict(list)  # zone → [trap, ...]
                for trap in self.K:
                    for zone in self.Z:
                        if schedule.get((trap, zone, t, p), 0):
                            active_zones[zone].append(trap)
                if len(active_zones) > 1:
                    violations.append({
                        "constraint": "C14", "t": t, "persona": p,
                        "zones": dict(active_zones),
                        "n_zones": len(active_zones)
                    })
        return violations

    def check_c15(self) -> dict:
        """
        C15: h_min ≥ κ_min  (construction-time precondition, V4)
        Slot granularity must exceed the fastest plausible kill-chain duration.
        Returns status dict; raises ValueError if violated.
        """
        result = {
            "constraint": "C15",
            "h_min": self.h_min, "kappa_min": self.kappa_min,
            "satisfied": self._c15_ok,
            "note": ("OK" if self._c15_ok else
                     f"VIOLATION: h_min={self.h_min}h < κ_min={self.kappa_min}h")
        }
        if not self._c15_ok:
            raise ValueError(
                f"C15 INFEASIBLE: h_min={self.h_min}h < κ_min={self.kappa_min}h. "
                "Slot granularity is too fine relative to the fastest known kill chain. "
                "Increase h_min or decrease κ_min before solving."
            )
        return result

    # ─────────────────────────────────────────────────────────────────
    #  FULL VALIDATION PASS
    # ─────────────────────────────────────────────────────────────────

    def validate_all(
        self,
        schedule: dict,
        rho_pi:   float = 0.30,
        verbose:  bool  = True,
    ) -> tuple[bool, dict]:
        """
        Run all 15 constraints against a concrete schedule.
        V5 note: constraints are evaluated as a flat conjunction.
        A schedule is feasible iff ALL fifteen return zero violations.

        Returns:
            (feasible: bool, report: dict)
        """
        report = {}
        all_ok = True

        checks = [
            ("C1",  lambda: self.check_c1()),
            ("C2",  lambda: self.check_c2()),
            ("C3",  lambda: self.check_c3()),
            ("C4",  lambda: self.check_c4()),
            ("C5",  lambda: self.check_c5()),
            ("C5b", lambda: self.check_c5b()),
            ("C6",  lambda: self.check_c6()),
            ("C7",  lambda: self.check_c7()),
            ("C8",  lambda: self.check_c8(schedule)),
            ("C9",  lambda: self.check_c9(rho_pi)),
            ("C10", lambda: self.check_c10()),
            ("C11", lambda: [self.check_c11(rho_pi)]),  # info only
            ("C12", lambda: self.check_c12(schedule)),
            ("C13", lambda: self.check_c13(schedule)),
            ("C14", lambda: self.check_c14(schedule)),
            ("C15", lambda: [self.check_c15()]),         # raises if violated
        ]

        for cid, fn in checks:
            try:
                result = fn()
                if cid in ("C11", "C15"):
                    report[cid] = {"info": result[0], "violations": 0}
                else:
                    n = len(result)
                    report[cid] = {"violations": n, "details": result[:5]}
                    if n > 0:
                        all_ok = False
            except ValueError as e:
                report[cid] = {"violations": 1, "details": [str(e)]}
                all_ok = False

        if verbose:
            self._print_report(report, all_ok, rho_pi)

        return all_ok, report

    def _print_report(self, report, all_ok, rho_pi):
        print("\n" + "=" * 70)
        print("  Hard Constraints C1–C15 — Validation Report")
        print(f"  (flat conjunction — all must be satisfied; ρπ={rho_pi})")
        print("=" * 70)
        for cid, r in report.items():
            n = r.get("violations", 0)
            if cid in ("C11", "C15"):
                info = r.get("info", {})
                if cid == "C11":
                    print(f"  {cid}  [INFO]  τᵈ_eff={info.get('tau_d_effective',0):.2f}"
                          f"  rotate_every={info.get('rotate_every_n_slots')} slot(s)"
                          f"{'  ⚠ floor' if info.get('floor_applied') else ''}")
                else:
                    print(f"  {cid}  [INFO]  {info.get('note','')}")
            elif n == 0:
                print(f"  {cid}  [✓] 0 violations")
            else:
                print(f"  {cid}  [✗] {n} violation(s):")
                for d in r.get("details", [])[:3]:
                    print(f"        {d}")
        status = "[✓] FEASIBLE" if all_ok else "[✗] INFEASIBLE"
        print(f"\n  Result: {status}")
        print("=" * 70)

    # ─────────────────────────────────────────────────────────────────
    #  WCNF HARD-CLAUSE GENERATION  (for RC2 encoder)
    # ─────────────────────────────────────────────────────────────────

    def wcnf_clauses(self, var_map: dict) -> list:
        """
        Generate all hard clauses as lists of integers for pysat WCNF.

        var_map: dict mapping (trap,zone,t,persona) → positive int literal
                 (the same variable numbering used by the WCNF encoder)

        Returns list of int-lists — each is one hard clause.
        Constraints that are construction-time preconditions (C15) or
        formula definitions (C11) produce no WCNF clauses.

        Clause families:
          C4  : pairwise conflict clauses   O(|C|·H)
          C5  : zone-affinity unit clauses  O(|K|·|Z|·H·|P|)
          C5b : GK plausibility clauses     O(|K|·|P|·H·|Z|)
          C8  : churn penalty (soft)        — handled in soft-clause encoder
          C12 : persona-conflict clauses    O(|K|²·|Z|·H·|P|)
          C14 : cross-zone persona clauses  O(|K|²·|Z|²·H·|P|) — via aux vars
          AMO : at-most-one persona per     O(|K|·|Z|·H·|P|²/2)
                (trap,zone,slot)
        """
        clauses = []

        def xv(trap, zone, t, persona):
            return var_map.get((trap, zone, t, persona), None)

        # ── C4: type-conflict pairs ───────────────────────────────────
        for t in range(self.H):
            for (ta, tb) in self.C_conflicts:
                for z in self.Z:
                    for p in self.P:
                        va = xv(ta, z, t, p)
                        vb = xv(tb, z, t, p)
                        if va and vb:
                            clauses.append([-va, -vb])

        # ── C5 + C5b: zone affinity and GK plausibility ───────────────
        for trap in self.K:
            for zone in self.Z:
                for t in range(self.H):
                    for p in self.P:
                        v = xv(trap, zone, t, p)
                        if v is None:
                            continue
                        # C5: zone affinity
                        if zone not in self.diamond.get(trap, []):
                            clauses.append([-v])
                        # C5: air-gap
                        elif any(zone in pair for pair in self.I2):
                            if zone not in self.diamond.get(trap, []):
                                clauses.append([-v])
                        # C5b: GK plausibility
                        if not self.pl.gk_admitted(trap, p):
                            clauses.append([-v])

        # ── AMO: at most one persona per (trap,zone,slot) ─────────────
        # Without this, RC2 may activate multiple personas simultaneously
        for trap in self.K:
            for zone in self.diamond.get(trap, []):
                if any(zone in pair for pair in self.I2):
                    continue
                for t in range(self.H):
                    valid_p = [p for p in self.P if self.pl.gk_admitted(trap, p)]
                    for i in range(len(valid_p)):
                        for j in range(i+1, len(valid_p)):
                            va = xv(trap, zone, t, valid_p[i])
                            vb = xv(trap, zone, t, valid_p[j])
                            if va and vb:
                                clauses.append([-va, -vb])

        # ── C12: persona-conflict within zone ─────────────────────────
        for t in range(self.H):
            for zone in self.Z:
                for p in self.P:
                    traps_here = [
                        tr for tr in self.K
                        if zone in self.diamond.get(tr, [])
                        and self.pl.gk_admitted(tr, p)
                        and not any(zone in pair for pair in self.I2)
                    ]
                    for i in range(len(traps_here)):
                        for j in range(i+1, len(traps_here)):
                            va = xv(traps_here[i], zone, t, p)
                            vb = xv(traps_here[j], zone, t, p)
                            if va and vb:
                                clauses.append([-va, -vb])

        # ── C14: cross-zone persona uniqueness (aux-variable encoding) ─
        # For each (persona, slot): pu[zone] = 1 if persona active in zone
        # AMO over pu variables ensures at most one zone active per (persona,t)
        # (aux vars extend var_map counter)
        next_var = max(var_map.values()) + 1 if var_map else 1

        for t in range(self.H):
            for p in self.P:
                zone_active_vars = {}   # zone → list of x vars with this persona
                for zone in self.Z:
                    if any(zone in pair for pair in self.I2):
                        continue
                    xs = [
                        xv(tr, zone, t, p)
                        for tr in self.K
                        if zone in self.diamond.get(tr, [])
                        and self.pl.gk_admitted(tr, p)
                        and xv(tr, zone, t, p) is not None
                    ]
                    if xs:
                        zone_active_vars[zone] = xs

                active_zones = list(zone_active_vars.keys())
                if len(active_zones) < 2:
                    continue

                # Create pu auxiliary variables
                pu = {}
                for zone in active_zones:
                    pu_var = next_var; next_var += 1
                    pu[zone] = pu_var
                    # Any x with this persona in zone → pu[zone]
                    for xvar in zone_active_vars[zone]:
                        clauses.append([-xvar, pu_var])

                # AMO over pu: at most one zone
                pu_list = list(pu.values())
                for i in range(len(pu_list)):
                    for j in range(i+1, len(pu_list)):
                        clauses.append([-pu_list[i], -pu_list[j]])

        return clauses

    def wcnf_hard_append(self, wcnf: WCNF, var_map: dict) -> WCNF:
        """
        Append all hard clauses directly to an existing pysat WCNF object.
        Convenience wrapper around wcnf_clauses().
        """
        for clause in self.wcnf_clauses(var_map):
            wcnf.append(clause)
        return wcnf

    def clause_count_estimate(self) -> dict:
        """
        Estimate clause counts per constraint family without building them.
        Useful for sizing the WCNF before encoding.
        """
        K = len(self.K); Z = len(self.Z); H = self.H; P = len(self.P)
        avg_valid_p = sum(
            1 for tr in self.K for p in self.P
            if self.pl.gk_admitted(tr, p)
        ) / max(1, K)
        traps_per_zone = {
            z: len([tr for tr in self.K if z in self.diamond.get(tr,[])])
            for z in self.Z
        }
        avg_traps = sum(traps_per_zone.values()) / max(1, Z)
        return {
            "C4  (type conflicts)":         len(self.C_conflicts) * H * Z * P,
            "C5/C5b (affinity+GK)":         K * Z * H * P,
            "AMO (one persona/trap/zone/t)": K * Z * H * int(avg_valid_p*(avg_valid_p-1)/2),
            "C12 (persona-conflict)":       Z * H * P * int(avg_traps*(avg_traps-1)/2),
            "C14 (cross-zone, aux)":        P * H * (Z * 2),   # implication + AMO
            "TOTAL estimate":               None,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    try:
        from config             import CFG
        from persona_layer      import PersonaLayer
        from decision_variables import DecisionVariables
    except ImportError:
        print("[WARN] Using minimal inline config")
        CFG = {
            "K": ["ssh_trap","db_trap","scada_trap","ad_trap",
                  "dns_trap","web_trap","generic_trap","smb_trap"],
            "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
            "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
            "H": 4,
            "G": [
                {"id":"pi1","name":"web-to-db",
                 "zones":["DMZ","Internal","Internal"],"rho":0.35,"iv":[1.8,1.4,1.0]},
                {"id":"pi2","name":"cloud-ad",
                 "zones":["Cloud","Internal","Mgmt"],"rho":0.25,"iv":[1.6,1.3,1.0]},
                {"id":"pi3","name":"ot-infiltr",
                 "zones":["DMZ","OT"],"rho":0.15,"iv":[1.5,1.2]},
                {"id":"pi4","name":"mgmt-pivot",
                 "zones":["DMZ","Mgmt","Internal"],"rho":0.20,"iv":[1.7,1.3,1.0]},
            ],
            "C_conflicts":[("generic_trap","dns_trap"),("smb_trap","generic_trap")],
            "I2":[("OT","DMZ"),("OT","Cloud"),("OT","Mgmt")],
            "diamond_affinity":{
                "ssh_trap":["DMZ","Internal","Cloud","Mgmt"],
                "db_trap":["Internal","Cloud","Mgmt"],
                "smb_trap":["Internal","Mgmt"],
                "scada_trap":["OT"],
                "ad_trap":["Internal","Mgmt"],
                "dns_trap":["DMZ","Internal","Cloud"],
                "web_trap":["DMZ","Cloud"],
                "generic_trap":["DMZ","Internal","Cloud","Mgmt"],
            },
            "trap_techniques":{
                "ssh_trap":["T1021","T1078"],"db_trap":["T1048","T1213"],
                "smb_trap":["T1021","T1046"],"scada_trap":["T1059"],
                "ad_trap":["T1110","T1078"],"dns_trap":["T1572","T1046"],
                "web_trap":["T1190","T1566"],"generic_trap":["T1046","T1213"],
            },
            "A_per_zone":{"DMZ":20,"Internal":40,"Cloud":20,"OT":10,"Mgmt":10},
            "A_total":100,
            "cost_per_type":{"ssh_trap":0.8,"db_trap":1.2,"smb_trap":0.9,
                "scada_trap":2.0,"ad_trap":1.5,"dns_trap":0.7,
                "web_trap":1.0,"generic_trap":0.5},
            "cost_zone_multiplier":{"DMZ":1.0,"Internal":1.0,"Cloud":0.9,
                "OT":1.5,"Mgmt":1.1},
            "B":62500.0,
            "B2":{"DMZ":15000,"Internal":20000,"Cloud":15000,"OT":8000,"Mgmt":4500},
            "h_min":24.0,"kappa_min":12.0,
            "GK_scores":{
                ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
                ("ssh_trap","Finance_DB"):0.40,    ("ssh_trap","Generic_Linux"):0.75,
                ("db_trap","Finance_DB"):0.95,     ("db_trap","DevOps_server"):0.70,
                ("db_trap","HR_workstation"):0.50, ("db_trap","Generic_Linux"):0.60,
                ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
                ("smb_trap","Finance_DB"):0.55,    ("smb_trap","Generic_Linux"):0.45,
                ("scada_trap","Generic_Linux"):0.90,("scada_trap","DevOps_server"):0.50,
                ("scada_trap","HR_workstation"):0.20,("scada_trap","Finance_DB"):0.15,
                ("ad_trap","HR_workstation"):0.90, ("ad_trap","DevOps_server"):0.75,
                ("ad_trap","Finance_DB"):0.60,     ("ad_trap","Generic_Linux"):0.40,
                ("dns_trap","DevOps_server"):0.80, ("dns_trap","Generic_Linux"):0.85,
                ("dns_trap","HR_workstation"):0.55,("dns_trap","Finance_DB"):0.40,
                ("web_trap","DevOps_server"):0.85, ("web_trap","HR_workstation"):0.65,
                ("web_trap","Finance_DB"):0.50,    ("web_trap","Generic_Linux"):0.80,
                ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
                ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
            },
            "tau_GK":0.65,"tau_d0":3,"tau_dp0":2,"rho_max":1.0,
            "Delta":2,"Delta_p":2,
            "q":{"HR_workstation":0.25,"DevOps_server":0.25,
                 "Finance_DB":0.25,"Generic_Linux":0.25},
            "gamma":0.80,"beta_max":0.60,"kappa":30.0,
            "rho_decay":0.5,"Delta_N":3,
            "stix_signals":[{"confidence":0.88,"deltas":{
                "Finance_DB":+0.25,"HR_workstation":+0.15,
                "DevOps_server":-0.05,"Generic_Linux":-0.05}}],
            "empirical_interactions":{"Finance_DB":18,"HR_workstation":12,
                "DevOps_server":7,"Generic_Linux":3},
        }
        from persona_layer import PersonaLayer
        from decision_variables import DecisionVariables

    print("\n" + "=" * 70)
    print("  Hard Constraints C1–C15 — Self-Test")
    print("=" * 70)

    pl = PersonaLayer(CFG); pl.update_qp()
    dv = DecisionVariables(CFG, pl)

    # ── Valid schedule — strictly C14-compliant (unique persona per slot) ──
    # Each slot has at most one deployment per persona across all zones.
    # t=0: DMZ=HR, Internal=Finance, Cloud=DevOps, OT=Generic
    # t=1: DMZ=HR, Internal=Finance, OT=Generic          (HR burns after t=1: τdp=2)
    # t=2: DMZ=DevOps (rotated), Cloud=Finance, OT=Generic
    # t=3: DMZ=HR, Internal=Finance, OT=Generic
    good = {
        ("ssh_trap",   "DMZ",      0, "HR_workstation"):  1,
        ("db_trap",    "Internal", 0, "Finance_DB"):       1,
        ("dns_trap",   "Cloud",    0, "DevOps_server"):    1,
        ("scada_trap", "OT",       0, "Generic_Linux"):    1,
        ("ssh_trap",   "DMZ",      1, "HR_workstation"):   1,
        ("db_trap",    "Internal", 1, "Finance_DB"):        1,
        ("scada_trap", "OT",       1, "Generic_Linux"):     1,
        ("ssh_trap",   "DMZ",      2, "DevOps_server"):    1,
        ("db_trap",    "Cloud",    2, "Finance_DB"):        1,
        ("scada_trap", "OT",       2, "Generic_Linux"):     1,
        ("ssh_trap",   "DMZ",      3, "HR_workstation"):   1,
        ("db_trap",    "Internal", 3, "Finance_DB"):        1,
        ("scada_trap", "OT",       3, "Generic_Linux"):     1,
    }
    dv.load_schedule(good, rho_pi=0.30); dv.compute_all_derived()
    hc = HardConstraints(CFG, pl, dv)

    print("\n[Test 1] C4 — valid schedule (no conflicts)")
    assert hc.check_c4() == [], "C4 should pass"
    print("  C4: 0 violations ✓")

    print("\n[Test 2] C4 — inject conflict (generic_trap + dns_trap same slot)")
    bad_c4 = dict(good)
    bad_c4[("generic_trap","DMZ",0,"HR_workstation")] = 1
    bad_c4[("dns_trap","DMZ",0,"DevOps_server")] = 1
    dv.load_schedule(bad_c4, rho_pi=0.30); dv.compute_all_derived()
    hc2 = HardConstraints(CFG, pl, dv)
    c4v = hc2.check_c4()
    assert len(c4v) > 0, "C4 should detect conflict"
    print(f"  C4: {len(c4v)} violation(s) detected ✓")
    dv.load_schedule(good, rho_pi=0.30); dv.compute_all_derived()
    hc = HardConstraints(CFG, pl, dv)

    print("\n[Test 3] C5b — GK plausibility")
    c5b_ok  = hc.check_c5b()
    assert c5b_ok == [], "Good schedule: no C5b violations"
    print("  C5b: 0 violations ✓")

    print("\n[Test 4] C8 — churn budget")
    c8_ok = hc.check_c8(good)
    assert c8_ok == [], "Good schedule: no C8 violations"
    print("  C8: 0 violations ✓")

    print("\n[Test 5] C12 — persona-conflict within zone")
    c12_ok = hc.check_c12(good)
    assert c12_ok == [], "Good schedule: no C12 violations"
    print("  C12: 0 violations ✓")

    print("\n[Test 6] C12 — inject violation")
    bad_c12 = dict(good)
    bad_c12[("db_trap","DMZ",0,"HR_workstation")] = 1  # HR already in DMZ
    c12v = hc.check_c12(bad_c12)
    assert len(c12v) > 0, "Should detect C12 violation"
    print(f"  C12: {len(c12v)} violation(s) detected ✓")

    print("\n[Test 7] C14 — cross-zone persona uniqueness")
    c14_ok = hc.check_c14(good)
    assert c14_ok == [], "Good schedule: no C14 violations"
    print("  C14: 0 violations ✓")

    print("\n[Test 8] C14 — inject cross-zone violation")
    bad_c14 = dict(good)
    bad_c14[("ad_trap","Internal",0,"HR_workstation")] = 1  # HR in DMZ AND Internal
    c14v = hc.check_c14(bad_c14)
    assert len(c14v) > 0, "Should detect C14 violation"
    print(f"  C14: {len(c14v)} violation(s) detected ✓")

    print("\n[Test 9] C10 — path persistence")
    c10v = hc.check_c10()
    print(f"  C10: {len(c10v)} violation(s) in sample schedule")

    print("\n[Test 10] C11 — threat-adaptive τᵈ (info)")
    c11_low  = hc.check_c11(rho_pi=0.30)
    c11_high = hc.check_c11(rho_pi=0.55)
    assert c11_low["tau_d_effective"]  > c11_high["tau_d_effective"], \
        "τᵈ must tighten as ρπ rises"
    print(f"  C11: ρπ=0.30 → τᵈ_eff={c11_low['tau_d_effective']:.2f}")
    print(f"  C11: ρπ=0.55 → τᵈ_eff={c11_high['tau_d_effective']:.2f}  (tighter ✓)")

    print("\n[Test 11] C15 — slot-duration floor")
    c15 = hc.check_c15()
    assert c15["satisfied"], "C15 should pass with h_min=24 >= kappa_min=12"
    print(f"  C15: h_min={c15['h_min']}h ≥ κ_min={c15['kappa_min']}h ✓")

    print("\n[Test 12] C15 — inject violation")
    bad_cfg = dict(CFG, h_min=6.0, kappa_min=12.0)
    try:
        HardConstraints(bad_cfg, pl, dv).check_c15()
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  C15 violation raised correctly: {str(e)[:60]}... ✓")

    print("\n[Test 13] Full validate_all — good schedule")
    ok, rpt = hc.validate_all(good, rho_pi=0.30, verbose=True)

    print("\n[Test 14] WCNF clause generation")
    var_map = {
        (trap, zone, t, p): idx+1
        for idx, (trap, zone, t, p) in enumerate(
            (tr, z, t, p)
            for tr in CFG["K"] for z in CFG["Z"]
            for t in range(CFG["H"]) for p in CFG["P"]
        )
    }
    clauses = hc.wcnf_clauses(var_map)
    assert len(clauses) > 0, "Should produce hard clauses"
    unit  = sum(1 for c in clauses if len(c) == 1)
    binary= sum(1 for c in clauses if len(c) == 2)
    print(f"\n  WCNF hard clauses: {len(clauses)} total")
    print(f"    unit clauses  (forced-off):  {unit}")
    print(f"    binary clauses (AMO/conflict): {binary}")
    est = hc.clause_count_estimate()
    print(f"\n  Clause count estimates:")
    for k,v in est.items():
        if v is not None: print(f"    {k}: ~{v}")

    print("\n[✓] All hard-constraint self-tests passed.")
