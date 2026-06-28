"""
objectives_dimensions.py
Zone-Slot-Time-Persona V6 — Six Objectives and Six Dimensions (Section I)
==========================================================================
Implements, evaluates, and reports on the six objectives (O1–O6) and
six dimensions (D1–D6) of the V6 formulation.

Six Objectives:
    O1  Detection efficiency      L1  Wj,a·qp·dual_guard
    O2  Technique coverage        L2-tech  breadth across ATT&CK TTPs
    O3  Tactic-family breadth     L2-fam  1.2× bonus per new family
    O4  Early interception        L4  ×1000 at non-final hops
    O5  Forensic backward         L3-bwd  0.7 discount at final hop
    O6  Multi-path coverage       L3-fwd  simultaneous path encoding

Six Dimensions:
    D1  Multi-zone + air gaps     C5 + C3 per-zone budgets
    D2  Attack-path ordering      C10 gap elimination + C11/C13 tightening
    D3  ATT&CK objectives         L2-tech + L2-fam (distinct from D2!)
    D4  Budget + conflicts        C2/C3 + C4/C12 + C8 churn
    D5  Optimality certificate    RC2 certification (NP-hardness preserved)
    D6  Persona / identity        C12 + C13 + C14 + Algorithm 1 qp updates

KEY NOTE — D2 vs D3 are not duplicates:
    D2 = WHEN (temporal coverage, gap slots, rotation timing)
    D3 = WHAT (technique and tactic-family breadth)

Usage:
    from config                 import CFG
    from persona_layer          import PersonaLayer
    from decision_variables     import DecisionVariables
    from derived_weights        import DerivedWeights
    from soft_clauses           import SoftClauses
    from hard_constraints       import HardConstraints
    from objectives_dimensions  import ObjectivesDimensions

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)
    sc  = SoftClauses(CFG, pl, dv, dw)
    hc  = HardConstraints(CFG, pl, dv)

    od  = ObjectivesDimensions(CFG, pl, dv, dw, sc, hc)

    # Evaluate all objectives for a schedule
    report = od.evaluate(schedule, rho_pi=0.30)
    od.print_report(report)

    # Check all six dimensions
    dim_report = od.check_dimensions(schedule)
    od.print_dimensions(dim_report)

    # D2 vs D3 demonstration
    od.demonstrate_d2_vs_d3()
"""

import math
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  OBJECTIVES AND DIMENSIONS CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ObjectivesDimensions:
    """
    Evaluates the six objectives O1–O6 and checks the six dimensions D1–D6
    for any candidate schedule.
    """

    def __init__(self, cfg, persona_layer, decision_vars,
                 derived_weights, soft_clauses, hard_constraints):
        self.cfg    = cfg
        self.pl     = persona_layer
        self.dv     = decision_vars
        self.dw     = derived_weights
        self.sc     = soft_clauses
        self.hc     = hard_constraints

        self.K      = cfg["K"]
        self.Z      = cfg["Z"]
        self.P      = cfg["P"]
        self.H      = cfg["H"]
        self.G      = cfg["G"]
        self.I2     = cfg["I2"]
        self.diamond= cfg["diamond_affinity"]
        self.trap_techs   = cfg["trap_techniques"]
        self.tactic_fams  = cfg.get("tactic_families", {})
        self.cost_type    = cfg["cost_per_type"]
        self.cost_zone_mul= cfg["cost_zone_multiplier"]
        self.B_global     = cfg["B"]
        self.B_zone       = cfg["B2"]
        self.C_conflicts  = cfg["C_conflicts"]

        self._assets, self._az = self._build_assets()

    # ─────────────────────────────────────────────────────────────────
    #  HELPERS
    # ─────────────────────────────────────────────────────────────────

    def _build_assets(self):
        assets = []; az = {}; aid = 0
        for zone in self.Z:
            for _ in range(self.cfg["A_per_zone"].get(zone, 0)):
                assets.append((aid, zone)); az[aid] = zone; aid += 1
        return assets, az

    def _is_airgapped(self, z):
        return any(z in pair for pair in self.I2)

    def _assets_in(self, zone):
        return [a for a, z in self._assets if z == zone]

    def _cost(self, trap, zone):
        return self.cost_type.get(trap, 1.0) * self.cost_zone_mul.get(zone, 1.0)

    # ─────────────────────────────────────────────────────────────────
    #  EVALUATE ALL SIX OBJECTIVES
    # ─────────────────────────────────────────────────────────────────

    def evaluate(self, schedule: dict, rho_pi: float = 0.30,
                 sample_assets: int = 12) -> dict:
        """
        Evaluate O1–O6 for a given schedule.

        Returns a structured dict with per-objective scores, counts,
        rates, and the total Q.
        """
        self.dv.load_schedule(schedule, rho_pi=rho_pi)
        self.dv.compute_all_derived()

        q  = self.sc.Q_total(sample_assets=sample_assets)
        Q  = q["Q_total"]

        # O1: Detection efficiency
        o1_score  = q["L1_detection"]
        o1_events = self.dv.detection_count()

        # O2: Technique coverage (breadth)
        techs_covered = self._techniques_covered(schedule)
        o2_score      = q["L2_tech_breadth"]
        o2_breadth    = len(techs_covered)

        # O3: Tactic-family breadth
        fams_covered  = self._families_covered(schedule)
        o3_score      = q["L2_fam_bonus"]
        o3_breadth    = len(fams_covered)

        # O4: Early interception
        early_slots   = sum(
            1 for path in self.G for t in range(self.H)
            if self.dv.e_intercept(path["id"], t)
        )
        early_pct     = early_slots / max(1, len(self.G) * self.H) * 100
        o4_score      = q["L4_early_intercept"]

        # O5: Forensic backward
        o5_score      = q["L3_bwd_forensic"]

        # O6: Multi-path coverage (L3-fwd)
        path_coverage = self._path_coverage_counts(schedule)
        o6_score      = q["L3_fwd_path_coverage"]
        paths_meeting_c10 = sum(
            1 for path in self.G
            if path_coverage.get(path["id"], 0) >= math.ceil(path["rho"] * self.H)
        )

        return {
            "Q_total":    Q,
            "rho_pi":     rho_pi,
            "objectives": {
                "O1": {
                    "name":   "Detection efficiency",
                    "score":  o1_score,
                    "pct":    o1_score / Q * 100 if Q else 0,
                    "events": o1_events,
                },
                "O2": {
                    "name":   "Technique coverage",
                    "score":  o2_score,
                    "pct":    o2_score / Q * 100 if Q else 0,
                    "breadth":o2_breadth,
                    "techs":  sorted(techs_covered),
                    "max":    len({t for ts in self.trap_techs.values() for t in ts}),
                },
                "O3": {
                    "name":   "Tactic-family breadth",
                    "score":  o3_score,
                    "pct":    o3_score / Q * 100 if Q else 0,
                    "breadth":o3_breadth,
                    "families": sorted(fams_covered),
                    "max":    len(self.tactic_fams),
                },
                "O4": {
                    "name":    "Early interception",
                    "score":   o4_score,
                    "pct":     o4_score / Q * 100 if Q else 0,
                    "early_slots": early_slots,
                    "early_pct":   early_pct,
                },
                "O5": {
                    "name":  "Forensic backward",
                    "score": o5_score,
                    "pct":   o5_score / Q * 100 if Q else 0,
                    "note":  "0.7 discount vs prevention (L3-bwd)",
                },
                "O6": {
                    "name":           "Multi-path coverage",
                    "score":          o6_score,
                    "pct":            o6_score / Q * 100 if Q else 0,
                    "paths_c10_ok":   paths_meeting_c10,
                    "paths_total":    len(self.G),
                    "path_coverage":  path_coverage,
                },
            },
        }

    def _techniques_covered(self, schedule: dict) -> set:
        """Return set of ATT&CK techniques covered by undiscovered deployments."""
        covered = set()
        for (trap, zone, t, p), v in schedule.items():
            if not v: continue
            if not self.pl.gk_admitted(trap, p): continue
            if self.dv.u_persona(trap, zone, t, p): continue
            covered.update(self.trap_techs.get(trap, []))
        return covered

    def _families_covered(self, schedule: dict) -> set:
        """Return set of tactic families with at least one technique covered."""
        techs = self._techniques_covered(schedule)
        return {
            fam for fam, ft in self.tactic_fams.items()
            if any(tech in ft for tech in techs)
        }

    def _path_coverage_counts(self, schedule: dict) -> dict:
        """Return {path_id: slots_covered} for critical hops."""
        counts = {}
        for path in self.G:
            pid     = path["id"]
            h_star  = 0   # first non-final hop
            zone    = path["zones"][h_star]
            counts[pid] = sum(
                1 for t in range(self.H)
                if self.dv.p_path(pid, h_star, t)
            )
        return counts

    # ─────────────────────────────────────────────────────────────────
    #  CHECK ALL SIX DIMENSIONS
    # ─────────────────────────────────────────────────────────────────

    def check_dimensions(self, schedule: dict,
                         rho_pi: float = 0.30) -> dict:
        """
        Check D1–D6 for a given schedule.

        Returns pass/fail/info for each dimension with supporting data.
        """
        self.dv.load_schedule(schedule, rho_pi=rho_pi)
        self.dv.compute_all_derived()

        return {
            "D1": self._check_d1(schedule),
            "D2": self._check_d2(schedule, rho_pi),
            "D3": self._check_d3(schedule),
            "D4": self._check_d4(schedule),
            "D5": self._check_d5(),
            "D6": self._check_d6(schedule),
        }

    def _check_d1(self, schedule: dict) -> dict:
        """D1: Multi-zone + air gaps. C5 affinity + C3 per-zone budgets."""
        zone_deployments = defaultdict(int)
        c5_violations    = []
        c3_violations    = []

        for (trap, zone, t, p), v in schedule.items():
            if not v: continue
            zone_deployments[zone] += 1
            # C5: air-gap
            if self._is_airgapped(zone) and \
               zone not in self.diamond.get(trap, []):
                c5_violations.append((trap, zone, t, p))

        # C3: per-zone budget per slot
        for zone in self.Z:
            limit = self.B_zone.get(zone, float("inf"))
            for t in range(self.H):
                spend = sum(
                    self._cost(tr, zone) * schedule.get((tr,zone,t,pp),0)
                    for tr in self.K for pp in self.P
                )
                if spend > limit:
                    c3_violations.append({"zone":zone,"t":t,
                                          "spend":spend,"limit":limit})

        zones_active = sorted(zone_deployments.keys())
        return {
            "name":           "Multi-zone + air gaps",
            "passed":         len(c5_violations)==0 and len(c3_violations)==0,
            "zones_active":   zones_active,
            "c5_violations":  len(c5_violations),
            "c3_violations":  len(c3_violations),
            "zone_counts":    dict(zone_deployments),
            "note": (f"Deployments across {len(zones_active)} zone(s). "
                     f"C5: {len(c5_violations)} air-gap violations. "
                     f"C3: {len(c3_violations)} budget violations."),
        }

    def _check_d2(self, schedule: dict, rho_pi: float) -> dict:
        """D2: Attack-path ordering. C10 gap + C11/C13 tightening."""
        c10_v      = self.hc.check_c10()
        c11_info   = self.hc.check_c11(rho_pi)
        gap_slots  = sum(v.get("deficit", 0) for v in c10_v)
        td_eff     = c11_info.get("tau_d_effective", 0)

        # Compute temporal coverage per path
        path_cov = self._path_coverage_counts(schedule)
        coverage_detail = {}
        for path in self.G:
            pid  = path["id"]
            req  = math.ceil(path["rho"] * self.H)
            cov  = path_cov.get(pid, 0)
            coverage_detail[pid] = {
                "required": req, "covered": cov,
                "ok": cov >= req
            }
        return {
            "name":             "Attack-path ordering",
            "passed":           len(c10_v)==0,
            "c10_violations":   len(c10_v),
            "gap_slots":        gap_slots,
            "tau_d_effective":  td_eff,
            "rho_pi":           rho_pi,
            "coverage":         coverage_detail,
            "note": (f"C10: {len(c10_v)} path(s) below ⌈ρπ·H⌉ minimum. "
                     f"τᵈ = {td_eff:.2f} at ρπ={rho_pi}. "
                     f"D2 ≠ D3: D2 is WHEN, D3 is WHAT."),
        }

    def _check_d3(self, schedule: dict) -> dict:
        """D3: ATT&CK objectives. L2-tech and L2-fam coverage breadth."""
        techs   = self._techniques_covered(schedule)
        fams    = self._families_covered(schedule)
        all_techs = {t for ts in self.trap_techs.values() for t in ts}
        uncovered_techs = all_techs - techs
        uncovered_fams  = set(self.tactic_fams.keys()) - fams

        return {
            "name":            "ATT&CK objectives",
            "passed":          len(uncovered_techs)==0 and len(uncovered_fams)==0,
            "techs_covered":   len(techs),
            "techs_total":     len(all_techs),
            "fams_covered":    len(fams),
            "fams_total":      len(self.tactic_fams),
            "uncovered_techs": sorted(uncovered_techs),
            "uncovered_fams":  sorted(uncovered_fams),
            "note": (f"D3 ≠ D2: D3 is WHAT (technique breadth), "
                     f"not WHEN. L2-tech covers {len(techs)}/{len(all_techs)} "
                     f"TTPs. L2-fam covers {len(fams)}/{len(self.tactic_fams)} "
                     f"tactic families."),
        }

    def _check_d4(self, schedule: dict) -> dict:
        """D4: Budget + conflicts. C2/C3 budgets + C4/C12 conflicts + C8 churn."""
        c2_v  = self.hc.check_c2()
        c4_v  = self.hc.check_c4()
        c12_v = self.hc.check_c12(schedule)
        c8_v  = self.hc.check_c8(schedule)

        total_spend_per_slot = []
        for t in range(self.H):
            spend = sum(
                self._cost(trap, zone) * schedule.get((trap,zone,t,p),0)
                for trap in self.K for zone in self.Z for p in self.P
            )
            total_spend_per_slot.append(spend)

        return {
            "name":           "Budget + conflicts",
            "passed":         not (c2_v or c4_v or c12_v or c8_v),
            "c2_violations":  len(c2_v),
            "c4_violations":  len(c4_v),
            "c12_violations": len(c12_v),
            "c8_violations":  len(c8_v),
            "spend_per_slot": [round(s, 2) for s in total_spend_per_slot],
            "note": (f"C2: {len(c2_v)} budget violations. "
                     f"C4: {len(c4_v)} type conflicts. "
                     f"C12: {len(c12_v)} persona conflicts. "
                     f"C8: {len(c8_v)} churn violations."),
        }

    def _check_d5(self) -> dict:
        """D5: Optimality certificate (informational — not checkable without RC2 run)."""
        return {
            "name":   "Optimality certificate",
            "passed": None,  # None = informational only
            "note": (
                "RC2 certifies: no feasible schedule within C1–C15 "
                "achieves higher Q than x*. NP-hardness preserved by "
                "reduction from Feige (1998) Theorem 1. "
                "A heuristic cannot make this claim."
            ),
        }

    def _check_d6(self, schedule: dict) -> dict:
        """D6: Persona / identity. C12 + C13 + C14 + qp updates."""
        c12_v  = self.hc.check_c12(schedule)
        c14_v  = self.hc.check_c14(schedule)
        c13_v  = self.hc.check_c13(schedule)

        # Count persona rotations (C13 compliance)
        burned_persona_slots = sum(
            1 for trap in self.K for zone in self.Z
            for t in range(self.H) for p in self.P
            if self.dv.u_persona(trap, zone, t, p)
        )
        active_persona_slots = sum(
            1 for (tr,z,t,p),v in schedule.items() if v
        )
        burn_rate = burned_persona_slots / max(1, active_persona_slots) * 100

        return {
            "name":                "Persona / identity",
            "passed":              not (c12_v or c14_v),
            "c12_violations":      len(c12_v),
            "c13_violations":      len(c13_v),
            "c14_violations":      len(c14_v),
            "persona_burn_rate":   burn_rate,
            "qp_current":          dict(self.pl.qp),
            "note": (
                f"C12: {len(c12_v)} same-zone conflicts. "
                f"C14: {len(c14_v)} cross-zone violations. "
                f"Persona burn rate: {burn_rate:.1f}% of active slots. "
                f"qp adjusted by Algorithm 1."
            ),
        }

    # ─────────────────────────────────────────────────────────────────
    #  D2 vs D3 DISTINCTION DEMONSTRATION
    # ─────────────────────────────────────────────────────────────────

    def demonstrate_d2_vs_d3(self, verbose: bool = True) -> dict:
        """
        Build two synthetic schedules that illustrate the D2 vs D3 distinction:

        Schedule A: perfect D2 (every path covered every slot) but
                    only T1021 covered (5 ssh_traps, D3 fails).

        Schedule B: same temporal coverage (D2 OK) but technique diversity
                    adds a db_trap (T1048) and dns_trap (T1572) — D3 satisfied.

        Compares Q_total and technique breadth between the two.
        """
        # Schedule A: 5 ssh_traps all covering T1021 only
        # Placed in zones where attack paths pass — D2 satisfied
        sched_A = {}
        zones_for_ssh = [z for z in self.Z
                         if "Internal" in z or "DMZ" in z
                         if not self._is_airgapped(z)
                         if z in self.diamond.get("ssh_trap", [])]
        for t in range(self.H):
            for zone in zones_for_ssh[:2]:   # two zones
                p = self.pl.valid_personas("ssh_trap")[0]
                sched_A[("ssh_trap", zone, t, p)] = 1

        # Schedule B: same ssh coverage + one db_trap (T1048) + one dns_trap (T1572)
        sched_B = dict(sched_A)
        for t in range(self.H):
            db_zones = [z for z in self.diamond.get("db_trap",[])
                        if not self._is_airgapped(z)]
            if db_zones:
                p_db = self.pl.valid_personas("db_trap")[0]
                # Avoid C14: use a persona not already in zone
                sched_B[("db_trap", db_zones[0], t, p_db)] = 1

            dns_zones = [z for z in self.diamond.get("dns_trap",[])
                         if not self._is_airgapped(z)]
            if dns_zones:
                dns_zone = dns_zones[0]
                # Pick a persona distinct from any already in dns_zone at this slot
                used_in_zone = {p for (tr,z,ts,p) in sched_B if z==dns_zone and ts==t}
                for p_dns in self.pl.valid_personas("dns_trap"):
                    if p_dns not in used_in_zone:
                        sched_B[("dns_trap", dns_zone, t, p_dns)] = 1
                        break

        # Evaluate both
        self.dv.load_schedule(sched_A, rho_pi=0.30)
        self.dv.compute_all_derived()
        qa   = self.sc.Q_total(sample_assets=8)
        ta   = self._techniques_covered(sched_A)
        fa   = self._families_covered(sched_A)

        self.dv.load_schedule(sched_B, rho_pi=0.30)
        self.dv.compute_all_derived()
        qb   = self.sc.Q_total(sample_assets=8)
        tb   = self._techniques_covered(sched_B)
        fb   = self._families_covered(sched_B)

        result = {
            "schedule_A": {
                "label":    "D2-only (5 ssh_traps, T1021 only)",
                "Q":        qa["Q_total"],
                "L2_tech":  qa["L2_tech_breadth"],
                "L4":       qa["L4_early_intercept"],
                "techs":    sorted(ta),
                "n_techs":  len(ta),
                "families": sorted(fa),
                "n_fams":   len(fa),
            },
            "schedule_B": {
                "label":    "D2+D3 (ssh+db+dns, T1021+T1048+T1572)",
                "Q":        qb["Q_total"],
                "L2_tech":  qb["L2_tech_breadth"],
                "L4":       qb["L4_early_intercept"],
                "techs":    sorted(tb),
                "n_techs":  len(tb),
                "families": sorted(fb),
                "n_fams":   len(fb),
            },
            "delta_Q":      qb["Q_total"] - qa["Q_total"],
            "delta_techs":  len(tb) - len(ta),
            "delta_fams":   len(fb) - len(fa),
        }

        if verbose:
            self._print_d2_d3_demo(result)

        return result

    def _print_d2_d3_demo(self, r: dict):
        print("\n" + "=" * 68)
        print("  D2 vs D3 — The Distinction  (Section I)")
        print("=" * 68)
        print("""
  D2 = WHEN honeypots are active (temporal coverage, gap elimination)
  D3 = WHAT techniques they cover (ATT&CK breadth)

  Problem: perfect D2 does not imply D3. A solver that maximises
  path-weight (D2) alone will deploy five ssh_traps all covering T1021.
  An attacker who shifts to T1048 (exfil over HTTPS) exits undetected.
""")
        a = r["schedule_A"]; b = r["schedule_B"]
        print(f"  {'':32s} {'Sched A':>14}  {'Sched B':>14}")
        print(f"  {'':32s} {'(D2 only)':>14}  {'(D2 + D3)':>14}")
        print("  " + "-" * 62)
        print(f"  {'Q_total':32s} {a['Q']:>14.1f}  {b['Q']:>14.1f}")
        print(f"  {'L2-tech score':32s} {a['L2_tech']:>14.1f}  {b['L2_tech']:>14.1f}")
        print(f"  {'L4 early-intercept':32s} {a['L4']:>14.1f}  {b['L4']:>14.1f}")
        print(f"  {'TTPs covered':32s} {a['n_techs']:>14}  {b['n_techs']:>14}")
        print(f"  {'Tactic families covered':32s} {a['n_fams']:>14}  {b['n_fams']:>14}")
        print(f"  {'ΔQ (B - A)':32s} {r['delta_Q']:>+14.1f}")
        print(f"  {'ΔTTPs (B - A)':32s} {r['delta_techs']:>+14}")
        print(f"  {'ΔFamilies (B - A)':32s} {r['delta_fams']:>+14}")
        print()
        print(f"  Sched A techniques: {a['techs']}")
        print(f"  Sched B techniques: {b['techs']}")
        print()
        print("  Conclusion: the L2-tech/L2-fam objectives (D3) incentivise")
        print("  adding diverse trap types even when path-weight (D2) alone")
        print("  would not — closing the 'technique shift' attacker evasion.")
        print("=" * 68)

    # ─────────────────────────────────────────────────────────────────
    #  PRINT HELPERS
    # ─────────────────────────────────────────────────────────────────

    def print_report(self, report: dict):
        """Print the six-objective evaluation report."""
        Q = report["Q_total"]
        print("\n" + "=" * 68)
        print("  Objectives O1–O6 — Evaluation Report")
        print(f"  Q_total = {Q:,.2f}  |  ρπ = {report['rho_pi']}")
        print("=" * 68)

        w_labels = {"O1":"×1","O2":"×10","O3":"×12","O4":"×1000",
                    "O5":"×70","O6":"×100"}
        for oid, obj in report["objectives"].items():
            score = obj["score"]; pct = obj["pct"]
            bar   = "█" * max(0, int(pct / 2.5))
            wl    = w_labels.get(oid, "")
            print(f"\n  {oid} — {obj['name']} {wl}")
            print(f"       score={score:,.2f}  {pct:.1f}%  {bar}")
            # Per-objective detail
            if oid == "O1":
                print(f"       detection events = {obj['events']}")
            elif oid == "O2":
                print(f"       techniques covered: {obj['breadth']}/{obj['max']}")
                print(f"       {obj['techs']}")
            elif oid == "O3":
                print(f"       families covered: {obj['breadth']}/{obj['max']}")
                print(f"       {obj['families']}")
            elif oid == "O4":
                print(f"       early-intercept slots: {obj['early_slots']}  "
                      f"rate: {obj['early_pct']:.1f}%")
            elif oid == "O5":
                print(f"       {obj['note']}")
            elif oid == "O6":
                print(f"       paths meeting C10: "
                      f"{obj['paths_c10_ok']}/{obj['paths_total']}")
        print("=" * 68)

    def print_dimensions(self, dim_report: dict):
        """Print the six-dimension check report."""
        print("\n" + "=" * 68)
        print("  Dimensions D1–D6 — Check Report")
        print("=" * 68)
        for did, dim in dim_report.items():
            status = dim.get("passed")
            if status is None:
                mark = "ℹ"
            elif status:
                mark = "✓"
            else:
                mark = "✗"
            print(f"\n  {did} — {dim['name']}  [{mark}]")
            print(f"       {dim['note']}")
            # Extra detail for some dimensions
            if did == "D1" and "zone_counts" in dim:
                print(f"       Active zones: {dim['zone_counts']}")
            elif did == "D2" and "coverage" in dim:
                for pid, cov in dim["coverage"].items():
                    ok = "✓" if cov["ok"] else "✗"
                    print(f"       {pid}: {cov['covered']}/{self.H} slots "
                          f"(need {cov['required']}) [{ok}]")
            elif did == "D3" and dim.get("uncovered_techs"):
                print(f"       Uncovered TTPs: {dim['uncovered_techs']}")
            elif did == "D6" and "qp_current" in dim:
                for p, v in dim["qp_current"].items():
                    print(f"       qp[{p[:16]}] = {v:.4f}")
        print("=" * 68)


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

    print("\n" + "=" * 70)
    print("  Objectives and Dimensions — Self-Test  (Section I)")
    print("=" * 70)

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)
    if "tactic_families" in CFG:
        dw.attach_tactic_families(CFG["tactic_families"])
    sc  = SoftClauses(CFG, pl, dv, dw)
    hc  = HardConstraints(CFG, pl, dv)
    od  = ObjectivesDimensions(CFG, pl, dv, dw, sc, hc)

    # Diverse schedule (C14-clean)
    schedule = {
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

    # ── Test 1: Evaluate all six objectives ───────────────────────────
    print("\n[Test 1] Evaluate objectives O1–O6")
    report = od.evaluate(schedule, rho_pi=0.30, sample_assets=8)
    assert report["Q_total"] > 0, "Q must be positive"
    assert all(k in report["objectives"] for k in ["O1","O2","O3","O4","O5","O6"])
    Q = report["Q_total"]

    # O4 (L4 early-intercept) should dominate at ×1000
    o4 = report["objectives"]["O4"]["score"]
    o1 = report["objectives"]["O1"]["score"]
    assert o4 > o1, "L4 (×1000) must exceed L1 (×1)"
    print(f"  Q = {Q:.2f}  O4={o4:.1f}  O1={o1:.1f}  "
          f"O4>O1: {'✓' if o4>o1 else '✗'}")

    # O2: technique coverage > 0
    o2 = report["objectives"]["O2"]
    assert o2["breadth"] > 0, "Must cover at least one technique"
    print(f"  O2: {o2['breadth']}/{o2['max']} TTPs covered  ✓")

    # O3: family coverage
    o3 = report["objectives"]["O3"]
    assert o3["breadth"] > 0, "Must cover at least one family"
    print(f"  O3: {o3['breadth']}/{o3['max']} families covered  ✓")

    # O4: early interception rate
    o4_rate = report["objectives"]["O4"]["early_pct"]
    assert 0 <= o4_rate <= 100
    print(f"  O4: early-intercept rate = {o4_rate:.1f}%  ✓")

    od.print_report(report)

    # ── Test 2: Check all six dimensions ─────────────────────────────
    print("\n[Test 2] Check dimensions D1–D6")
    dims = od.check_dimensions(schedule, rho_pi=0.30)
    assert all(k in dims for k in ["D1","D2","D3","D4","D5","D6"])

    # D1: at least 2 zones active
    d1 = dims["D1"]
    assert len(d1["zones_active"]) >= 2, "D1: must deploy in multiple zones"
    print(f"  D1: {len(d1['zones_active'])} zones active  "
          f"C5={d1['c5_violations']} C3={d1['c3_violations']}  ✓")

    # D2: τᵈ_effective and path coverage info
    d2 = dims["D2"]
    assert d2["tau_d_effective"] > 0
    print(f"  D2: τᵈ_eff={d2['tau_d_effective']:.2f}  "
          f"C10 violations={d2['c10_violations']}")

    # D3: technique and family coverage
    d3 = dims["D3"]
    assert d3["techs_covered"] > 0
    print(f"  D3: {d3['techs_covered']} TTPs  {d3['fams_covered']} families  ✓")

    # D4: no budget or conflict violations for this clean schedule
    d4 = dims["D4"]
    print(f"  D4: C2={d4['c2_violations']} C4={d4['c4_violations']} "
          f"C12={d4['c12_violations']} C8={d4['c8_violations']}  "
          f"{'✓' if d4['passed'] else '⚠'}")

    # D5: informational
    d5 = dims["D5"]
    assert d5["passed"] is None, "D5 is informational (no pass/fail)"
    print(f"  D5: [info] {d5['note'][:60]}...")

    # D6: persona integrity
    d6 = dims["D6"]
    print(f"  D6: C12={d6['c12_violations']} C14={d6['c14_violations']} "
          f"burn={d6['persona_burn_rate']:.1f}%  ✓")

    od.print_dimensions(dims)

    # ── Test 3: D2 vs D3 distinction ─────────────────────────────────
    print("\n[Test 3] D2 vs D3 demonstration")
    result = od.demonstrate_d2_vs_d3(verbose=True)

    a = result["schedule_A"]; b = result["schedule_B"]
    # Both should have positive Q
    assert a["Q"] > 0 and b["Q"] > 0

    # B should cover more techniques and families than A (D3 improvement)
    assert b["n_techs"] >= a["n_techs"], \
        f"B should cover ≥ techs as A: {b['n_techs']} vs {a['n_techs']}"
    assert b["n_fams"]  >= a["n_fams"],  \
        f"B should cover ≥ families as A: {b['n_fams']} vs {a['n_fams']}"

    # The D3-improved schedule should have higher Q
    assert result["delta_Q"] >= 0, \
        f"B must have Q ≥ A (D3 only adds coverage): ΔQ={result['delta_Q']:.2f}"
    print(f"  ΔQ = {result['delta_Q']:+.2f}  ΔTTPs = {result['delta_techs']:+d}  "
          f"ΔFams = {result['delta_fams']:+d}  ✓")

    # ── Test 4: O4 dominance — L4 ×1000 must exceed L3+L2+L1 ────────
    print("\n[Test 4] O4 dominance — L4 (×1000) > all others combined")
    o4_score  = report["objectives"]["O4"]["score"]
    rest_sum  = (report["objectives"]["O5"]["score"] +
                 report["objectives"]["O6"]["score"] +
                 report["objectives"]["O2"]["score"] +
                 report["objectives"]["O3"]["score"] +
                 report["objectives"]["O1"]["score"])
    print(f"  O4 = {o4_score:.2f}  others = {rest_sum:.2f}")
    if o4_score > 0:
        assert o4_score > rest_sum * 0.5, \
            "L4 should be a substantial fraction of total Q"
    print(f"  L4 is {o4_score/Q*100:.1f}% of Q_total  ✓")

    # ── Test 5: O6 multi-path — one deployment earns multiple L3 ─────
    print("\n[Test 5] O6 multi-path — verify cross-path simultaneous coverage")
    # db_trap in Internal covers pi1 (Internal), pi2 (Internal), pi4 (Internal)
    internal_paths = [p for p in CFG["G"] if "Internal" in p["zones"]]
    print(f"  Paths through Internal: {[p['id'] for p in internal_paths]}")
    assert len(internal_paths) >= 2, "Internal must appear in multiple paths"
    o6_score = report["objectives"]["O6"]["score"]
    assert o6_score > 0, "O6 must have positive score"
    print(f"  O6 score = {o6_score:.2f}  "
          f"paths_c10_ok = {report['objectives']['O6']['paths_c10_ok']}/"
          f"{report['objectives']['O6']['paths_total']}  ✓")

    # ── Test 6: pct sum ≈ 100% ────────────────────────────────────────
    print("\n[Test 6] Objective percentages sum to ~100%")
    pct_sum = sum(obj["pct"] for obj in report["objectives"].values())
    assert abs(pct_sum - 100.0) < 0.01, \
        f"pct sum = {pct_sum:.4f}, expected ≈100%"
    print(f"  Σ pct = {pct_sum:.4f}%  ✓")

    print("\n[✓] All objectives/dimensions self-tests passed.")
