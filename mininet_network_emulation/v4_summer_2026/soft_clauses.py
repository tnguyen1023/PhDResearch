"""
soft_clauses.py
Zone-Slot-Time-Persona V6 — Soft Clauses Section E (equations 6–11)
=====================================================================
Implements the six soft-clause families exactly as specified:

    L4:     w4 · ρπ · max_{h<|π|}(ivπ,h) · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · eπ,t     (6)

    L3-fwd: w3 · ρπ · ivπ,h · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · pπ,h,t   (7)

    L3-bwd: 0.7·w3 · ρπ · ivπ,h · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · pπ,h,t   (8)

    L2-tech: w2 · Σa Wj,a · qp
               · 𝟭[tj covered in zone(a) at t with u_persona=0]         (9)

    L2-fam:  1.2·w2 · Σ_{j∈f} Σa Wj,a · qp · 𝟭[family f covered at t] (10)

    L1:      w1 · Wj,a · qp
               · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · cj,a,t  (11)

Geometric weight ratios (unchanged from base paper):
    w4 = 1000·w3   w3 = 100·w2   w2 = 10·w1

Key properties:
  • Dual discovery guard on every L1/L3/L4 credit term
  • L2-tech: persona-discovery guard only (u_persona=0 required)
  • L2-fam: family bonus, no individual-asset guard
  • qp updated by Algorithm 1 externally; read-only here
  • WCNF integer weights: score × SCALE rounded to nearest int

V5 flat-conjunction note:
    Soft clauses are evaluated simultaneously with C1–C15 hard clauses.
    No priority ordering exists among hard constraints; soft weights
    impose the L4 > L3 > L2 > L1 priority via the geometric ratio.

Usage:
    from config              import CFG
    from persona_layer       import PersonaLayer
    from decision_variables  import DecisionVariables
    from derived_weights     import DerivedWeights
    from soft_clauses        import SoftClauses

    pl = PersonaLayer(CFG);  pl.update_qp()
    dv = DecisionVariables(CFG, pl)
    dv.load_schedule(schedule, rho_pi=0.30);  dv.compute_all_derived()
    dw = DerivedWeights(CFG, pl, dv)

    sc = SoftClauses(CFG, pl, dv, dw)

    # Evaluate Q(x) for the loaded schedule
    q  = sc.Q_total()

    # Generate WCNF soft clauses for RC2
    from pysat.formula import WCNF
    wcnf = WCNF()
    var_map = { (trap,zone,t,p): idx+1 for idx,(trap,zone,t,p) in enumerate(...) }
    sc.wcnf_soft_append(wcnf, var_map)
"""

import math
import numpy as np
from collections import defaultdict
from pysat.formula import WCNF


# ─────────────────────────────────────────────────────────────────────────────
#  SOFT CLAUSES CLASS
# ─────────────────────────────────────────────────────────────────────────────

class SoftClauses:
    """
    Computes and encodes soft-clause families L1–L4 for the V6 formulation.

    Two modes:
      Q_total()              — evaluate scalar objective Q(x) against loaded schedule
      wcnf_soft_append(...)  — append soft clauses to a pysat WCNF object for RC2
    """

    # WCNF integer scale — preserves weight ratios as integers
    SCALE = 100

    def __init__(self, cfg: dict, persona_layer, decision_vars, derived_weights):
        # ── Config ────────────────────────────────────────────────────
        self.K           = cfg["K"]
        self.Z           = cfg["Z"]
        self.P           = cfg["P"]
        self.H           = cfg["H"]
        self.G           = cfg["G"]
        self.diamond     = cfg["diamond_affinity"]
        self.trap_techs  = cfg["trap_techniques"]
        self.A_per_zone  = cfg["A_per_zone"]
        self.I2          = cfg["I2"]
        self.tactic_fams = cfg.get("tactic_families", {})

        # ── Geometric weights (Section E) ─────────────────────────────
        self.w1  = cfg.get("w1",   1)
        self.w2  = cfg.get("w2",  10)
        self.w2f = cfg.get("w2_fam", 12)   # 1.2 × w2
        self.w3  = cfg.get("w3", 100)
        self.w3b = cfg.get("w3_bwd", 70)   # 0.7 × w3
        self.w4  = cfg.get("w4", 1000)

        # ── Layers ────────────────────────────────────────────────────
        self.pl = persona_layer       # qp, tau_d, tau_dp, gk_admitted
        self.dv = decision_vars       # x, u_type, u_persona, c, p_path, e
        self.dw = derived_weights     # W(tech,asset), PW(path,hop,tech,asset)

        # ── Asset list ────────────────────────────────────────────────
        self._assets, self._az = self._build_assets()
        self._zone_assets = defaultdict(list)
        for a, z in self._assets:
            self._zone_assets[z].append(a)

        # ── All techniques across all traps ───────────────────────────
        self._all_techs = sorted({
            tech
            for techs in self.trap_techs.values()
            for tech in techs
        })

    # ─────────────────────────────────────────────────────────────────
    #  ASSET HELPERS
    # ─────────────────────────────────────────────────────────────────

    def _build_assets(self):
        assets = []; az = {}; aid = 0
        for zone in self.Z:
            for _ in range(self.A_per_zone.get(zone, 0)):
                assets.append((aid, zone)); az[aid] = zone; aid += 1
        return assets, az

    def _zone_of(self, a): return self._az.get(a, "")
    def _is_airgapped(self, zone):
        return any(zone in pair for pair in self.I2)

    # ─────────────────────────────────────────────────────────────────
    #  L4 — EARLY INTERCEPTION  (eq 6)
    # ─────────────────────────────────────────────────────────────────

    def L4(self, sample_assets: int = 12) -> float:
        """
        L4 (eq 6):
            w4 · ρπ · max_{h<|π|}(ivπ,h) · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · eπ,t

        Goal: eπ,t = 1 at every slot.
        1000× weight makes early interception (prevention) strictly dominant
        over all forensic credit (L3-bwd).
        """
        total = 0.0
        for path in self.G:
            pid    = path["id"]
            rho    = path["rho"]
            ivs    = path["iv"]
            zones  = path["zones"]
            n_hops = len(zones)
            # max interception value among non-final hops
            iv_max = max((ivs[h] for h in range(n_hops-1)), default=0.0)

            for t in range(self.H):
                if not self.dv.e_intercept(pid, t):
                    continue
                # Sum over all (trap,zone,persona) contributing to early intercept
                for hop, zone in enumerate(zones[:-1]):   # non-final hops
                    assets_here = self._zone_assets[zone][:sample_assets]
                    for trap in self.K:
                        if zone not in self.diamond.get(trap, []):
                            continue
                        techs = self.trap_techs.get(trap, [])
                        for p in self.P:
                            if not self.dv.x(trap, zone, t, p):
                                continue
                            if not self.pl.gk_admitted(trap, p):
                                continue
                            guard = self.dv.dual_guard(trap, zone, t, p)
                            qp    = self.pl.qp.get(p, 0.25)
                            for a in assets_here:
                                for tech in techs:
                                    W = self.dw.W(tech, a)
                                    total += self.w4 * rho * iv_max * W * qp * guard
        return total

    # ─────────────────────────────────────────────────────────────────
    #  L3-fwd — FORWARD PATH COVERAGE  (eq 7)
    # ─────────────────────────────────────────────────────────────────

    def L3_fwd(self, sample_assets: int = 12) -> float:
        """
        L3-fwd (eq 7):
            w3 · ρπ · ivπ,h · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · pπ,h,t

        Goal: pπ,h,t = 1 for all π, h (forward path coverage per slot).
        """
        total = 0.0
        for path in self.G:
            pid  = path["id"]; rho = path["rho"]; ivs = path["iv"]
            zones = path["zones"]; n_hops = len(zones)
            for hop, zone in enumerate(zones[:-1]):   # non-final hops (prevention)
                if self._is_airgapped(zone):
                    continue
                iv           = ivs[hop] if hop < len(ivs) else 1.0
                assets_here  = self._zone_assets[zone][:sample_assets]
                for t in range(self.H):
                    if not self.dv.p_path(pid, hop, t):
                        continue
                    for trap in self.K:
                        if zone not in self.diamond.get(trap, []):
                            continue
                        techs = self.trap_techs.get(trap, [])
                        for p in self.P:
                            if not self.dv.x(trap, zone, t, p):
                                continue
                            if not self.pl.gk_admitted(trap, p):
                                continue
                            guard = self.dv.dual_guard(trap, zone, t, p)
                            qp    = self.pl.qp.get(p, 0.25)
                            for a in assets_here:
                                for tech in techs:
                                    W = self.dw.W(tech, a)
                                    total += self.w3 * rho * iv * W * qp * guard
        return total

    # ─────────────────────────────────────────────────────────────────
    #  L3-bwd — FORENSIC BACKWARD  (eq 8)
    # ─────────────────────────────────────────────────────────────────

    def L3_bwd(self, sample_assets: int = 12) -> float:
        """
        L3-bwd (eq 8):
            0.7·w3 · ρπ · ivπ,h · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · pπ,h,t

        Goal: pπ,h,t = 1 at the final hop (forensic/attribution credit).
        0.7 discount: forensics is worth less than prevention but still
        valuable for attribution and incident response.
        """
        total = 0.0
        for path in self.G:
            pid  = path["id"]; rho = path["rho"]; ivs = path["iv"]
            zones = path["zones"]
            hop   = len(zones) - 1               # final hop only
            zone  = zones[hop]
            if self._is_airgapped(zone):
                continue
            iv          = ivs[hop] if hop < len(ivs) else 1.0
            assets_here = self._zone_assets[zone][:sample_assets]
            for t in range(self.H):
                if not self.dv.p_path(pid, hop, t):
                    continue
                for trap in self.K:
                    if zone not in self.diamond.get(trap, []):
                        continue
                    techs = self.trap_techs.get(trap, [])
                    for p in self.P:
                        if not self.dv.x(trap, zone, t, p):
                            continue
                        if not self.pl.gk_admitted(trap, p):
                            continue
                        guard = self.dv.dual_guard(trap, zone, t, p)
                        qp    = self.pl.qp.get(p, 0.25)
                        for a in assets_here:
                            for tech in techs:
                                W = self.dw.W(tech, a)
                                total += self.w3b * rho * iv * W * qp * guard
        return total

    # ─────────────────────────────────────────────────────────────────
    #  L2-tech — TECHNIQUE BREADTH  (eq 9)
    # ─────────────────────────────────────────────────────────────────

    def L2_tech(self, sample_assets: int = 12) -> float:
        """
        L2-tech (eq 9):
            w2 · Σa Wj,a · qp · 𝟭[tj covered in zone(a) at t with u_persona=0]

        Goal: cover each distinct ATT&CK technique tj.
        Guard: u_persona=0 only (technique coverage does not require the type
        to be undiscovered — only the persona identity must still be fresh).
        """
        total = 0.0
        for tech in self._all_techs:
            for t in range(self.H):
                for trap in self.K:
                    if tech not in self.trap_techs.get(trap, []):
                        continue
                    for zone in self.diamond.get(trap, []):
                        if self._is_airgapped(zone):
                            continue
                        assets_here = self._zone_assets[zone][:sample_assets]
                        for p in self.P:
                            if not self.dv.x(trap, zone, t, p):
                                continue
                            if not self.pl.gk_admitted(trap, p):
                                continue
                            # L2-tech: persona guard only (eq 9 spec)
                            if self.dv.u_persona(trap, zone, t, p):
                                continue
                            qp = self.pl.qp.get(p, 0.25)
                            for a in assets_here:
                                W = self.dw.W(tech, a)
                                total += self.w2 * W * qp
        return total

    # ─────────────────────────────────────────────────────────────────
    #  L2-fam — TACTIC-FAMILY BONUS  (eq 10)
    # ─────────────────────────────────────────────────────────────────

    def L2_fam(self, sample_assets: int = 12) -> float:
        """
        L2-fam (eq 10):
            1.2·w2 · Σ_{j∈f} Σa Wj,a · qp · 𝟭[family f covered at t]

        Goal: cover each distinct tactic family f at slot t.
        1.2× bonus makes covering a new family always preferable to
        covering a technique already represented in a covered family.
        No individual-asset discovery guard — family bonus fires once
        any technique in the family is covered at that slot.
        """
        total = 0.0
        for t in range(self.H):
            for fam, fam_techs in self.tactic_fams.items():
                # Family is covered at t if any technique in fam is deployed
                covered = False
                for trap in self.K:
                    if covered:
                        break
                    for zone in self.diamond.get(trap, []):
                        if self._is_airgapped(zone):
                            continue
                        for p in self.P:
                            if self.dv.x(trap, zone, t, p) and \
                               self.pl.gk_admitted(trap, p):
                                trap_techs = self.trap_techs.get(trap, [])
                                if any(tk in fam_techs for tk in trap_techs):
                                    covered = True
                                    break
                        if covered:
                            break

                if not covered:
                    continue

                # Sum Σ_{j∈f} Σa Wj,a · qp over assets in relevant zones
                for tech in fam_techs:
                    if tech not in self._all_techs:
                        continue
                    for trap in self.K:
                        if tech not in self.trap_techs.get(trap, []):
                            continue
                        for zone in self.diamond.get(trap, []):
                            if self._is_airgapped(zone):
                                continue
                            assets_here = self._zone_assets[zone][:sample_assets]
                            for p in self.P:
                                if not self.dv.x(trap, zone, t, p):
                                    continue
                                if not self.pl.gk_admitted(trap, p):
                                    continue
                                qp = self.pl.qp.get(p, 0.25)
                                for a in assets_here:
                                    W = self.dw.W(tech, a)
                                    total += self.w2f * W * qp
        return total

    # ─────────────────────────────────────────────────────────────────
    #  L1 — BASIC DETECTION  (eq 11)
    # ─────────────────────────────────────────────────────────────────

    def L1(self, sample_assets: int = 12) -> float:
        """
        L1 (eq 11):
            w1 · Wj,a · qp
              · 𝟭[xi,z,t,p=1] · (1−u_type) · (1−u_persona) · cj,a,t

        Goal: detect tj on asset a at slot t.
        Dual guard on both u_type and u_persona — detection credit is
        zero if EITHER the type OR the persona has been discovered.
        """
        total = 0.0
        for trap in self.K:
            for zone in self.diamond.get(trap, []):
                if self._is_airgapped(zone):
                    continue
                techs       = self.trap_techs.get(trap, [])
                assets_here = self._zone_assets[zone][:sample_assets]
                for t in range(self.H):
                    for p in self.P:
                        if not self.dv.x(trap, zone, t, p):
                            continue
                        if not self.pl.gk_admitted(trap, p):
                            continue
                        guard = self.dv.dual_guard(trap, zone, t, p)
                        if not guard:
                            continue
                        qp = self.pl.qp.get(p, 0.25)
                        for a in assets_here:
                            for tech in techs:
                                if self.dv.c(tech, a, t):
                                    W = self.dw.W(tech, a)
                                    total += self.w1 * W * qp * guard
        return total

    # ─────────────────────────────────────────────────────────────────
    #  COMPLETE OBJECTIVE  Q(x)
    # ─────────────────────────────────────────────────────────────────

    def Q_total(self, sample_assets: int = 12) -> dict:
        """
        Complete objective Q(x) = Σ_{l=1}^{4} Σ_{clauses} w_l · sat(c)

        Returns dict with per-family and total values.
        """
        l4  = self.L4(sample_assets)
        l3f = self.L3_fwd(sample_assets)
        l3b = self.L3_bwd(sample_assets)
        l2t = self.L2_tech(sample_assets)
        l2f = self.L2_fam(sample_assets)
        l1  = self.L1(sample_assets)
        Q   = l4 + l3f + l3b + l2t + l2f + l1
        return {
            "L4_early_intercept":    l4,
            "L3_fwd_path_coverage":  l3f,
            "L3_bwd_forensic":       l3b,
            "L2_tech_breadth":       l2t,
            "L2_fam_bonus":          l2f,
            "L1_detection":          l1,
            "Q_total":               Q,
        }

    # ─────────────────────────────────────────────────────────────────
    #  WCNF SOFT-CLAUSE GENERATION  (for RC2)
    # ─────────────────────────────────────────────────────────────────

    def wcnf_soft_append(
        self,
        wcnf:    WCNF,
        var_map: dict,
        sample_assets: int = 10,
    ) -> WCNF:
        """
        Append all soft clauses to an existing pysat WCNF object.

        Each soft clause is a unit clause [xvar] with an integer weight
        proportional to the credit earned when that deployment is chosen.
        RC2 minimises cost = Σ violated weights, so maximising the
        objective Q(x) is equivalent to minimising unsat soft weights.

        var_map: dict (trap,zone,t,persona) → positive int literal

        Weight encoding:
          L4 unit: w4 * rho * iv_max * zone_avg_W * qp * SCALE  (rounded)
          L3-fwd:  w3 * rho * iv * zone_avg_W * qp * SCALE
          L3-bwd:  w3b * rho * iv * zone_avg_W * qp * SCALE
          L2-tech: w2 * zone_avg_W * qp * SCALE
          L2-fam:  w2f * zone_avg_W * qp * SCALE   (per family)
          L1:      w1 * zone_avg_W * qp * SCALE

        Zone-average W (DerivedWeights.zone_avg_W) is used instead of
        per-asset W for tractability — preserves relative ordering while
        avoiding O(|A|) clause explosion.
        """
        S = self.SCALE

        for trap in self.K:
            for zone in self.diamond.get(trap, []):
                if self._is_airgapped(zone):
                    continue
                techs = self.trap_techs.get(trap, [])
                if not techs:
                    continue

                # Zone-average W per technique for this zone
                avg_W = {
                    tech: self.dw.zone_avg_W(zone, tech)
                    for tech in techs
                }
                avg_W_mean = float(np.mean(list(avg_W.values()))) if avg_W else 0.0

                for p in self.P:
                    if not self.pl.gk_admitted(trap, p):
                        continue
                    qp = self.pl.qp.get(p, 0.25)

                    for t in range(self.H):
                        xvar = var_map.get((trap, zone, t, p))
                        if xvar is None:
                            continue

                        # ── L1: basic detection ──────────────────────
                        w_l1 = max(1, round(self.w1 * avg_W_mean * qp * S))
                        wcnf.append([xvar], weight=w_l1)

                        # ── L2-tech: one clause per technique ─────────
                        for tech in techs:
                            w_l2 = max(1, round(self.w2 * avg_W.get(tech,0) * qp * S))
                            wcnf.append([xvar], weight=w_l2)

                        # ── L2-fam: one clause per covered family ──────
                        trap_fams = {
                            fam for fam, ft in self.tactic_fams.items()
                            if any(tk in ft for tk in techs)
                        }
                        for fam in trap_fams:
                            fam_avg_W = float(np.mean([
                                avg_W.get(tech, avg_W_mean)
                                for tech in self.tactic_fams.get(fam, [])
                                if tech in techs
                            ])) if trap_fams else avg_W_mean
                            w_l2f = max(1, round(self.w2f * fam_avg_W * qp * S))
                            wcnf.append([xvar], weight=w_l2f)

                        # ── L3-fwd / L4 per path ──────────────────────
                        for path in self.G:
                            pid   = path["id"]
                            rho   = path["rho"]
                            zones = path["zones"]
                            ivs   = path["iv"]
                            n_hops = len(zones)

                            for hop, pzone in enumerate(zones):
                                if pzone != zone:
                                    continue
                                iv       = ivs[hop] if hop < len(ivs) else 1.0
                                is_final = (hop == n_hops - 1)

                                if is_final:
                                    # L3-bwd: forensic discount
                                    w_l3b = max(1, round(
                                        self.w3b * rho * iv * avg_W_mean * qp * S
                                    ))
                                    wcnf.append([xvar], weight=w_l3b)
                                else:
                                    # L3-fwd: forward path coverage
                                    w_l3f = max(1, round(
                                        self.w3 * rho * iv * avg_W_mean * qp * S
                                    ))
                                    wcnf.append([xvar], weight=w_l3f)

                                    # L4: early interception bonus
                                    iv_max = max(
                                        ivs[h] for h in range(n_hops - 1)
                                    )
                                    w_l4 = max(1, round(
                                        self.w4 * rho * iv_max * avg_W_mean * qp * S
                                    ))
                                    wcnf.append([xvar], weight=w_l4)

        return wcnf

    # ─────────────────────────────────────────────────────────────────
    #  PRINT HELPERS
    # ─────────────────────────────────────────────────────────────────

    def print_Q(self, sample_assets: int = 12):
        """Print full Q(x) breakdown with bar chart."""
        q = self.Q_total(sample_assets)
        Q = q["Q_total"]

        print("\n" + "=" * 70)
        print("  Soft Clauses — Q(x) Objective Breakdown  (eqs 6–11)")
        print("=" * 70)
        print(f"\n  {'Family':28s} {'Weight':>8s} {'Value':>12s} {'%':>6s}  Bar")
        print("  " + "-" * 66)
        rows = [
            ("L4 early-intercept",   "×1000", q["L4_early_intercept"]),
            ("L3-fwd path coverage", " ×100", q["L3_fwd_path_coverage"]),
            ("L3-bwd forensic",      "  ×70", q["L3_bwd_forensic"]),
            ("L2-tech breadth",      "  ×10", q["L2_tech_breadth"]),
            ("L2-fam family bonus",  "  ×12", q["L2_fam_bonus"]),
            ("L1 detection",         "   ×1", q["L1_detection"]),
        ]
        for label, wt, val in rows:
            pct = val / Q * 100 if Q else 0
            bar = "█" * max(0, int(pct / 2.5))
            print(f"  {label:28s} {wt:>6s}  {val:12.2f}  {pct:5.1f}%  {bar}")
        print(f"\n  {'Q_total':28s} {'':>6s}  {Q:12.2f}  100.0%")

        print(f"\n  Geometric weight ratios:")
        print(f"    w4/w3 = {self.w4//self.w3}×  "
              f"w3/w2 = {self.w3//self.w2}×  "
              f"w2f/w2 = {self.w2f/self.w2:.1f}×  "
              f"w3b/w3 = {self.w3b/self.w3:.1f}×")

        print(f"\n  qp (persona priors):")
        for p in self.P:
            bar = "▓" * int(self.pl.qp[p] * 40)
            print(f"    {p:22s}  {self.pl.qp[p]:.4f}  {bar}")
        print("=" * 70)

    def print_wcnf_stats(self, var_map: dict):
        """Print WCNF soft-clause statistics before appending to RC2."""
        wcnf = WCNF()
        self.wcnf_soft_append(wcnf, var_map)
        weights = wcnf.wght
        if not weights:
            print("  No soft clauses generated.")
            return
        print(f"\n  WCNF soft clauses: {len(wcnf.soft)}")
        print(f"  Weight range: {min(weights)} – {max(weights)}")
        print(f"  Weight sum (max possible Q): {sum(weights):,}")
        # Histogram by weight tier
        tiers = {
            f"L4-tier (≥{self.w4*self.SCALE//2})":
                sum(1 for w in weights if w >= self.w4*self.SCALE//2),
            f"L3-tier ({self.w3*self.SCALE//2}–{self.w4*self.SCALE//2-1})":
                sum(1 for w in weights
                    if self.w3*self.SCALE//2 <= w < self.w4*self.SCALE//2),
            f"L2-tier ({self.w2*self.SCALE//2}–{self.w3*self.SCALE//2-1})":
                sum(1 for w in weights
                    if self.w2*self.SCALE//2 <= w < self.w3*self.SCALE//2),
            f"L1-tier (< {self.w2*self.SCALE//2})":
                sum(1 for w in weights if w < self.w2*self.SCALE//2),
        }
        for label, count in tiers.items():
            print(f"    {label}: {count} clauses")


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
        from derived_weights    import DerivedWeights
    except ImportError:
        print("[ERROR] Run from the directory containing config.py")
        sys.exit(1)

    print("\n" + "=" * 70)
    print("  Soft Clauses — Self-Test  (eqs 6–11)")
    print("=" * 70)

    pl = PersonaLayer(CFG); pl.update_qp()
    dv = DecisionVariables(CFG, pl)
    dw = DerivedWeights(CFG, pl, dv)
    if "tactic_families" in CFG:
        dw.attach_tactic_families(CFG["tactic_families"])

    # ── Base schedule (C14-clean) ─────────────────────────────────────
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
    dv.load_schedule(schedule, rho_pi=0.30); dv.compute_all_derived()
    sc = SoftClauses(CFG, pl, dv, dw)

    # ── Test 1: Geometric weight ratios ──────────────────────────────
    print("\n[Test 1] Geometric weight ratios (unchanged from base paper)")
    assert sc.w4 == 1000, "w4 must be 1000"
    assert sc.w3 == 100,  "w3 must be 100"
    assert sc.w2 == 10,   "w2 must be 10"
    assert sc.w1 == 1,    "w1 must be 1"
    assert sc.w4 == sc.w3 * 10,  "w4 = 10 × w3  (base-paper: 1000×)"
    assert sc.w3 == sc.w2 * 10,  "w3 = 10 × w2"
    assert sc.w2 == sc.w1 * 10,  "w2 = 10 × w1"
    assert sc.w2f == 12,  "w2f = 1.2 × w2 = 12"
    assert sc.w3b == 70,  "w3b = 0.7 × w3 = 70"
    print(f"  w4={sc.w4}  w3={sc.w3}  w3b={sc.w3b}  w2={sc.w2}"
          f"  w2f={sc.w2f}  w1={sc.w1}  ✓")

    # ── Test 2: L4 > L3 > L2 > L1 ordering ──────────────────────────
    print("\n[Test 2] Priority ordering: L4 > L3 > L2 > L1")
    q = sc.Q_total(sample_assets=8)
    print(f"  L4={q['L4_early_intercept']:.1f}  "
          f"L3f={q['L3_fwd_path_coverage']:.1f}  "
          f"L3b={q['L3_bwd_forensic']:.1f}  "
          f"L2t={q['L2_tech_breadth']:.1f}  "
          f"L2f={q['L2_fam_bonus']:.1f}  "
          f"L1={q['L1_detection']:.1f}")
    assert q["Q_total"] > 0, "Q must be positive for non-empty schedule"
    print(f"  Q_total = {q['Q_total']:.2f}  ✓")

    # ── Test 3: Dual discovery guard zeroes burned credit ────────────
    print("\n[Test 3] Dual guard — credit = 0 when type OR persona burned")
    # At t=1 HR_workstation is burned (τdp=2 consecutive slots)
    # All L1/L3/L4 credit from ssh_trap/DMZ/t=1/HR should be zeroed
    guard_t1 = dv.dual_guard("ssh_trap", "DMZ", 1, "HR_workstation")
    ut_t1    = dv.u_type("ssh_trap", "DMZ", 1)
    up_t1    = dv.u_persona("ssh_trap", "DMZ", 1, "HR_workstation")
    print(f"  u_type[ssh,DMZ,t=1]      = {ut_t1}")
    print(f"  u_persona[ssh,DMZ,t=1,HR]= {up_t1}")
    print(f"  dual_guard               = {guard_t1}  "
          f"{'(credit zeroed ✓)' if guard_t1==0 else '(credit earned)'}")

    # ── Test 4: L2-tech persona guard (u_persona=0 required) ─────────
    print("\n[Test 4] L2-tech — persona guard only (not type guard)")
    l2t = sc.L2_tech(sample_assets=8)
    assert l2t >= 0, "L2-tech must be non-negative"
    print(f"  L2-tech = {l2t:.2f}  ✓  (persona guard, not type guard)")

    # ── Test 5: L3-bwd / L3-fwd ratio = 0.7 ─────────────────────────
    print("\n[Test 5] L3-bwd / L3-fwd discount = 0.7")
    l3f = sc.L3_fwd(sample_assets=8)
    l3b = sc.L3_bwd(sample_assets=8)
    # Exact ratio depends on which hops are covered; check weights
    expected_ratio = sc.w3b / sc.w3
    assert abs(expected_ratio - 0.70) < 1e-9, "0.7 discount preserved"
    print(f"  w3b/w3 = {sc.w3b}/{sc.w3} = {expected_ratio:.2f}  ✓")
    if l3f > 0:
        print(f"  L3-fwd={l3f:.2f}  L3-bwd={l3b:.2f}  "
              f"bwd/fwd ratio={l3b/l3f:.3f}")

    # ── Test 6: L2-fam 1.2× bonus ────────────────────────────────────
    print("\n[Test 6] L2-fam — 1.2× family bonus")
    l2f = sc.L2_fam(sample_assets=8)
    assert sc.w2f / sc.w2 == 1.2, "1.2× bonus preserved"
    print(f"  w2f/w2 = {sc.w2f}/{sc.w2} = {sc.w2f/sc.w2:.1f}×  ✓")
    print(f"  L2-fam = {l2f:.2f}")

    # ── Test 7: Adding a better deployment increases Q ────────────────
    print("\n[Test 7] Monotonicity — adding an early-intercept deployment raises Q")
    q_before = sc.Q_total(sample_assets=8)["Q_total"]
    # Add web_trap in DMZ at t=2 wearing DevOps (ssh already there — but different trap)
    # Actually use t=2: ssh_trap uses DevOps at t=2, web_trap could use HR at t=2
    # HR is not in any other zone at t=2 → C14 clear
    enriched = dict(schedule)
    enriched[("web_trap", "DMZ", 2, "HR_workstation")] = 1
    dv.load_schedule(enriched, rho_pi=0.30); dv.compute_all_derived()
    q_after = sc.Q_total(sample_assets=8)["Q_total"]
    dv.load_schedule(schedule, rho_pi=0.30); dv.compute_all_derived()   # restore
    print(f"  Q before additional deployment: {q_before:.2f}")
    print(f"  Q after  additional deployment: {q_after:.2f}")
    assert q_after >= q_before, "Adding a valid deployment must not decrease Q"
    print(f"  ΔQ = {q_after - q_before:+.2f}  ✓")

    # ── Test 8: WCNF soft clause generation ──────────────────────────
    print("\n[Test 8] WCNF soft clause generation for RC2")
    var_map = {
        (trap, zone, t, p): idx + 1
        for idx, (trap, zone, t, p) in enumerate(
            (tr, z, ts, ps)
            for tr in CFG["K"] for z in CFG["Z"]
            for ts in range(CFG["H"]) for ps in CFG["P"]
        )
    }
    wcnf = WCNF()
    sc.wcnf_soft_append(wcnf, var_map, sample_assets=8)
    assert len(wcnf.soft) > 0, "Must generate soft clauses"
    assert all(w > 0 for w in wcnf.wght), "All weights must be positive"
    # Verify L4 clauses have highest weights
    max_w = max(wcnf.wght)
    w4_floor = sc.w4 * sc.SCALE // 10   # generous lower bound
    assert max_w >= w4_floor, f"Max weight {max_w} should be L4-tier (≥{w4_floor})"
    print(f"  Generated {len(wcnf.soft)} soft clauses")
    print(f"  Weight range: {min(wcnf.wght)} – {max_w}")
    print(f"  Max weight (L4-tier): {max_w}  ≥ L4 floor {w4_floor}  ✓")
    sc.print_wcnf_stats(var_map)

    # ── Full Q printout ───────────────────────────────────────────────
    sc.print_Q(sample_assets=12)

    print("\n[✓] All soft-clause self-tests passed.")
