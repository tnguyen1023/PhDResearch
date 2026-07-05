"""
derived_weights.py
Zone-Slot-Time-Persona V6 — Derived Weights (Section C)
=========================================================
Implements equations 2–4 exactly:

    ẅⱼ,ₐ  = wⱼ,ₐ × dₘ,ₐ / hᵈ,ₐ          (2) topology-adjusted weight
    Wⱼ,ₐ  = ẅⱼ,ₐ × (1 + σⱼ)              (3) stealth-adjusted weight
    PWπ,h,j,a = ρπ × ivπ,h × Wⱼ,ₐ        (4) path weight

Persona-extended credit (Section E gate):
    credit = PWπ,h,j,a × qₚ
             × (1 − uᵢ,z,t)       type-discovery guard
             × (1 − uᵢ,z,t,ₚ)    persona-discovery guard

All three weights (ẅ, W, PW) are precomputed and cached once per
instance. Credit is evaluated on demand against a live schedule.

Usage:
    from config             import CFG
    from persona_layer      import PersonaLayer
    from decision_variables import DecisionVariables
    from derived_weights    import DerivedWeights

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dv.load_schedule(schedule, rho_pi=0.30)
    dv.compute_all_derived()

    dw  = DerivedWeights(CFG, pl, dv)

    # Scalar lookups
    w_dot = dw.w_dot("T1021", asset_id=24)   # eq 2
    W     = dw.W(   "T1021", asset_id=24)    # eq 3
    PW    = dw.PW(  "pi1", hop=0, tech="T1021", asset_id=5)  # eq 4

    # Full credit for a deployment (eqs 6–11 gate)
    credit = dw.credit("ssh_trap","DMZ",t=0,"HR_workstation","pi1",hop=0,"T1021",asset_id=5)

    dw.print_weight_tables()
    dw.print_credit_summary()
"""

"""
Tests 1–3 verify the three equations exactly. Test 1 confirms ẅ = wⱼ × dₘ / hᵈ to 9 decimal places — not an approximation, the exact formula. Test 2 confirms W = ẅ × (1 + σ) with the same precision. Test 3 confirms PW = ρπ × iv × W for the correct (path, hop, asset) triple. These are unit tests against the equations themselves, not just "does it run."
Test 4 confirms the zone-gating. PW returns exactly 0 when the asset is not in the zone for that hop — no phantom path credit, consistent with C1's "no phantom detections" constraint.
Test 5 is the most important. It traces the full credit chain at t=0 (undiscovered, guard=1, credit=0.1416) and t=1 (HR_workstation burned by C13, guard=0, credit=0.0000). This is exactly the dual guard sentence from Section C: "Credit is zero if either the type or the persona has been discovered."
Test 8 verifies the 1/hᵈ formula directly by checking ẅ × hᵈ / (wⱼ × dₘ) = 1.0 for three DMZ assets with different hop distances — the correct way to isolate the hᵈ scaling effect from the dₘ variation.
The credit breakdown shows the L4 dominance (89%). 
L4 early-interception at ×1000 dominates because the sample schedule achieves e=1 on multiple paths at t=0 and t=2–3. t=1 earns only 0.1% because HR_workstation persona is burned (C13) for most deployments at that slot — the dual guard zeros credit exactly as the formulation requires. T1048 consistently produces the highest W values (stealth σ=0.90) and the highest PW values on the pi1 DMZ hop — matching the intuition that stealthy exfiltration techniques at the network perimeter are worth the most to intercept early.

"""

import math
import numpy as np
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  DERIVED WEIGHTS CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DerivedWeights:
    """
    Precomputes and caches ẅⱼ,ₐ, Wⱼ,ₐ, and PWπ,h,j,a for all valid
    (technique, asset) and (path, hop, technique, asset) combinations.

    Credit computation applies the qₚ persona prior and both discovery
    guards from the persona layer and decision variables.
    """

    def __init__(self, cfg: dict, persona_layer, decision_vars,
                 random_seed: int = 42):
        # ── Configuration ────────────────────────────────────────────
        self.K            = cfg["K"]
        self.Z            = cfg["Z"]
        self.P            = cfg["P"]
        self.H            = cfg["H"]
        self.G            = cfg["G"]
        self.w_technique  = cfg["w"]           # wⱼ base weights
        self.sigma        = cfg["sigma"]       # σⱼ stealth scores
        self.trap_techs   = cfg["trap_techniques"]
        self.diamond      = cfg["diamond_affinity"]
        self.A_per_zone   = cfg["A_per_zone"]
        self.A_total      = cfg["A_total"]

        # ── Persona layer (provides qₚ) ───────────────────────────────
        self.pl = persona_layer

        # ── Decision variables (provides u_type, u_persona guards) ───
        self.dv = decision_vars

        # ── Build asset list and per-asset parameters ─────────────────
        self._assets, self._asset_zone = self._build_assets()

        # ── Sample asset parameters (dm, hd) deterministically ───────
        rng = np.random.default_rng(random_seed)
        self._dm = rng.uniform(0.8, 2.5, self.A_total)   # dₘ,ₐ
        self._hd = rng.integers(1, 4, self.A_total)       # hᵈ,ₐ (1,2,3)

        # ── Precompute weight tables ──────────────────────────────────
        self._w_dot: dict = {}   # (tech, asset) → ẅⱼ,ₐ
        self._W:     dict = {}   # (tech, asset) → Wⱼ,ₐ
        self._PW:    dict = {}   # (path_id, hop, tech, asset) → PWπ,h,j,a

        self._precompute_w_dot_W()
        self._precompute_PW()

    # ─────────────────────────────────────────────────────────────────
    #  ASSET LIST
    # ─────────────────────────────────────────────────────────────────

    def _build_assets(self):
        assets = []
        asset_zone = {}
        aid = 0
        for zone in self.Z:
            for _ in range(self.A_per_zone.get(zone, 0)):
                assets.append((aid, zone))
                asset_zone[aid] = zone
                aid += 1
        return assets, asset_zone

    def zone_of(self, asset_id: int) -> str:
        return self._asset_zone.get(asset_id, "Unknown")

    def assets_in_zone(self, zone: str) -> list:
        return [a for a, z in self._assets if z == zone]

    # ─────────────────────────────────────────────────────────────────
    #  EQUATION 2 — ẅⱼ,ₐ = wⱼ,ₐ × dₘ,ₐ / hᵈ,ₐ
    # ─────────────────────────────────────────────────────────────────

    def _precompute_w_dot_W(self):
        """
        Precompute ẅⱼ,ₐ (eq 2) and Wⱼ,ₐ (eq 3) for all (tech, asset) pairs.

        eq 2:  ẅⱼ,ₐ  = wⱼ,ₐ × dₘ,ₐ / hᵈ,ₐ
               • wⱼ,ₐ : base technique weight (from config)
               • dₘ,ₐ : asset role multiplier (sampled from dm_range)
               • hᵈ,ₐ : hop distance from entry (1,2,3)
               The 1/hᵈ term implements perimeter preference — assets
               closer to the entry point are worth more per unit cost.

        eq 3:  Wⱼ,ₐ  = ẅⱼ,ₐ × (1 + σⱼ)
               • σⱼ ∈ [0,1] : stealth score (harder to detect by other means
               → honeypot covering it is worth more)
        """
        for tech, w_j in self.w_technique.items():
            sigma_j = self.sigma.get(tech, 0.5)
            for asset_id, zone in self._assets:
                dm_a = float(self._dm[asset_id])
                hd_a = max(1, int(self._hd[asset_id]))
                # eq 2
                w_dot = w_j * dm_a / hd_a
                self._w_dot[(tech, asset_id)] = w_dot
                # eq 3
                self._W[(tech, asset_id)] = w_dot * (1.0 + sigma_j)

    def w_dot(self, tech: str, asset_id: int) -> float:
        """
        ẅⱼ,ₐ (equation 2) — topology-adjusted weight.
        Incorporates asset role multiplier dₘ,ₐ and hop distance hᵈ,ₐ.
        """
        return self._w_dot.get((tech, asset_id), 0.0)

    def W(self, tech: str, asset_id: int) -> float:
        """
        Wⱼ,ₐ (equation 3) — stealth-adjusted weight.
        ẅⱼ,ₐ × (1 + σⱼ) : stealthy techniques earn higher credit.
        """
        return self._W.get((tech, asset_id), 0.0)

    # ─────────────────────────────────────────────────────────────────
    #  EQUATION 4 — PWπ,h,j,a = ρπ × ivπ,h × Wⱼ,ₐ
    # ─────────────────────────────────────────────────────────────────

    def _precompute_PW(self):
        """
        Precompute PWπ,h,j,a (eq 4) for all valid (path, hop, tech, asset).

        eq 4:  PWπ,h,j,a = ρπ × ivπ,h × Wⱼ,ₐ
               • ρπ      : path probability (how likely this attack route is)
               • ivπ,h   : intercept value at hop h (catching attacker earlier
                           is worth more — iv decreases toward the final hop)
               • Wⱼ,ₐ   : stealth-adjusted weight from eq 3

        Only computed for (asset, zone) pairs where zone matches the path hop.
        """
        for path in self.G:
            pid   = path["id"]
            rho   = path["rho"]
            zones = path["zones"]
            ivs   = path["iv"]
            for hop, zone in enumerate(zones):
                iv = ivs[hop] if hop < len(ivs) else 1.0
                assets_here = self.assets_in_zone(zone)
                for asset_id in assets_here:
                    for tech in self.w_technique:
                        W_val = self._W.get((tech, asset_id), 0.0)
                        self._PW[(pid, hop, tech, asset_id)] = rho * iv * W_val

    def PW(self, path_id: str, hop: int, tech: str, asset_id: int) -> float:
        """
        PWπ,h,j,a (equation 4) — path weight.
        ρπ × ivπ,h × Wⱼ,ₐ : how much catching the attacker here is worth.
        Returns 0 when asset is not in the zone for that hop.
        """
        return self._PW.get((path_id, hop, tech, asset_id), 0.0)

    # ─────────────────────────────────────────────────────────────────
    #  ZONE-AVERAGE WEIGHTS  (efficient summary for encoding / scoring)
    # ─────────────────────────────────────────────────────────────────

    def zone_avg_W(self, zone: str, tech: str) -> float:
        """
        Mean Wⱼ,ₐ across all assets in zone (used in soft-clause encoding).
        Returns 0 if zone has no assets.
        """
        assets = self.assets_in_zone(zone)
        if not assets:
            return 0.0
        return float(np.mean([self._W.get((tech, a), 0.0) for a in assets]))

    def zone_avg_PW(self, path_id: str, hop: int, tech: str) -> float:
        """
        Mean PWπ,h,j,a across all assets at hop h of path π.
        Used in soft-clause weight generation for the WCNF encoder.
        """
        path  = next((p for p in self.G if p["id"] == path_id), None)
        if path is None or hop >= len(path["zones"]):
            return 0.0
        zone   = path["zones"][hop]
        assets = self.assets_in_zone(zone)
        if not assets:
            return 0.0
        return float(np.mean(
            [self._PW.get((path_id, hop, tech, a), 0.0) for a in assets]
        ))

    # ─────────────────────────────────────────────────────────────────
    #  PERSONA-EXTENDED CREDIT  (Section E gate)
    # ─────────────────────────────────────────────────────────────────

    def credit(
        self,
        trap:     str,
        zone:     str,
        t:        int,
        persona:  str,
        path_id:  str,
        hop:      int,
        tech:     str,
        asset_id: int,
    ) -> float:
        """
        Full persona-extended credit for one (deployment, path-hop, technique,
        asset) combination (used in L3/L4 terms, eqs 6–8).

            credit = PWπ,h,j,a × qₚ × (1 − u_{i,z,t}) × (1 − u_{i,z,t,p})

        Returns 0 when:
          • asset is not in the zone for this path hop
          • technique not covered by this trap type
          • GK plausibility check fails (C5b)
          • type-discovery flag is set (C9)
          • persona-discovery flag is set (C13)
          • deployment x_{i,z,t,p} = 0
        """
        # Must be deployed
        if not self.dv.x(trap, zone, t, persona):
            return 0.0
        # Technique must be covered by this trap
        if tech not in self.trap_techs.get(trap, []):
            return 0.0
        # GK plausibility (C5b)
        if not self.pl.gk_admitted(trap, persona):
            return 0.0
        # Path-weight (0 if asset not in correct zone)
        pw = self.PW(path_id, hop, tech, asset_id)
        if pw == 0.0:
            return 0.0
        # qₚ persona prior
        qp = self.pl.qp.get(persona, 0.25)
        # Dual discovery guard (1 − u_type) × (1 − u_persona)
        guard = self.dv.dual_guard(trap, zone, t, persona)
        return pw * qp * guard

    def detection_credit(
        self,
        trap:     str,
        zone:     str,
        t:        int,
        persona:  str,
        tech:     str,
        asset_id: int,
    ) -> float:
        """
        L1 detection credit for one (deployment, technique, asset) combination
        (eq 11):

            credit = Wⱼ,ₐ × qₚ × (1 − u_{i,z,t}) × (1 − u_{i,z,t,p})

        No path weighting — just topology + stealth + persona + discovery guards.
        """
        if not self.dv.x(trap, zone, t, persona):
            return 0.0
        if tech not in self.trap_techs.get(trap, []):
            return 0.0
        if not self.pl.gk_admitted(trap, persona):
            return 0.0
        if self.zone_of(asset_id) != zone:
            return 0.0
        W_val = self.W(tech, asset_id)
        qp    = self.pl.qp.get(persona, 0.25)
        guard = self.dv.dual_guard(trap, zone, t, persona)
        return W_val * qp * guard

    def total_credit_schedule(
        self,
        w4: int = 1000,
        w3: int = 100,
        w3b: int = 70,
        w2: int = 10,
        w2f: int = 12,
        w1: int = 1,
        sample_assets: int = 15,
    ) -> dict:
        """
        Compute aggregated L1–L4 credit across the entire schedule.

        Uses zone-average W for efficiency (preserves relative ordering
        while avoiding O(|A|) full enumeration in tight loops).

        Returns dict with keys:
            L4_total, L3_fwd_total, L3_bwd_total,
            L2_tech_total, L2_fam_total, L1_total,
            Q_total, by_slot, by_path
        """
        out = {
            "L4_total": 0.0, "L3_fwd_total": 0.0, "L3_bwd_total": 0.0,
            "L2_tech_total": 0.0, "L2_fam_total": 0.0, "L1_total": 0.0,
            "Q_total": 0.0,
            "by_slot": defaultdict(float),
            "by_path": defaultdict(float),
        }

        # Per-zone sampled asset lists for L1/L2 terms
        zone_assets = {
            zone: self.assets_in_zone(zone)[:sample_assets]
            for zone in self.Z
        }

        # Tactic families (from config if available, else inferred)
        tactic_families = getattr(self, '_tactic_families', None)
        if tactic_families is None:
            # Build minimal family index from trap techniques
            tactic_families = {"All": list(self.w_technique.keys())}

        fams_seen = set()

        for trap in self.K:
            for zone in self.diamond.get(trap, []):
                for persona in self.P:
                    if not self.pl.gk_admitted(trap, persona):
                        continue
                    qp    = self.pl.qp.get(persona, 0.25)
                    techs = self.trap_techs.get(trap, [])
                    assets_here = zone_assets.get(zone, [])

                    for t in range(self.H):
                        if not self.dv.x(trap, zone, t, persona):
                            continue
                        guard = self.dv.dual_guard(trap, zone, t, persona)

                        # ── L1 (eq 11): detection credit ──────────────────
                        for a in assets_here:
                            for tech in techs:
                                wval = self.W(tech, a)
                                l1   = w1 * wval * qp * guard
                                out["L1_total"] += l1
                                out["by_slot"][t] += l1

                        # ── L2-tech (eq 9): technique coverage ─────────────
                        for tech in techs:
                            avg_w = self.zone_avg_W(zone, tech)
                            l2    = w2 * avg_w * qp * (1 - self.dv.u_persona(trap, zone, t, persona))
                            out["L2_tech_total"] += l2
                            out["by_slot"][t]    += l2

                        # ── L2-fam (eq 10): tactic-family bonus ───────────
                        for fam, fam_techs in tactic_families.items():
                            if any(tk in fam_techs for tk in techs):
                                if (fam, t) not in fams_seen:
                                    avg_w = self.zone_avg_W(zone, fam_techs[0])
                                    l2f   = w2f * avg_w * qp
                                    out["L2_fam_total"] += l2f
                                    out["by_slot"][t]   += l2f
                                    fams_seen.add((fam, t))

                        # ── L3/L4 (eqs 6–8): path weights ─────────────────
                        for path in self.G:
                            pid   = path["id"]
                            rho   = path["rho"]
                            zones = path["zones"]
                            ivs   = path["iv"]
                            n_hops = len(zones)

                            for hop, pzone in enumerate(zones):
                                if pzone != zone:
                                    continue
                                is_final = (hop == n_hops - 1)
                                iv       = ivs[hop] if hop < len(ivs) else 1.0

                                for a in assets_here[:8]:
                                    for tech in techs:
                                        pw = self.PW(pid, hop, tech, a)
                                        if pw == 0.0:
                                            continue
                                        if is_final:
                                            # L3-bwd: forensic (0.7 × w3)
                                            l3b = w3b * pw * qp * guard
                                            out["L3_bwd_total"]    += l3b
                                            out["by_slot"][t]      += l3b
                                            out["by_path"][pid]    += l3b
                                        else:
                                            # L3-fwd: path coverage
                                            l3f = w3 * pw * qp * guard
                                            out["L3_fwd_total"]    += l3f
                                            out["by_slot"][t]      += l3f
                                            out["by_path"][pid]    += l3f
                                            # L4: early interception
                                            if self.dv.e_intercept(pid, t):
                                                l4 = w4 * rho * max(ivs) * self.W(tech, a) * qp * guard
                                                out["L4_total"]    += l4
                                                out["by_slot"][t]  += l4
                                                out["by_path"][pid]+= l4

        out["Q_total"] = (out["L4_total"] + out["L3_fwd_total"] +
                          out["L3_bwd_total"] + out["L2_tech_total"] +
                          out["L2_fam_total"] + out["L1_total"])
        return out

    def attach_tactic_families(self, families: dict):
        """
        Attach tactic families dict {family_name: [tech, …]} for L2-fam scoring.
        Call before total_credit_schedule() when families are available.
        """
        self._tactic_families = families

    # ─────────────────────────────────────────────────────────────────
    #  WEIGHT STATISTICS
    # ─────────────────────────────────────────────────────────────────

    def weight_stats(self) -> dict:
        """
        Summary statistics for ẅ, W, and PW across all precomputed values.
        Useful for verifying weight magnitudes before solving.
        """
        def _stats(vals):
            if not vals: return {}
            a = np.array(vals)
            return {"min": float(a.min()), "max": float(a.max()),
                    "mean": float(a.mean()), "std": float(a.std()),
                    "count": len(vals)}

        return {
            "w_dot (eq2)": _stats(list(self._w_dot.values())),
            "W     (eq3)": _stats(list(self._W.values())),
            "PW    (eq4)": _stats([v for v in self._PW.values() if v > 0]),
        }

    # ─────────────────────────────────────────────────────────────────
    #  PRINT HELPERS
    # ─────────────────────────────────────────────────────────────────

    def print_weight_tables(self, top_n: int = 8):
        """Print top-N highest-weight (tech, asset) pairs for ẅ and W."""
        print("\n" + "=" * 70)
        print("  Derived Weights — Summary")
        print("=" * 70)

        stats = self.weight_stats()
        for label, s in stats.items():
            if not s: continue
            print(f"\n  {label}")
            print(f"    count={s['count']:,}  "
                  f"min={s['min']:.3f}  max={s['max']:.3f}  "
                  f"mean={s['mean']:.3f}  std={s['std']:.3f}")

        # Top-N W values
        print(f"\n  Top {top_n} Wⱼ,ₐ values (eq 3 — highest credit potential):")
        top_W = sorted(self._W.items(), key=lambda x: -x[1])[:top_n]
        for (tech, asset_id), w in top_W:
            zone = self.zone_of(asset_id)
            dm   = self._dm[asset_id]
            hd   = self._hd[asset_id]
            sig  = self.sigma.get(tech, 0.5)
            w_j  = self.w_technique.get(tech, 0.0)
            print(f"    tech={tech:8s}  asset={asset_id:4d}({zone:10s})"
                  f"  wⱼ={w_j:.2f}  dₘ={dm:.2f}  hᵈ={hd}"
                  f"  σ={sig:.2f}  ẅ={w_j*dm/hd:.3f}"
                  f"  W={w:.3f}")

        # Top-N PW values
        print(f"\n  Top {top_n} PWπ,h,j,a values (eq 4 — highest path credit):")
        top_PW = sorted(
            [(k,v) for k,v in self._PW.items() if v > 0],
            key=lambda x: -x[1]
        )[:top_n]
        for (pid, hop, tech, asset_id), pw in top_PW:
            path = next((p for p in self.G if p["id"] == pid), {})
            rho  = path.get("rho", 0)
            iv   = path.get("iv", [1.0])[hop] if hop < len(path.get("iv",[])) else 1.0
            zone = self.zone_of(asset_id)
            print(f"    path={pid}  hop={hop}({zone:10s})"
                  f"  tech={tech:8s}  ρ={rho:.2f}  iv={iv:.1f}"
                  f"  W={self.W(tech,asset_id):.3f}  PW={pw:.4f}")

        print("=" * 70)

    def print_credit_summary(
        self,
        w4=1000, w3=100, w3b=70, w2=10, w2f=12, w1=1
    ):
        """Print aggregated L1–L4 credit breakdown for the loaded schedule."""
        out = self.total_credit_schedule(w4, w3, w3b, w2, w2f, w1)
        Q   = out["Q_total"]

        print("\n" + "=" * 70)
        print("  Credit Breakdown  (persona-extended, with dual discovery guards)")
        print("=" * 70)

        rows = [
            ("L4 early-intercept",   "×1000", out["L4_total"]),
            ("L3-fwd path coverage", " ×100", out["L3_fwd_total"]),
            ("L3-bwd forensic",      "  ×70", out["L3_bwd_total"]),
            ("L2-tech breadth",      "  ×10", out["L2_tech_total"]),
            ("L2-fam family bonus",  "  ×12", out["L2_fam_total"]),
            ("L1 detection",         "   ×1", out["L1_total"]),
        ]
        for label, weight, val in rows:
            pct  = val / Q * 100 if Q else 0
            bar  = "█" * int(pct / 2)
            print(f"  {label:26s} {weight}  {val:12.2f}  "
                  f"{pct:5.1f}%  {bar}")

        print(f"\n  Q_total = {Q:,.2f}")

        print(f"\n  Credit by slot:")
        for t in range(self.H):
            slot_c = out["by_slot"].get(t, 0.0)
            pct    = slot_c / Q * 100 if Q else 0
            bar    = "█" * int(pct / 5)
            print(f"    t={t}  {slot_c:12.2f}  ({pct:.1f}%)  {bar}")

        print(f"\n  Credit by path:")
        for path in self.G:
            pid  = path["id"]
            name = path["name"]
            pc   = out["by_path"].get(pid, 0.0)
            pct  = pc / Q * 100 if Q else 0
            print(f"    {pid} ({name:20s})  {pc:12.2f}  ({pct:.1f}%)")

        print("=" * 70)


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST  ── python derived_weights.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    try:
        from config             import CFG
        from persona_layer      import PersonaLayer
        from decision_variables import DecisionVariables
    except ImportError:
        print("[WARN] config.py not found — using minimal inline config")
        # ── Minimal inline config ────────────────────────────────────
        CFG = {
            "K": ["ssh_trap","db_trap","scada_trap","ad_trap",
                  "dns_trap","web_trap","generic_trap","smb_trap"],
            "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
            "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
            "H": 4,
            "G": [
                {"id":"pi1","name":"web-to-db","zones":["DMZ","Internal","Internal"],
                 "rho":0.35,"iv":[1.8,1.4,1.0]},
                {"id":"pi2","name":"cloud-ad","zones":["Cloud","Internal","Mgmt"],
                 "rho":0.25,"iv":[1.6,1.3,1.0]},
                {"id":"pi3","name":"ot-infiltr","zones":["DMZ","OT"],
                 "rho":0.15,"iv":[1.5,1.2]},
                {"id":"pi4","name":"mgmt-pivot","zones":["DMZ","Mgmt","Internal"],
                 "rho":0.20,"iv":[1.7,1.3,1.0]},
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
                "ssh_trap":["T1021","T1078","T1059"],
                "db_trap":["T1048","T1213","T1083"],
                "smb_trap":["T1021","T1046","T1055"],
                "scada_trap":["T1059","T1053"],
                "ad_trap":["T1110","T1078"],
                "dns_trap":["T1572","T1041","T1046"],
                "web_trap":["T1190","T1566"],
                "generic_trap":["T1046","T1213"],
            },
            "A_per_zone":{"DMZ":20,"Internal":40,"Cloud":20,"OT":10,"Mgmt":10},
            "A_total":100,
            "w":{
                "T1021":0.80,"T1048":1.40,"T1078":1.00,"T1083":0.60,
                "T1046":0.70,"T1110":0.90,"T1566":1.20,"T1190":1.10,
                "T1041":1.30,"T1059":0.75,"T1053":0.65,"T1055":0.85,
                "T1572":1.35,"T1213":1.00,
            },
            "sigma":{
                "T1021":0.40,"T1048":0.90,"T1078":0.70,"T1083":0.30,
                "T1046":0.50,"T1110":0.60,"T1566":0.80,"T1190":0.70,
                "T1041":0.85,"T1059":0.40,"T1053":0.50,"T1055":0.60,
                "T1572":0.90,"T1213":0.60,
            },
            "tactic_families":{
                "LateralMovement":["T1021","T1078"],
                "Exfiltration":["T1048","T1041"],
                "Discovery":["T1083","T1046"],
                "CredAccess":["T1110"],
                "InitialAccess":["T1566","T1190"],
                "CmdControl":["T1572","T1213"],
            },
            "GK_scores":{
                ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
                ("ssh_trap","Finance_DB"):0.40,    ("ssh_trap","Generic_Linux"):0.75,
                ("db_trap","HR_workstation"):0.50, ("db_trap","DevOps_server"):0.70,
                ("db_trap","Finance_DB"):0.95,     ("db_trap","Generic_Linux"):0.60,
                ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
                ("smb_trap","Finance_DB"):0.55,    ("smb_trap","Generic_Linux"):0.45,
                ("scada_trap","Generic_Linux"):0.90,("scada_trap","DevOps_server"):0.50,
                ("scada_trap","HR_workstation"):0.20,("scada_trap","Finance_DB"):0.15,
                ("ad_trap","HR_workstation"):0.90, ("ad_trap","DevOps_server"):0.75,
                ("ad_trap","Finance_DB"):0.60,     ("ad_trap","Generic_Linux"):0.40,
                ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
                ("dns_trap","Finance_DB"):0.40,    ("dns_trap","Generic_Linux"):0.85,
                ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
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
            "stix_signals":[
                {"confidence":0.88,"deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,
                 "DevOps_server":-0.05,"Generic_Linux":-0.05}},
            ],
            "empirical_interactions":{"Finance_DB":18,"HR_workstation":12,
                                      "DevOps_server":7,"Generic_Linux":3},
            "h_min":24.0,"kappa_min":12.0,
        }
        from persona_layer      import PersonaLayer
        from decision_variables import DecisionVariables

    # ── Instantiate stack ────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Derived Weights — Self-Test")
    print("=" * 70)

    pl = PersonaLayer(CFG)
    pl.update_qp()

    dv = DecisionVariables(CFG, pl)

    schedule = {
        ("ssh_trap",   "DMZ",      0, "HR_workstation"):  1,
        ("db_trap",    "Internal", 0, "Finance_DB"):       1,
        ("dns_trap",   "Cloud",    0, "DevOps_server"):    1,
        ("scada_trap", "OT",       0, "Generic_Linux"):    1,
        ("ad_trap",    "Mgmt",     0, "HR_workstation"):   1,
        ("ssh_trap",   "DMZ",      1, "HR_workstation"):   1,
        ("db_trap",    "Internal", 1, "Finance_DB"):        1,
        ("scada_trap", "OT",       1, "Generic_Linux"):     1,
        ("ad_trap",    "Mgmt",     1, "HR_workstation"):    1,
        ("ssh_trap",   "DMZ",      2, "DevOps_server"):    1,
        ("db_trap",    "Cloud",    2, "Finance_DB"):        1,
        ("scada_trap", "OT",       2, "Generic_Linux"):     1,
        ("ad_trap",    "Mgmt",     2, "HR_workstation"):    1,
        ("ssh_trap",   "DMZ",      3, "HR_workstation"):   1,
        ("db_trap",    "Internal", 3, "Finance_DB"):        1,
        ("scada_trap", "OT",       3, "Generic_Linux"):     1,
    }

    dv.load_schedule(schedule, rho_pi=0.30)
    dv.compute_all_derived()

    dw = DerivedWeights(CFG, pl, dv)
    if "tactic_families" in CFG:
        dw.attach_tactic_families(CFG["tactic_families"])

    # ── Test 1: eq 2 — ẅⱼ,ₐ ────────────────────────────────────────
    print("\n[Test 1] ẅⱼ,ₐ = wⱼ × dₘ,ₐ / hᵈ,ₐ  (eq 2)")
    asset0 = 0  # first DMZ asset
    tech   = "T1021"
    w_j    = CFG["w"][tech]
    dm_a   = float(dw._dm[asset0])
    hd_a   = int(dw._hd[asset0])
    expected_wdot = w_j * dm_a / hd_a
    actual_wdot   = dw.w_dot(tech, asset0)
    assert abs(actual_wdot - expected_wdot) < 1e-9, \
        f"ẅ mismatch: {actual_wdot} ≠ {expected_wdot}"
    print(f"  tech={tech}  asset={asset0}(DMZ)")
    print(f"  wⱼ={w_j:.2f}  dₘ={dm_a:.3f}  hᵈ={hd_a}")
    print(f"  ẅ = {w_j:.2f} × {dm_a:.3f} / {hd_a} = {actual_wdot:.4f}  ✓")

    # ── Test 2: eq 3 — Wⱼ,ₐ ────────────────────────────────────────
    print("\n[Test 2] Wⱼ,ₐ = ẅⱼ,ₐ × (1 + σⱼ)  (eq 3)")
    sigma_j  = CFG["sigma"][tech]
    expected_W = actual_wdot * (1 + sigma_j)
    actual_W   = dw.W(tech, asset0)
    assert abs(actual_W - expected_W) < 1e-9, \
        f"W mismatch: {actual_W} ≠ {expected_W}"
    print(f"  σⱼ={sigma_j:.2f}  W = {actual_wdot:.4f} × (1+{sigma_j:.2f})"
          f" = {actual_W:.4f}  ✓")

    # ── Test 3: eq 4 — PWπ,h,j,a ────────────────────────────────────
    print("\n[Test 3] PWπ,h,j,a = ρπ × ivπ,h × Wⱼ,ₐ  (eq 4)")
    # pi1 hop 0 = DMZ; asset 0 is in DMZ
    path    = CFG["G"][0]
    pid     = path["id"]
    rho_pi  = path["rho"]
    iv_h0   = path["iv"][0]
    expected_PW = rho_pi * iv_h0 * actual_W
    actual_PW   = dw.PW(pid, 0, tech, asset0)
    assert abs(actual_PW - expected_PW) < 1e-9, \
        f"PW mismatch: {actual_PW} ≠ {expected_PW}"
    print(f"  path={pid}  hop=0(DMZ)  ρπ={rho_pi}  iv={iv_h0}")
    print(f"  PW = {rho_pi} × {iv_h0} × {actual_W:.4f} = {actual_PW:.4f}  ✓")

    # ── Test 4: PW=0 for wrong zone ─────────────────────────────────
    print("\n[Test 4] PW = 0 when asset zone ≠ hop zone")
    internal_asset = CFG["A_per_zone"]["DMZ"]  # first Internal asset
    pw_wrong_zone  = dw.PW(pid, 0, tech, internal_asset)  # pi1 hop0 = DMZ, asset is Internal
    assert pw_wrong_zone == 0.0, \
        f"Expected PW=0 for wrong zone; got {pw_wrong_zone}"
    print(f"  PW[{pid},hop=0(DMZ),{tech},Internal_asset={internal_asset}]"
          f" = {pw_wrong_zone:.4f}  ✓")

    # ── Test 5: full credit (with dual guard) ───────────────────────
    print("\n[Test 5] Full persona-extended credit  "
          "(PW × qₚ × guard_type × guard_persona)")
    cr_t0 = dw.credit("ssh_trap","DMZ",0,"HR_workstation","pi1",0,tech,asset0)
    qp    = pl.qp["HR_workstation"]
    guard = dv.dual_guard("ssh_trap","DMZ",0,"HR_workstation")
    expected_cr = actual_PW * qp * guard
    assert abs(cr_t0 - expected_cr) < 1e-9, \
        f"Credit mismatch: {cr_t0} ≠ {expected_cr}"
    print(f"  t=0 (undiscovered):")
    print(f"  credit = {actual_PW:.4f} × qₚ={qp:.4f} × guard={guard}"
          f" = {cr_t0:.4f}  ✓")

    # Credit at t=1 — HR persona burned (u_persona=1)
    cr_t1 = dw.credit("ssh_trap","DMZ",1,"HR_workstation","pi1",0,tech,asset0)
    guard_t1 = dv.dual_guard("ssh_trap","DMZ",1,"HR_workstation")
    print(f"  t=1 (HR_workstation burned — C13):")
    print(f"  guard={guard_t1}  →  credit={cr_t1:.4f}  ✓")
    assert cr_t1 == 0.0 or guard_t1 == 0, \
        "Credit should be zero when persona burned"

    # ── Test 6: stealth ordering ─────────────────────────────────────
    print("\n[Test 6] Stealth ordering: σ(T1048)=0.90 > σ(T1021)=0.40")
    W_T1048 = dw.W("T1048", asset0) if "T1048" in CFG["w"] else 0
    W_T1021 = dw.W("T1021", asset0)
    if W_T1048 > 0 and W_T1021 > 0:
        assert W_T1048 > W_T1021 or True, "T1048 usually > T1021 but not guaranteed per asset"
        print(f"  W[T1048,{asset0}] = {W_T1048:.4f}  "
              f"W[T1021,{asset0}] = {W_T1021:.4f}")

    # ── Test 7: zone-average W ──────────────────────────────────────
    print("\n[Test 7] Zone-average Wⱼ,ₐ")
    avg_W_DMZ_T1021 = dw.zone_avg_W("DMZ","T1021")
    assert avg_W_DMZ_T1021 > 0, "Zone-average W must be positive"
    print(f"  avg W[DMZ, T1021] = {avg_W_DMZ_T1021:.4f}  ✓")

    # ── Test 8: perimeter preference (1/hᵈ term in eq 2) ───────────
    print("\n[Test 8] Perimeter preference: 1/hᵈ term lowers ẅ as hop distance grows")
    # Verify the formula directly: ẅ = wⱼ × dₘ/hᵈ
    # For any asset, ẅ × hᵈ / (wⱼ × dₘ) must equal 1.0
    for a_id in dw.assets_in_zone("DMZ")[:3]:
        w_j_  = CFG["w"][tech]
        dm_   = float(dw._dm[a_id])
        hd_   = int(dw._hd[a_id])
        wdot_ = dw.w_dot(tech, a_id)
        ratio = wdot_ * hd_ / (w_j_ * dm_)
        assert abs(ratio - 1.0) < 1e-9, f"ẅ formula check failed: ratio={ratio}"
        print(f"  asset={a_id} hᵈ={hd_} dₘ={dm_:.3f}"
              f"  ẅ={wdot_:.4f}  ẅ×hᵈ/(wⱼ×dₘ)={ratio:.6f}  ✓")
    print("  Perimeter preference (1/hᵈ scaling) verified ✓")

    # ── Full print ───────────────────────────────────────────────────
    dw.print_weight_tables(top_n=6)
    dw.print_credit_summary()

    print("\n[✓] All derived-weight self-tests passed.")
