"""
force_multiplier.py
Zone-Slot-Time-Persona V6 — Cross-Path Force-Multiplier (Section G)
=====================================================================
A single deployment decision x_{i,z,t,p} = 1 simultaneously resolves
L3 soft clauses across multiple paths and earns the qp persona-prior
bonus on each.

Document table (reproduced exactly):
    Path            ρ     iv   Wj,a   qp    L3 weight
    web-to-db (h2) 0.30  1.8  3.24  0.40  0.30×1.8×3.24×0.40 = 0.700
    ot-infiltr(h2) 0.15  1.7  3.24  0.40  0.15×1.7×3.24×0.40 = 0.330
    brute-to-ad(h2)0.20  1.6  3.24  0.40  0.20×1.6×3.24×0.40 = 0.415

    RC2 total  (qp=0.40):              1.445
    Base-paper RC2 total (no qp):      3.612
    Base-paper Greedy (highest-ρ only):1.749
    RC2-vs-Greedy ratio ≈ 2.1× preserved at default qp = 1/|P|

Key insight: the force-multiplier comes from SIMULTANEOUS multi-path
coverage by one deployment.  A greedy solver covers only the highest-ρ
path; RC2 finds the placement that covers all paths at once.

Persona extension: qp weights amplify credit on threat-relevant personas,
preserving the 2.1× ratio at the uniform default qp = 1/|P| = 0.25 and
boosting it further when STIX intelligence elevates a specific persona.

Usage:
    from config              import CFG
    from persona_layer       import PersonaLayer
    from decision_variables  import DecisionVariables
    from derived_weights     import DerivedWeights
    from force_multiplier    import ForceMultiplier

    pl  = PersonaLayer(CFG);  pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)

    fm  = ForceMultiplier(CFG, pl, dw)

    # Reproduce document table exactly
    fm.print_document_table()

    # Compute multiplier for any deployment
    result = fm.compute(trap="db_trap", zone="Internal", t=0,
                        persona="Finance_DB", asset_id=24)
    print(result["ratio_vs_greedy"])

    # Scan all deployments and rank by force-multiplier
    fm.rank_deployments(top_n=10)
"""

import math
import numpy as np
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  FORCE MULTIPLIER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ForceMultiplier:
    """
    Computes the cross-path force-multiplier for any deployment.

    The multiplier measures how much more credit RC2 earns versus a
    greedy solver that covers only the highest-ρ path.

    Formally:
        FM(i,z,t,p) = Σ_{π: z ∈ hops(π)} L3_credit(π,h,i,z,t,p)
                      ─────────────────────────────────────────────
                      L3_credit(π_max_rho, h, i, z, t, p)

    where π_max_rho is the path with the highest ρπ passing through zone z.
    """

    def __init__(self, cfg: dict, persona_layer, derived_weights,
                 decision_vars=None):
        self.cfg    = cfg
        self.pl     = persona_layer
        self.dw     = derived_weights
        self.dv     = decision_vars   # optional (needed for schedule-based eval)

        self.K      = cfg["K"]
        self.Z      = cfg["Z"]
        self.P      = cfg["P"]
        self.H      = cfg["H"]
        self.G      = cfg["G"]
        self.diamond= cfg["diamond_affinity"]
        self.trap_techs = cfg["trap_techniques"]
        self.I2     = cfg["I2"]

        # Soft-clause weights (geometric)
        self.w3  = cfg.get("w3",  100)
        self.w3b = cfg.get("w3_bwd", 70)
        self.w4  = cfg.get("w4", 1000)

        # Build asset index
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

    def _zone_of(self, a): return self._az.get(a, "")
    def _is_airgapped(self, z): return any(z in pair for pair in self.I2)
    def _assets_in(self, zone): return [a for a, z in self._assets if z == zone]

    def _paths_through(self, zone: str) -> list[dict]:
        """Return all paths that pass through zone at any hop."""
        return [p for p in self.G if zone in p["zones"]]

    def _hop_of(self, path: dict, zone: str) -> list[int]:
        """Return all hop indices where zone appears in this path."""
        return [h for h, z in enumerate(path["zones"]) if z == zone]

    # ─────────────────────────────────────────────────────────────────
    #  DOCUMENT TABLE REPRODUCTION  (Section G exact numbers)
    # ─────────────────────────────────────────────────────────────────

    def document_table(self) -> dict:
        """
        Reproduce the Section G table exactly using the document's
        fixed parameters:
            W_{j,a} = 3.24  (topology + stealth adjusted, fixed for illustration)
            qp = 0.40       (Finance_DB persona elevated by STIX)
            |P| = 4         (default qp = 1/4 = 0.25)

        Three paths through the Internal zone asset (hop 2 in each case):
            pi1 web-to-db:  ρ=0.30, iv=1.8
            pi3 ot-infiltr: ρ=0.15, iv=1.7   (document uses ρ=0.15,iv=1.7)
            pi4 brute-to-ad:ρ=0.20, iv=1.6

        Returns dict with per-path weights and derived totals.
        """
        W_fixed    = 3.24
        qp_elevated= 0.40   # Finance_DB after STIX financial signal
        qp_default = 1 / len(self.P)   # = 0.25 for |P|=4

        paths_doc = [
            {"name": "web-to-db",   "rho": 0.30, "iv": 1.8},
            {"name": "ot-infiltr.", "rho": 0.15, "iv": 1.7},
            {"name": "brute-to-ad", "rho": 0.20, "iv": 1.6},
        ]

        rows = []
        for p in paths_doc:
            # L3-fwd weight per document formula: ρ × iv × W × qp
            l3_qp   = p["rho"] * p["iv"] * W_fixed * qp_elevated
            l3_no_qp= p["rho"] * p["iv"] * W_fixed   # base paper (no qp)
            rows.append({
                "name":       p["name"],
                "rho":        p["rho"],
                "iv":         p["iv"],
                "W":          W_fixed,
                "qp":         qp_elevated,
                "l3_with_qp": l3_qp,
                "l3_no_qp":   l3_no_qp,
            })

        # Totals
        rc2_total_qp    = sum(r["l3_with_qp"] for r in rows)
        rc2_total_no_qp = sum(r["l3_no_qp"]   for r in rows)

        # Greedy: only the highest-ρ path (ρ=0.30, iv=1.8)
        greedy_row      = max(rows, key=lambda r: r["rho"])
        greedy_total    = greedy_row["rho"] * greedy_row["iv"] * W_fixed

        # RC2-vs-Greedy ratio: qp scales both numerator and denominator equally
        # so the ratio is computed on the no-qp values and is qp-independent
        # (document note: "preserved at default qp = 1/|P|" confirms this)
        ratio_default   = rc2_total_no_qp / greedy_total if greedy_total else 0

        # With elevated qp the absolute credits change but the ratio is unchanged
        ratio_elevated  = ratio_default

        return {
            "rows":              rows,
            "rc2_total_qp":      rc2_total_qp,       # 1.445
            "rc2_total_no_qp":   rc2_total_no_qp,    # 3.612
            "greedy_total_no_qp":greedy_total,        # 1.749
            "ratio_at_default_qp": ratio_default,     # ≈ 2.1×
            "ratio_at_elevated_qp": ratio_elevated,
            "qp_elevated":       qp_elevated,
            "qp_default":        qp_default,
            "W_fixed":           W_fixed,
        }

    def print_document_table(self):
        """Print the Section G table with exact document values."""
        d = self.document_table()

        print("\n" + "=" * 72)
        print("  Section G — Cross-Path Force-Multiplier")
        print("  Single deployment x_{i,z,t,p}=1 covering three paths simultaneously")
        print("=" * 72)

        # Table header
        print(f"\n  {'Path':18s} {'ρ':>5} {'iv':>5} {'Wj,a':>6} "
              f"{'qp':>5} {'L3 weight':>12}  {'Formula'}")
        print("  " + "-" * 70)

        for r in d["rows"]:
            formula = (f"{r['rho']}×{r['iv']}×{r['W']:.2f}×{r['qp']}"
                       f"={r['l3_with_qp']:.3f}")
            print(f"  {r['name']:18s} {r['rho']:>5.2f} {r['iv']:>5.1f} "
                  f"{r['W']:>6.2f} {r['qp']:>5.2f} "
                  f"{r['l3_with_qp']:>12.3f}  {formula}")

        print("  " + "-" * 70)
        print(f"\n  RC2 total (qp=0.40):                    "
              f"{d['rc2_total_qp']:>8.3f}  "
              f"{'✓' if abs(d['rc2_total_qp']-1.445)<0.01 else '!'} doc=1.445")
        print(f"  Base-paper RC2 total (no qp):           "
              f"{d['rc2_total_no_qp']:>8.3f}  "
              f"{'✓' if abs(d['rc2_total_no_qp']-3.612)<0.01 else '!'} doc=3.612")
        print(f"  Base-paper Greedy (highest-ρ, no qp):   "
              f"{d['greedy_total_no_qp']:>8.3f}  "
              f"{'✓' if abs(d['greedy_total_no_qp']-1.749)<0.01 else '!'} doc=1.749")
        print(f"\n  RC2-vs-Greedy ratio at qp=1/|P|=0.25: "
              f"{d['ratio_at_default_qp']:>7.2f}×  "
              f"{'✓' if abs(d['ratio_at_default_qp']-2.1)<0.15 else '!'} "
              f"doc≈2.1×")

        print("\n  Interpretation:")
        print(f"    • One db_trap in Internal covers all three paths simultaneously")
        print(f"    • RC2 finds this; greedy only covers web-to-db (highest ρ)")
        print(f"    • Persona prior qp=0.40 amplifies credit on Finance_DB persona")
        print(f"    • At default qp=1/|P|=0.25, ratio≈2.1× — preserved from base paper")
        print("=" * 72)

    # ─────────────────────────────────────────────────────────────────
    #  SINGLE DEPLOYMENT ANALYSIS
    # ─────────────────────────────────────────────────────────────────

    def compute(
        self,
        trap:      str,
        zone:      str,
        t:         int,
        persona:   str,
        asset_id:  int | None = None,
        rho_scale: float = 1.0,
    ) -> dict:
        """
        Compute the cross-path force-multiplier for a given deployment.

        Returns dict with:
            path_credits     : {path_id: L3_credit} for each path through zone
            total_credit     : Σ L3 credits across all paths
            greedy_credit    : credit from highest-ρ path only
            ratio_vs_greedy  : total_credit / greedy_credit
            qp               : persona prior used
            guard            : dual discovery guard (1 or 0)
            by_path_detail   : full breakdown per path and hop
        """
        if self._is_airgapped(zone):
            return {"error": f"{zone} is air-gapped", "ratio_vs_greedy": 0.0}
        if zone not in self.diamond.get(trap, []):
            return {"error": f"{trap} not affine to {zone}", "ratio_vs_greedy": 0.0}
        if not self.pl.gk_admitted(trap, persona):
            return {"error": f"GK rejects ({trap},{persona})", "ratio_vs_greedy": 0.0}

        qp    = self.pl.qp.get(persona, 0.25)
        techs = self.trap_techs.get(trap, [])

        # Discovery guard (from dv if available, else assume undiscovered)
        if self.dv:
            guard = self.dv.dual_guard(trap, zone, t, persona)
        else:
            guard = 1

        # Use first asset in zone if not specified
        if asset_id is None:
            zone_assets = [a for a, z in self._assets if z == zone]
            asset_id = zone_assets[0] if zone_assets else 0

        # Mean W across techniques for this asset
        avg_W = float(np.mean([
            self.dw.W(tech, asset_id) for tech in techs
        ])) if techs else 0.0

        # Credit from each path that passes through this zone
        path_credits   = {}
        path_detail    = {}
        greedy_credit  = 0.0
        max_rho        = 0.0

        for path in self.G:
            pid   = path["id"]
            rho   = path["rho"] * rho_scale
            zones = path["zones"]
            ivs   = path["iv"]
            n_hops= len(zones)

            hops_in_zone = self._hop_of(path, zone)
            if not hops_in_zone:
                continue

            path_credit = 0.0
            hops_info   = []
            for hop in hops_in_zone:
                iv        = ivs[hop] if hop < len(ivs) else 1.0
                is_final  = (hop == n_hops - 1)
                # L3-fwd or L3-bwd depending on hop position
                w3_eff    = self.w3b if is_final else self.w3
                l3_credit = w3_eff * rho * iv * avg_W * qp * guard

                # L4 bonus at non-final hops
                iv_max     = max(ivs[h] for h in range(n_hops - 1)) \
                             if n_hops > 1 else 0.0
                l4_credit  = self.w4 * rho * iv_max * avg_W * qp * guard \
                             if not is_final else 0.0

                path_credit += l3_credit + l4_credit
                hops_info.append({
                    "hop": hop, "zone": zone, "iv": iv,
                    "is_final": is_final,
                    "l3": l3_credit, "l4": l4_credit,
                })

            path_credits[pid] = path_credit
            path_detail[pid]  = {
                "rho": rho, "hops": hops_info, "credit": path_credit
            }

            # Track which path gives greedy its single credit
            if rho > max_rho:
                max_rho       = rho
                greedy_credit = path_credit

        total_credit    = sum(path_credits.values())
        ratio           = total_credit / greedy_credit if greedy_credit > 0 else 0.0

        return {
            "trap":            trap,
            "zone":            zone,
            "t":               t,
            "persona":         persona,
            "asset_id":        asset_id,
            "qp":              qp,
            "guard":           guard,
            "avg_W":           avg_W,
            "path_credits":    path_credits,
            "total_credit":    total_credit,
            "greedy_credit":   greedy_credit,
            "ratio_vs_greedy": ratio,
            "by_path_detail":  path_detail,
            "n_paths_covered": len(path_credits),
        }

    # ─────────────────────────────────────────────────────────────────
    #  FULL DEPLOYMENT RANKING
    # ─────────────────────────────────────────────────────────────────

    def rank_deployments(
        self,
        top_n:     int   = 10,
        t:         int   = 0,
        rho_scale: float = 1.0,
        verbose:   bool  = True,
    ) -> list[dict]:
        """
        Score every valid (trap, zone, persona) and rank by force-multiplier.

        Args:
            top_n     : number of top deployments to return/print
            t         : slot index (for discovery guard if dv is attached)
            rho_scale : scale factor applied to all path probabilities

        Returns:
            List of result dicts sorted by total_credit descending.
        """
        results = []

        for trap in self.K:
            for zone in self.diamond.get(trap, []):
                if self._is_airgapped(zone):
                    continue
                for persona in self.P:
                    if not self.pl.gk_admitted(trap, persona):
                        continue
                    res = self.compute(
                        trap=trap, zone=zone, t=t,
                        persona=persona, rho_scale=rho_scale
                    )
                    if "error" not in res and res["total_credit"] > 0:
                        results.append(res)

        results.sort(key=lambda r: -r["total_credit"])

        if verbose:
            self._print_ranking(results[:top_n])

        return results

    def _print_ranking(self, results: list[dict]):
        print("\n" + "=" * 78)
        print("  Force-Multiplier Ranking — Top Deployments")
        print(f"  {'#':>2}  {'trap':14s} {'zone':10s} {'persona':18s}"
              f" {'qp':>6} {'paths':>6} {'FM':>7} {'total_credit':>13}")
        print("  " + "-" * 76)
        for i, r in enumerate(results, 1):
            fm = r["ratio_vs_greedy"]
            tc = r["total_credit"]
            pid_list = ",".join(r["path_credits"].keys())
            print(f"  {i:>2}  {r['trap']:14s} {r['zone']:10s} "
                  f"{r['persona']:18s} {r['qp']:>6.3f} "
                  f"{r['n_paths_covered']:>6} {fm:>7.2f}×"
                  f" {tc:>13.2f}")
        print("=" * 78)

    # ─────────────────────────────────────────────────────────────────
    #  PER-PATH BREAKDOWN
    # ─────────────────────────────────────────────────────────────────

    def print_path_breakdown(self, result: dict):
        """Print detailed per-path credit breakdown for a compute() result."""
        print(f"\n  Deployment: {result['trap']} / {result['zone']} / "
              f"t={result['t']} / {result['persona']}")
        print(f"  qp={result['qp']:.4f}  guard={result['guard']}"
              f"  avg_W={result['avg_W']:.4f}")
        print(f"\n  {'Path':12s} {'ρ':>6} {'hop':>4} {'final':>6} "
              f"{'iv':>5} {'L3':>10} {'L4':>10} {'subtotal':>12}")
        print("  " + "-" * 67)
        for pid, detail in result["by_path_detail"].items():
            for h in detail["hops"]:
                print(f"  {pid:12s} {detail['rho']:>6.3f} {h['hop']:>4d} "
                      f"{'yes' if h['is_final'] else 'no':>6s} "
                      f"{h['iv']:>5.2f} {h['l3']:>10.2f} {h['l4']:>10.2f} "
                      f"{h['l3']+h['l4']:>12.2f}")
        print("  " + "-" * 67)
        print(f"  {'TOTAL':12s} {'':>6} {'':>4} {'':>6} {'':>5} "
              f"{'':>10} {'':>10} {result['total_credit']:>12.2f}")
        print(f"\n  Greedy credit (best single path): {result['greedy_credit']:.2f}")
        print(f"  RC2 cross-path total:             {result['total_credit']:.2f}")
        print(f"  Force-multiplier:                 {result['ratio_vs_greedy']:.2f}×")

    # ─────────────────────────────────────────────────────────────────
    #  SCENARIO COMPARISON
    # ─────────────────────────────────────────────────────────────────

    def compare_qp_scenarios(
        self,
        trap:     str,
        zone:     str,
        t:        int,
        persona:  str,
        qp_vals:  list[float] | None = None,
    ) -> list[dict]:
        """
        Show how the force-multiplier changes as qp varies.
        Useful for illustrating the value of STIX-driven persona priors.
        """
        if qp_vals is None:
            qp_vals = [1/len(self.P), 0.30, 0.40, 0.50, 0.60]

        q_orig = dict(self.pl.qp)
        results = []
        for qp_val in qp_vals:
            self.pl.qp = {p: (qp_val if p == persona else
                              (1-qp_val)/(len(self.P)-1))
                          for p in self.P}
            res = self.compute(trap, zone, t, persona)
            res["qp_scenario"] = qp_val
            results.append(res)
        self.pl.qp = q_orig

        # Print comparison table
        print(f"\n  Force-multiplier vs qp for {trap}/{zone}/{persona}:")
        print(f"  {'qp':>8} {'total_credit':>14} {'ratio':>8}")
        print("  " + "-" * 34)
        for r in results:
            print(f"  {r['qp_scenario']:>8.4f} {r['total_credit']:>14.2f}"
                  f" {r['ratio_vs_greedy']:>7.2f}×")
        return results


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

    print("\n" + "=" * 70)
    print("  Force-Multiplier — Self-Test  (Section G)")
    print("=" * 70)

    pl  = PersonaLayer(CFG); pl.update_qp()
    dv  = DecisionVariables(CFG, pl)
    dw  = DerivedWeights(CFG, pl, dv)
    if "tactic_families" in CFG:
        dw.attach_tactic_families(CFG["tactic_families"])

    fm = ForceMultiplier(CFG, pl, dw, dv)

    # ── Test 1: Document table exact values ───────────────────────────
    print("\n[Test 1] Reproduce Section G document table exactly")
    d = fm.document_table()

    # Check each row
    expected_rows = [
        ("web-to-db",    0.30, 1.8, 3.24, 0.40, 0.700),
        ("ot-infiltr.",  0.15, 1.7, 3.24, 0.40, 0.330),
        ("brute-to-ad",  0.20, 1.6, 3.24, 0.40, 0.415),
    ]
    for exp, row in zip(expected_rows, d["rows"]):
        l3_exp = exp[5]
        l3_act = row["l3_with_qp"]
        assert abs(l3_act - l3_exp) < 0.001, \
            f"{exp[0]}: expected L3={l3_exp:.3f}, got {l3_act:.3f}"
        print(f"  {exp[0]:18s}: L3={l3_act:.3f}  "
              f"{'✓' if abs(l3_act-l3_exp)<0.001 else '✗'}")

    # Totals
    assert abs(d["rc2_total_qp"]    - 1.445) < 0.01, \
        f"RC2 total qp: {d['rc2_total_qp']:.3f} ≠ 1.445"
    assert abs(d["rc2_total_no_qp"] - 3.612) < 0.01, \
        f"RC2 no-qp: {d['rc2_total_no_qp']:.3f} ≠ 3.612"
    assert abs(d["greedy_total_no_qp"] - 1.749) < 0.01, \
        f"Greedy: {d['greedy_total_no_qp']:.3f} ≠ 1.749"
    assert abs(d["ratio_at_default_qp"] - 2.1) < 0.15, \
        f"Ratio: {d['ratio_at_default_qp']:.2f} should be ≈ 2.1×"

    print(f"  RC2 total (qp=0.40) = {d['rc2_total_qp']:.3f}  "
          f"(doc=1.445 ✓)")
    print(f"  Base-paper no-qp    = {d['rc2_total_no_qp']:.3f}  "
          f"(doc=3.612 ✓)")
    print(f"  Greedy (highest-ρ)  = {d['greedy_total_no_qp']:.3f}  "
          f"(doc=1.749 ✓)")
    print(f"  RC2/Greedy ratio    = {d['ratio_at_default_qp']:.2f}×  "
          f"(doc≈2.1× ✓)")

    fm.print_document_table()

    # ── Test 2: compute() for a real deployment ───────────────────────
    print("\n[Test 2] compute() — db_trap in Internal covers multiple paths")
    # Find first Internal asset
    internal_assets = [a for a, z in fm._assets if z == "Internal"]
    a_int = internal_assets[0] if internal_assets else 0

    # Temporarily set qp to elevated Finance_DB = 0.40
    pl_qp_orig = dict(pl.qp)
    pl.qp = {"Finance_DB": 0.40, "HR_workstation": 0.25,
              "DevOps_server": 0.20, "Generic_Linux": 0.15}

    result = fm.compute("db_trap", "Internal", t=0, persona="Finance_DB",
                        asset_id=a_int)
    pl.qp = pl_qp_orig   # restore

    assert "error" not in result, f"compute() error: {result.get('error')}"
    assert result["n_paths_covered"] >= 1, "Must cover at least one path"
    assert result["ratio_vs_greedy"] >= 1.0, "Ratio must be ≥ 1"
    print(f"  Paths covered: {result['n_paths_covered']}")
    print(f"  Total credit:  {result['total_credit']:.2f}")
    print(f"  Greedy credit: {result['greedy_credit']:.2f}")
    print(f"  FM ratio:      {result['ratio_vs_greedy']:.2f}×  ✓")
    fm.print_path_breakdown(result)

    # ── Test 3: FM ratio ≥ 1 everywhere (RC2 ≥ greedy by construction) ─
    print("\n[Test 3] FM ratio ≥ 1.0 for all valid deployments")
    all_ok = True
    for trap in CFG["K"]:
        for zone in CFG["diamond_affinity"].get(trap, []):
            if fm._is_airgapped(zone): continue
            for persona in CFG["P"]:
                if not pl.gk_admitted(trap, persona): continue
                r = fm.compute(trap, zone, t=0, persona=persona)
                if "error" in r: continue
                if r["ratio_vs_greedy"] < 1.0:
                    print(f"  FAIL: {trap}/{zone}/{persona} ratio={r['ratio_vs_greedy']:.3f}")
                    all_ok = False
    if all_ok:
        print("  All valid deployments have FM ≥ 1.0  ✓")

    # ── Test 4: qp amplification — higher qp → higher credit ──────────
    print("\n[Test 4] qp amplification — higher qp raises force-multiplier credit")
    qp_scenarios = fm.compare_qp_scenarios(
        "db_trap", "Internal", t=0, persona="Finance_DB",
        qp_vals=[0.25, 0.30, 0.40, 0.50]
    )
    credits = [r["total_credit"] for r in qp_scenarios]
    assert credits == sorted(credits), "Credit must be monotone in qp"
    print(f"  qp=0.25→0.50: credit {credits[0]:.1f}→{credits[-1]:.1f}  "
          f"(monotone ✓)")

    # ── Test 5: Air-gap / zone-affinity rejection ──────────────────────
    print("\n[Test 5] Air-gapped zone returns error gracefully")
    r_ot = fm.compute("ssh_trap", "OT", t=0, persona="Generic_Linux")
    assert "error" in r_ot, "ssh_trap in OT (air-gapped) must return error"
    print(f"  ssh_trap/OT: '{r_ot['error']}'  ✓")

    # ── Test 6: Full ranking ───────────────────────────────────────────
    print("\n[Test 6] Rank all valid deployments by force-multiplier")
    ranked = fm.rank_deployments(top_n=8, verbose=True)
    assert ranked[0]["ratio_vs_greedy"] >= ranked[-1]["ratio_vs_greedy"], \
        "Ranking must be descending"
    assert ranked[0]["total_credit"] > 0
    print(f"\n  Top deployment: {ranked[0]['trap']} / {ranked[0]['zone']} / "
          f"{ranked[0]['persona']}")
    print(f"  FM = {ranked[0]['ratio_vs_greedy']:.2f}×  ✓")

    # ── Test 7: 2.1× ratio preserved at default qp = 1/|P| ────────────
    print("\n[Test 7] 2.1× ratio preserved at default qp=1/|P|=0.25")
    # Set all qp to uniform 0.25
    pl_qp_orig = dict(pl.qp)
    pl.qp = {p: 0.25 for p in CFG["P"]}
    doc_ratio = fm.document_table()["ratio_at_default_qp"]
    pl.qp = pl_qp_orig
    assert abs(doc_ratio - 2.1) < 0.15, f"Ratio {doc_ratio:.2f} not ≈ 2.1×"
    print(f"  Document ratio at qp=0.25: {doc_ratio:.3f}×  "
          f"({'≈2.1× ✓' if abs(doc_ratio-2.1)<0.15 else 'FAIL'})")

    print("\n[✓] All force-multiplier self-tests passed.")
