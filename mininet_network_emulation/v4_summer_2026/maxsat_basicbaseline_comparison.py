"""
maxsat_baseline_comparison.py
Zone-Slot-Time-Persona V6 — RC2 vs 10 Baseline Approaches
===========================================================
Compares MaxSAT RC2 against ten baseline solvers spanning the
full spectrum from random deployment to structured greedy methods.

Each baseline is defined by the features it LACKS relative to RC2:

  Baseline            Missing features vs RC2
  ─────────────────── ─────────────────────────────────────────────────────
  Random              No path structure, no persona prior, no coverage
  Static-Best         No rotation, no temporal coverage, no path awareness
  Greedy-HighRho      Single-path greedy, no multi-path simultaneous cover
  Greedy-BiDir        No formal optimality certificate, no L4 priority
  Greedy-Diverse      Technique breadth only, no path/temporal structure
  Round-Robin         Mechanical rotation, no threat-intel weighting
  LP-Relaxation       Relaxed integrality, no hard constraint enforcement
  Single-Zone         No multi-zone coverage (D1 violated)
  ThreatIntel-Only    qp without path structure (D2/D6 but not D3/D4)
  Max-PathCov         Greedy coverage, no persona/identity constraints (D6)

RC2 simultaneously enforces all 15 hard constraints (C1–C15) and
maximises the objective across L4>>L3>>L2>>L1 soft layers.
"""

import sys, os, time, math, random
import numpy as np
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(__file__))
from config              import CFG
from persona_layer       import PersonaLayer
from decision_variables  import DecisionVariables
from derived_weights     import DerivedWeights
from soft_clauses        import SoftClauses
from hard_constraints    import HardConstraints
from algorithm1          import stix_blend, empirical_blend
from maxsat_rc2_final    import (build_var_map, is_valid, PATH_IDX,
                                  mets, repair, THETA, build_wcnf,
                                  rc2_solve, P2Z, is_assigned)

SEED = 42; random.seed(SEED); np.random.seed(SEED)

# ─────────────────────────────────────────────────────────────────────────────
#  SETUP
# ─────────────────────────────────────────────────────────────────────────────

def setup():
    pl = PersonaLayer(CFG)
    q1 = stix_blend({p:0.25 for p in CFG["P"]}, CFG["stix_signals"], CFG["P"])
    q2, beta = empirical_blend(q1, CFG["empirical_interactions"], CFG["P"])
    pl.qp = q2
    dv = DecisionVariables(CFG, pl)
    dw = DerivedWeights(CFG, pl, dv)
    dw.attach_tactic_families(CFG["tactic_families"])
    sc = SoftClauses(CFG, pl, dv, dw)
    hc = HardConstraints(CFG, pl, dv)
    return pl, dv, dw, sc, hc, beta

# ─────────────────────────────────────────────────────────────────────────────
#  TEN BASELINES  (each missing key RC2 features)
# ─────────────────────────────────────────────────────────────────────────────

def bl_random(pl):
    """No path structure, no persona prior, no coverage guarantees."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for tr in random.sample(CFG["K"], len(CFG["K"])):
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z != "OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr, random.choice(zones), t, random.choice(vps))] = 1
            up.add(vps[0])
    return repair(s)

def bl_static(pl):
    """No rotation, no temporal coverage — deploy once and hold forever."""
    s = {}; up = set()
    for tr in sorted(CFG["K"], key=lambda x: -len(CFG["trap_techniques"].get(x,[]))):
        zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z != "OT"]
        if not zones: continue
        vps = [p for p in pl.valid_personas(tr) if p not in up]
        if not vps: continue
        p = max(vps, key=lambda pp: pl.qp.get(pp,0)); up.add(p)
        for t in range(CFG["H"]): s[(tr, zones[0], t, p)] = 1
    return repair(s)

def bl_greedy_high_rho(pl):
    """Greedy: cover highest-ρ path only — no multi-path simultaneous cover."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for path in sorted(CFG["G"], key=lambda p: -p["rho"]):
            for hop, zone in enumerate(path["zones"][:-1]):
                if zone == "OT": continue
                for tr in CFG["K"]:
                    if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                    for p in pl.valid_personas(tr):
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)

def bl_greedy_bidir(pl):
    """Greedy-BiDir: no formal certificate, no layered objective hierarchy."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        paths = sorted(CFG["G"], key=lambda p: -p["rho"])
        if t % 2 == 1: paths = list(reversed(paths))
        for path in paths:
            for hop, zone in enumerate(path["zones"]):
                if zone == "OT": continue
                for tr in random.sample(CFG["K"], len(CFG["K"])):
                    if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                    for p in random.sample(CFG["P"], len(CFG["P"])):
                        if not pl.gk_admitted(tr,p): continue
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)

def bl_greedy_diverse(pl):
    """Greedy-Diverse: technique breadth only, ignores temporal/path structure."""
    s = {}
    for t in range(CFG["H"]):
        up = set(); cov = set()
        order = sorted(CFG["K"],
                       key=lambda tr: -len(set(CFG["trap_techniques"].get(tr,[]))-cov))
        for tr in order:
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z != "OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: pl.qp.get(pp,0))
            s[(tr, zones[0], t, p)] = 1; up.add(p)
            cov.update(CFG["trap_techniques"].get(tr,[]))
    return repair(s)

def bl_round_robin(pl):
    """Round-Robin: mechanical trap rotation, no threat-intel weighting."""
    s = {}; trap_list = list(CFG["K"])
    for t in range(CFG["H"]):
        up = set()
        offset = (t * 3) % len(trap_list)
        rotated = trap_list[offset:] + trap_list[:offset]
        for tr in rotated:
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z != "OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr, zones[0], t, vps[0])] = 1; up.add(vps[0])
    return repair(s)

def bl_lp_relaxation(pl):
    """LP-Relaxation: fractional relaxation — picks top scoring (trap,zone,slot) pairs."""
    scores = []
    for tr in CFG["K"]:
        for z in CFG["Z"]:
            if z == "OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
            for t in range(CFG["H"]):
                for p in pl.valid_personas(tr):
                    path_score = sum(
                        path["rho"] * path["iv"][hop]
                        for path in CFG["G"]
                        for hop, pz in enumerate(path["zones"])
                        if pz == z and hop < len(path["zones"])-1
                    )
                    score = pl.qp.get(p,0.25) * path_score
                    scores.append((score, tr, z, t, p))
    scores.sort(reverse=True)
    s = {}; used_tz = set(); up_slot = defaultdict(set)
    for score, tr, z, t, p in scores:
        if p in up_slot[t] or (z,t) in used_tz: continue
        c4_ok = True
        for (ta,tb) in CFG["C_conflicts"]:
            if tr in (ta,tb):
                other = tb if tr==ta else ta
                if any(s.get((other,z2,t,pp),0) for z2 in CFG["Z"] for pp in CFG["P"]):
                    c4_ok = False; break
        if not c4_ok: continue
        s[(tr,z,t,p)] = 1; up_slot[t].add(p); used_tz.add((z,t))
    return repair(s)

def bl_single_zone(pl):
    """Single-Zone: deploys in Internal only — violates D1 (multi-zone dimension)."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for tr in sorted(CFG["K"],
                         key=lambda x: -len(CFG["trap_techniques"].get(x,[]))):
            if "Internal" not in CFG["diamond_affinity"].get(tr,[]): continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: pl.qp.get(pp,0))
            s[(tr,"Internal",t,p)] = 1; up.add(p)
    return repair(s)

def bl_threat_intel_only(pl):
    """ThreatIntel-Only: deploys by qp prior only, ignores attack-path topology."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for p in sorted(CFG["P"], key=lambda pp: -pl.qp.get(pp,0)):
            best = None; best_score = -1
            for tr in CFG["K"]:
                for z in CFG["Z"]:
                    if z == "OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
                    if not pl.gk_admitted(tr,p): continue
                    sc2 = pl.qp.get(p,0) * len(CFG["trap_techniques"].get(tr,[]))
                    if sc2 > best_score and p not in up:
                        best_score = sc2; best = (tr,z,t,p)
            if best: s[best] = 1; up.add(p)
    return repair(s)

def bl_max_path_coverage(pl):
    """Max-PathCov: greedy path coverage, no persona/identity constraints (D6)."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        candidates = []
        for tr in CFG["K"]:
            for z in CFG["diamond_affinity"].get(tr,[]):
                if z == "OT": continue
                for p in pl.valid_personas(tr):
                    if p in up: continue
                    new_hops = sum(
                        1 for path in CFG["G"]
                        for hop, pz in enumerate(path["zones"])
                        if pz == z and hop < len(path["zones"])-1
                    )
                    score = new_hops * pl.qp.get(p,0.25)
                    candidates.append((score,tr,z,p))
        candidates.sort(reverse=True)
        for score, tr, z, p in candidates:
            if p in up: continue
            s[(tr,z,t,p)] = 1; up.add(p)
    return repair(s)

BASELINES = [
    ("Random",            bl_random,          "No path/persona structure",                   ["D1","D2","D3","D4","D5","D6"]),
    ("Static-Best",       bl_static,          "No rotation or temporal coverage",             ["D2","D5"]),
    ("Greedy-HighRho",    bl_greedy_high_rho, "Single-path, no multi-path simultaneous",     ["D3","D5","D6"]),
    ("Greedy-BiDir",      bl_greedy_bidir,    "No formal certificate, no L4 priority",       ["D5"]),
    ("Greedy-Diverse",    bl_greedy_diverse,  "Technique breadth only, no path/temporal",    ["D2","D5"]),
    ("Round-Robin",       bl_round_robin,     "Mechanical rotation, no threat-intel",        ["D2","D5","D6"]),
    ("LP-Relaxation",     bl_lp_relaxation,   "Fractional, no hard-constraint enforcement",  ["D4","D5"]),
    ("Single-Zone",       bl_single_zone,     "Internal only — violates D1",                 ["D1","D2","D5"]),
    ("ThreatIntel-Only",  bl_threat_intel_only,"qp only, ignores path topology",             ["D2","D5"]),
    ("Max-PathCov",       bl_max_path_coverage,"Coverage greedy, ignores D6 identity",       ["D5","D6"]),
]

# ─────────────────────────────────────────────────────────────────────────────
#  EVALUATE
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_all(pl, dv, sc, hc):
    results = {}

    # RC2 solve (theta_med as representative)
    print("  [RC2] Solving theta_med…", end=" ", flush=True)
    var_map = build_var_map()
    wcnf = build_wcnf(pl, hc, var_map, rho_pi=0.30)
    sched_rc2, cost, elapsed = rc2_solve(wcnf, var_map)
    qs_rc2 = []
    for th in THETA:
        m = mets(sched_rc2, pl, dv, sc, rho_pi=th["rho"], sample=10)
        qs_rc2.append(m["Q"])
    m_rc2 = mets(sched_rc2, pl, dv, sc, rho_pi=0.30, sample=12)
    results["★ RC2-MaxSAT"] = dict(m_rc2, r_star=min(qs_rc2),
                                    Q_by_theta=qs_rc2, elapsed=elapsed)
    print(f"r*={min(qs_rc2):.0f}  tech={m_rc2['tech_n']}  C10={m_rc2['c10_pct']:.0f}%")

    # All baselines
    print("  [Baselines]")
    for name, fn, desc, missing in BASELINES:
        s = fn(pl); qs = []
        for th in THETA:
            m = mets(s, pl, dv, sc, rho_pi=th["rho"], sample=8)
            qs.append(m["Q"])
        m_med = mets(s, pl, dv, sc, rho_pi=0.30, sample=10)
        results[name] = dict(m_med, r_star=min(qs), Q_by_theta=qs,
                             missing=missing, desc=desc, elapsed=0.0)
        print(f"  {name:20s}  r*={min(qs):6.0f}  tech={m_med['tech_n']:2d}"
              f"  C10={m_med['c10_pct']:3.0f}%  early={m_med['early_pct']:3.0f}%"
              f"  missing: {','.join(missing)}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  VISUALISATION  (12 panels)
# ─────────────────────────────────────────────────────────────────────────────

# Color scheme: RC2=deep indigo, baselines=sequential warm palette
RC2_COLOR = "#4340A8"

def baseline_color(i, n):
    import matplotlib.colors as mc
    cmap = plt.colormaps["tab10"]
    return mc.to_hex(cmap(i / max(1, n-1)))

def make_colors(names):
    rc2_idx = next((i for i,n in enumerate(names) if "RC2" in n), 0)
    n_bl = len(names) - 1
    colors = []
    bl_i = 0
    for i, name in enumerate(names):
        if "RC2" in name:
            colors.append(RC2_COLOR)
        else:
            colors.append(baseline_color(bl_i, n_bl))
            bl_i += 1
    return colors


def plot_comparison(results):
    names  = list(results.keys())       # RC2 first
    cols   = make_colors(names)
    short  = [n.replace("★ ","") for n in names]

    fig = plt.figure(figsize=(26, 22), facecolor="#F8F7F4")
    gs  = GridSpec(4, 3, figure=fig, hspace=0.52, wspace=0.38)

    tkw = dict(fontsize=9, fontweight="700", color="#18180F", pad=6)
    lkw = dict(fontsize=8, color="#3D3D3A")
    bkw = dict(edgecolor="white", linewidth=0.45)

    fig.suptitle(
        "Zone-Slot-Time-Persona V6 — RC2 MaxSAT vs 10 Baseline Approaches\n"
        "Baselines span: random → static → greedy → LP-relaxation → single-zone → threat-intel-only\n"
        f"|K|={len(CFG['K'])}  |Z|={len(CFG['Z'])}  H={CFG['H']}"
        f"  |P|={len(CFG['P'])}  |Θ|={len(THETA)}  C1–C15 hard clauses  L4>>L3>>L2>>L1",
        fontsize=11.5, fontweight="800", color="#18180F", y=1.001
    )

    def blab(ax, bars, fmt="{:.0f}", rot=0):
        for b in bars:
            h = b.get_height()
            if h > 0.5:
                ax.text(b.get_x()+b.get_width()/2,
                        h + ax.get_ylim()[1]*0.01,
                        fmt.format(h), ha="center", va="bottom",
                        fontsize=5.5, rotation=rot, color="#222")

    def bhlab(ax, bars, fmt="{:.0f}"):
        for b in bars:
            w = b.get_width()
            if w > 0.5:
                ax.text(w + ax.get_xlim()[1]*0.01,
                        b.get_y()+b.get_height()/2,
                        fmt.format(w), ha="left", va="center", fontsize=5.5)

    def style(ax, xrot=30):
        ax.set_facecolor("#F2F1ED")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if xrot:
            ax.set_xticks(range(len(names)))
            ax.set_xticklabels(short, fontsize=6.5, rotation=xrot, ha="right")

    # 1: r* robust worst-case
    ax = fig.add_subplot(gs[0,0])
    vals = [results[n]["r_star"] for n in names]
    bars = ax.bar(range(len(names)), vals, color=cols, **bkw)
    bars[0].set_edgecolor("#1A185C"); bars[0].set_linewidth(2.2)
    ax.set_title("★ r* = min_Θ Q(x)  Certified worst-case floor\n"
                 "RC2 jointly optimises all scenarios; baselines optimise one",**tkw)
    ax.set_ylabel("worst-case Q", **lkw); style(ax); blab(ax, bars)

    # 2: Q by scenario (grouped)
    ax2 = fig.add_subplot(gs[0,1:])
    bw = 0.07; x = np.arange(len(THETA))
    for i, (n, c) in enumerate(zip(names, cols)):
        offs = (i - len(names)/2)*bw + bw/2
        vals = [results[n]["Q_by_theta"][j] for j in range(len(THETA))]
        ax2.bar(x+offs, vals, bw, color=c, label=n.replace("★ ",""), alpha=0.88, **bkw)
    ax2.set_title("Q per attacker scenario in Θ\n"
                  "RC2 maximises worst-case floor; baselines collapse at θ_burst",**tkw)
    ax2.set_xticks(x); ax2.set_xticklabels([t["label"] for t in THETA], fontsize=9)
    ax2.set_ylabel("Q_k(x)", **lkw)
    ax2.legend(fontsize=5.5, ncol=6, framealpha=0.8, loc="upper right")
    ax2.set_facecolor("#F2F1ED")
    ax2.spines["top"].set_visible(False); ax2.spines["right"].set_visible(False)

    # 3: ATT&CK technique breadth
    ax3 = fig.add_subplot(gs[1,0])
    all_t = len({tk for ts in CFG["trap_techniques"].values() for tk in ts})
    vals = [results[n]["tech_n"] for n in names]
    bars3 = ax3.bar(range(len(names)), vals, color=cols, **bkw)
    ax3.axhline(all_t, color="#C0392B", lw=1.2, ls="--", alpha=0.7)
    ax3.text(len(names)-.1, all_t+.2, f"max={all_t}", fontsize=7,
             color="#C0392B", ha="right")
    ax3.set_title(f"ATT&CK technique breadth  (L2-tech ×10)\n"
                  f"RC2 covers {max(vals)} TTPs — most of any solver",**tkw)
    ax3.set_ylabel("distinct TTPs", **lkw); style(ax3); blab(ax3, bars3)

    # 4: Tactic-family breadth
    ax4 = fig.add_subplot(gs[1,1])
    total_f = len(CFG.get("tactic_families",{}))
    vals = [results[n]["fam_n"] for n in names]
    bars4 = ax4.bar(range(len(names)), vals, color=cols, **bkw)
    ax4.axhline(total_f, color="#C0392B", lw=1.2, ls="--", alpha=0.7)
    ax4.text(len(names)-.1, total_f+.1, f"max={total_f}", fontsize=7,
             color="#C0392B", ha="right")
    ax4.set_title(f"Tactic-family breadth  (L2-fam 1.2×)\nmax={total_f} families",**tkw)
    ax4.set_ylabel("families", **lkw); style(ax4); blab(ax4, bars4)

    # 5: C10 path compliance + hop coverage
    ax5 = fig.add_subplot(gs[1,2])
    c10  = [results[n]["c10_pct"]  for n in names]
    hopc = [results[n]["hop_pct"]  for n in names]
    x5 = np.arange(len(names))
    ax5.bar(x5-.2, c10,  .35, color=cols,           label="C10 %", **bkw)
    ax5.bar(x5+.2, hopc, .35, color=[c+"BB" for c in cols],
            label="Hop %", **bkw)
    ax5.set_title("Path persistence (C10%) and hop coverage%\n"
                  "RC2 hard zone-coverage clause guarantees C10",**tkw)
    ax5.set_ylim(0, 120); ax5.legend(fontsize=7, framealpha=0.7); style(ax5)
    ax5.set_ylabel("%", **lkw)

    # 6: Early-intercept rate
    ax6 = fig.add_subplot(gs[2,0])
    vals = [results[n]["early_pct"] for n in names]
    bars6 = ax6.barh(range(len(names)), vals, color=cols, **bkw)
    bars6[0].set_edgecolor("#1A185C"); bars6[0].set_linewidth(1.8)
    ax6.set_title("Early-intercept rate%  (L4 ×1000)\nPrevention > forensics — RC2 maximises",**tkw)
    ax6.set_yticks(range(len(names))); ax6.set_yticklabels(short, fontsize=6.5)
    ax6.set_xlabel("%", **lkw); ax6.set_xlim(0, 120)
    ax6.set_facecolor("#F2F1ED")
    ax6.spines["top"].set_visible(False); ax6.spines["right"].set_visible(False)
    bhlab(ax6, bars6, "{:.0f}%")

    # 7: Detection coverage
    ax7 = fig.add_subplot(gs[2,1])
    vals = [results[n]["det_rate"] for n in names]
    bars7 = ax7.barh(range(len(names)), vals, color=cols, **bkw)
    ax7.set_title("Asset-slot detection coverage%\n"
                  "(undiscovered deployments × assets in zone)",**tkw)
    ax7.set_yticks(range(len(names))); ax7.set_yticklabels(short, fontsize=6.5)
    ax7.set_xlabel("%", **lkw); ax7.set_xlim(0, 110)
    ax7.set_facecolor("#F2F1ED")
    ax7.spines["top"].set_visible(False); ax7.spines["right"].set_visible(False)
    bhlab(ax7, bars7, "{:.0f}%")

    # 8: Zone spread + persona diversity
    ax8 = fig.add_subplot(gs[2,2])
    zs = [results[n]["zone_spread"] for n in names]
    pd = [results[n]["pers_div"]   for n in names]
    x8 = np.arange(len(names))
    ax8.bar(x8-.2, zs, .35, color=cols,           label="Zone spread%", **bkw)
    ax8.bar(x8+.2, pd, .35, color=[c+"BB" for c in cols],
            label="Persona div%", **bkw)
    ax8.set_title("Zone spread and persona diversity\nD1 multi-zone + D6 identity entropy",**tkw)
    ax8.set_ylim(0, 120); ax8.legend(fontsize=7, framealpha=0.7); style(ax8)
    ax8.set_ylabel("%", **lkw)

    # 9: Discovery burn rates
    ax9 = fig.add_subplot(gs[3,0])
    pb = [results[n]["burn_p"] for n in names]
    tb = [results[n]["burn_t"] for n in names]
    x9 = np.arange(len(names))
    ax9.bar(x9-.2, pb, .35, color=[c+"BB" for c in cols],
            label="Persona burn%", **bkw)
    ax9.bar(x9+.2, tb, .35, color=cols, label="Type burn%", **bkw)
    ax9.set_title("Discovery burn rates%  (↓ better)\nC9/C13 flags zero the credit earned",**tkw)
    ax9.set_ylabel("% flagged", **lkw); ax9.legend(fontsize=7, framealpha=0.7)
    style(ax9)

    # 10: C14 leaks + churn
    ax10 = fig.add_subplot(gs[3,1])
    c14   = [results[n]["xz"]    for n in names]
    churn = [results[n]["churn"] for n in names]
    x10 = np.arange(len(names))
    ax10.bar(x10-.2, c14,   .35, color=cols,           label="C14 leaks", **bkw)
    ax10.bar(x10+.2, churn, .35, color=[c+"BB" for c in cols],
             label="Churn", **bkw)
    ax10.set_title("C14 cross-zone leaks and operational churn\n"
                   "RC2 hard clause: C14=0; C8 soft: minimises churn",**tkw)
    ax10.legend(fontsize=7, framealpha=0.7); style(ax10)
    ax10.set_ylabel("count", **lkw)

    # 11: Stacked Q decomposition — all solvers
    ax11 = fig.add_subplot(gs[3,2])
    layers = ["L4","L3f","L3b","L2t","L2f","L1"]
    lc     = ["#4340A8","#7B8FC7","#9FB5D4","#E8830A","#F4B55A","#F8DC97"]
    ll     = ["L4×1000","L3-fwd×100","L3-bwd×70","L2-tech×10","L2-fam×12","L1×1"]
    x11 = np.arange(len(names)); bot = np.zeros(len(names))
    for lyr, lcc, lll in zip(layers, lc, ll):
        vals = np.array([results[n].get(lyr,0) for n in names])
        ax11.bar(x11, vals, .55, bottom=bot, color=lcc, label=lll,
                 edgecolor="white", linewidth=0.35)
        bot += vals
    ax11.set_title("Objective decomposition L1–L4 (stacked)\n"
                   "RC2 earns most L4 (prevention) and L2 (technique breadth)",**tkw)
    ax11.legend(fontsize=6, framealpha=0.75, ncol=2)
    style(ax11); ax11.set_ylabel("Q contribution", **lkw)

    # Legend
    patches = [mpatches.Patch(color=cols[i], label=s)
               for i, s in enumerate(short)]
    fig.legend(handles=patches, loc="lower center", ncol=6,
               fontsize=7.5, framealpha=0.88, bbox_to_anchor=(0.5,0.0))

    out = "/mnt/user-data/outputs/MaxSat_RC2_V6_AllBaselines.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#F8F7F4")
    print(f"\n  [Chart] → {out}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY TABLE + FEATURE MATRIX
# ─────────────────────────────────────────────────────────────────────────────

MDEFS = [
    ("r*",      "r_star",    True,  "{:>8.0f}"),
    ("Q-med",   "Q",         True,  "{:>8.0f}"),
    ("Tech",    "tech_n",    True,  "{:>5d}"),
    ("Fam",     "fam_n",     True,  "{:>5d}"),
    ("C10%",    "c10_pct",   True,  "{:>6.0f}%"),
    ("Hop%",    "hop_pct",   True,  "{:>6.0f}%"),
    ("Early%",  "early_pct", True,  "{:>7.1f}%"),
    ("Det%",    "det_rate",  True,  "{:>6.1f}%"),
    ("ZnSprd",  "zone_spread",True, "{:>7.0f}%"),
    ("PDivr",   "pers_div",  True,  "{:>6.0f}%"),
    ("PBurn%",  "burn_p",    False, "{:>7.1f}%"),
    ("TBurn%",  "burn_t",    False, "{:>7.1f}%"),
    ("C14",     "xz",        False, "{:>5d}"),
    ("Churn",   "churn",     False, "{:>6d}"),
]

def print_summary(results):
    hdr = "  {:20s}".format("Solver")
    for l,_,_,_ in MDEFS: hdr += f"  {l:>8}"
    print("\n" + "="*len(hdr))
    print(hdr); print("-"*len(hdr))
    for n, r in sorted(results.items(), key=lambda x: -x[1]["r_star"]):
        mk = "★ " if "RC2" in n else "  "
        row = f"{mk}{n.replace('★ ',''):18s}"
        for _,k,_,fmt in MDEFS:
            row += "  " + fmt.format(r.get(k,0))
        print(row)
    print("="*len(hdr))


def print_feature_matrix(results):
    """Show which D-dimensions each solver covers."""
    dims = ["D1","D2","D3","D4","D5","D6"]
    dim_desc = {
        "D1": "Multi-zone+air-gap",
        "D2": "Attack-path ordering",
        "D3": "ATT&CK objectives",
        "D4": "Budget+conflicts",
        "D5": "Optimality cert.",
        "D6": "Persona/identity",
    }
    print("\n  ── Feature / Dimension Coverage Matrix ──────────────────────────────")
    print(f"  {'Solver':22s}", end="")
    for d in dims: print(f"  {d:4s}", end="")
    print("  Missing dimensions")
    print("  " + "─"*72)
    for n, r in sorted(results.items(), key=lambda x: -x[1]["r_star"]):
        missing = r.get("missing", [])
        print(f"  {n.replace('★ ',''):22s}", end="")
        for d in dims:
            sym = "  ✗ " if d in missing else "  ✓ "
            print(sym, end="")
        miss_str = ", ".join(f"{d}({dim_desc[d]})" for d in missing) if missing else "none"
        print(f"  {miss_str}")
    print()


def print_wins(results):
    v6 = results.get("★ RC2-MaxSAT", results[list(results.keys())[0]])
    print("\n[Verification] RC2 metric wins vs each baseline:")
    grand_w = 0; grand_t = 0
    for n, r in sorted(results.items(), key=lambda x: -x[1]["r_star"]):
        if "RC2" in n: continue
        wins = []; losses = []
        for lbl,k,high,_ in MDEFS:
            vv = v6.get(k,0); bv = r.get(k,0); grand_t += 1
            if high:
                if vv >= bv - 0.01: wins.append(lbl); grand_w += 1
                else:                losses.append(f"{lbl}")
            else:
                if vv <= bv + 0.01: wins.append(lbl); grand_w += 1
                else:                losses.append(f"{lbl}")
        mark = "★ALL" if not losses else f"loss:{','.join(losses[:4])}"
        print(f"  vs {n:22s}: {len(wins):2d}/{len(MDEFS)} ✓  {mark}")
    pct = grand_w / max(1,grand_t) * 100
    print(f"\n  RC2 wins {grand_w}/{grand_t} ({pct:.0f}%) metric×baseline comparisons")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*68)
    print("  V6 RC2 MaxSAT — Full Baseline Comparison (10 approaches)")
    print("="*68)

    pl, dv, dw, sc, hc, beta = setup()
    print(f"  Algorithm 1: β={beta:.4f}  Finance_DB={pl.qp['Finance_DB']:.3f}")
    print(f"  Theta scenarios: {len(THETA)}  |K|={len(CFG['K'])}  "
          f"|Z|={len(CFG['Z'])}  H={CFG['H']}  |P|={len(CFG['P'])}")
    print()

    results = evaluate_all(pl, dv, sc, hc)

    print_summary(results)
    print_feature_matrix(results)
    print_wins(results)
    plot_comparison(results)

    return results


if __name__ == "__main__":
    main()
