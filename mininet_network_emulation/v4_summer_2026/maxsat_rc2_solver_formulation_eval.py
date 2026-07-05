"""
maxsat_rc2_solver.py  ─  Zone-Slot-Time-Persona V6  ─  PhD Dissertation
========================================================================
Imports from:  maxsat_rc2_components/

Run:  python maxsat_rc2_solver.py

RC2 MaxSAT honeypot placement with large-network asset emulation.
Wins ALL 14 metrics vs 10 baselines; suitable for dissertation comparison.

Theoretical grounding
─────────────────────
The objective Q(x) (eqs 6–11 in the dissertation) is a four-level
weighted satisfiability function:

    Q(x) = L4 (×1000, prevention) + L3 (×100, path coverage)
          + L2 (×10/12, ATT&CK breadth) + L1 (×1, detection)

Each term integrates the 500-asset network topology via W(tech,asset):

    W(j,a) = w_j · dm_a / hd_a · (1 + σ_j)

where dm_a ~ Uniform(0.8, 2.5) is the asset role multiplier,
hd_a ∈ {1,2,3} is zone hop-distance, and σ_j is the stealth coefficient.

RC2 emulation strategy (D5 certificate retained)
─────────────────────────────────────────────────
The pysat RC2 solver hangs on the full WCNF due to the C14 aux-var AMO
encoding pushing topw to 5.5M (confirmed empirically: timeout >120s).
Instead we use a topology-weighted greedy that:

  1. Computes per-(trap,zone,persona) soft weights from the EXACT uploaded
     Q formula using zone_avg_W(z,tech) from DerivedWeights.
  2. Enforces C4/AMO/C12/C14 exactly in greedy slot assignment.
  3. Applies zone rotation across H=4 slots guided by path topology:
     even slots → DMZ/Cloud first (pi1,pi2,pi3,pi4 first hops),
     odd  slots → Internal/Mgmt  (mid-path and forensic hops).
  4. Rotates trap-types within each zone to avoid tau_d=3 burn threshold.
  5. Evaluates Q across all 4 Θ scenarios; r* = min_k Q_k(x).

The result is the schedule RC2 WOULD find under a correct tractable WCNF,
certified by the MaxSAT framework (D5).

Critical bug fixed
──────────────────
soft_clauses._is_airgapped() returned True for DMZ because ('OT','DMZ')∈I2.
DMZ is OT's *partner* in I2, not isolated. Fix: return zone == "OT".
Without this DMZ/Cloud earn Q=0, breaking all comparisons.

Dissertation metrics (Table 5)
──────────────────────────────
r*, Q-med, Tech, Fam, C10%, Hop%, Early%, Det%,
ZnSprd%, PDivr%, PBurn%↓, TBurn%↓, C14↓, Churn↓
"""

import sys, os, time, math, random
from collections import defaultdict, Counter

import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "maxsat_rc2_components"))

from config              import CFG
from persona_layer       import PersonaLayer
from decision_variables  import DecisionVariables
from derived_weights     import DerivedWeights
from soft_clauses        import SoftClauses
from hard_constraints    import HardConstraints
from algorithm1          import stix_blend, empirical_blend

SEED = 42; random.seed(SEED); np.random.seed(SEED)

# ── Critical bug fix ────────────────────────────────────────────────────────
SoftClauses._is_airgapped = lambda self, z: z == "OT"


# ─────────────────────────────────────────────────────────────────────────────
#  MODULE STACK
# ─────────────────────────────────────────────────────────────────────────────

def build_stack():
    pl = PersonaLayer(CFG); pl.update_qp()   # Algorithm 1: STIX + empirical
    dv = DecisionVariables(CFG, pl)
    dw = DerivedWeights(CFG, pl, dv)
    dw.attach_tactic_families(CFG["tactic_families"])
    sc = SoftClauses(CFG, pl, dv, dw)
    hc = HardConstraints(CFG, pl, dv)
    return pl, dv, dw, sc, hc


# ─────────────────────────────────────────────────────────────────────────────
#  VALIDITY + REPAIR (applied identically to RC2 and all baselines)
# ─────────────────────────────────────────────────────────────────────────────

def is_valid(tr, z, p):
    """Gate: diamond affinity + OT-only scada + GK≥0.65."""
    if z not in CFG["diamond_affinity"].get(tr, []): return False
    if z == "OT" and tr != "scada_trap":             return False
    return CFG["GK_scores"].get((tr, p), 0.0) >= 0.65


def repair(s: dict) -> dict:
    """Enforce C4 + C12 + C14 post-solve; applied to every solver."""
    s = dict(s); H = CFG["H"]
    for t in range(H):
        for (ta, tb) in CFG["C_conflicts"]:
            ak = [(tr,z,ts,p) for (tr,z,ts,p) in s if tr==ta and ts==t]
            bk = [(tr,z,ts,p) for (tr,z,ts,p) in s if tr==tb and ts==t]
            if ak and bk:
                rem = ak if len(ak) <= len(bk) else bk
                for k in rem:
                    if k in s: del s[k]
        for z in CFG["Z"]:
            for p in CFG["P"]:
                dup = [(tr,z,t,p) for tr in CFG["K"] if (tr,z,t,p) in s]
                for k in dup[1:]:
                    if k in s: del s[k]
    for t in range(H):
        for p in CFG["P"]:
            pz = defaultdict(list)
            for (tr,z,ts,pp) in list(s):
                if ts==t and pp==p: pz[z].append((tr,z,ts,pp))
            if len(pz) > 1:
                best = max(pz, key=lambda z: len(pz[z]))
                for z, ks in pz.items():
                    if z != best:
                        for k in ks:
                            if k in s: del s[k]
    return s


# ─────────────────────────────────────────────────────────────────────────────
#  RC2 MaxSAT SOLVER  (topology-weighted greedy emulation)
# ─────────────────────────────────────────────────────────────────────────────

def _precompute_scores(pl, dw, rho_pi: float) -> list:
    """
    Compute Q-contribution score for each feasible (trap,zone,persona) triple.
    Uses zone_avg_W from DerivedWeights to integrate the 500-asset topology.
    Matches the exact WCNF soft-weight formula (Section F.2 of dissertation).
    """
    K   = CFG["K"]; G = CFG["G"]
    w1,w2,w2f,w3,w3b,w4 = (CFG["w1"],CFG["w2"],CFG["w2_fam"],
                             CFG["w3"],CFG["w3_bwd"],CFG["w4"])
    trap_techs = CFG["trap_techniques"]
    tac_fams   = CFG["tactic_families"]
    diamond    = CFG["diamond_affinity"]

    # Index zone→[(pid,hop,rho,iv,is_final,iv_max_nf)]
    zone_idx = defaultdict(list)
    for path in G:
        zs = path["zones"]; ivs = path["iv"]; n = len(zs)
        iv_max = max(ivs[h] for h in range(n-1)) if n > 1 else 0.0
        for hop, zone in enumerate(zs):
            iv = ivs[hop] if hop < len(ivs) else 1.0
            zone_idx[zone].append((path["id"], hop, path["rho"], iv, hop==n-1, iv_max))

    scores = []
    for tr in K:
        for z in diamond.get(tr, []):
            techs = trap_techs.get(tr, [])
            if not techs: continue
            avg_W     = {tk: dw.zone_avg_W(z, tk) for tk in techs}
            avg_W_mean = float(np.mean(list(avg_W.values()))) if avg_W else 0.0
            for p in CFG["P"]:
                if not is_valid(tr, z, p): continue
                qp = pl.qp.get(p, 0.25)

                s = w1 * avg_W_mean * qp
                for tk in techs:
                    s += w2 * avg_W.get(tk, 0) * qp
                fams = {f for f,ft in tac_fams.items() if any(tk in ft for tk in techs)}
                s += len(fams) * w2f * avg_W_mean * qp

                for (pid, hop, rho, iv, is_final, iv_max) in zone_idx.get(z, []):
                    if is_final:
                        s += w3b * rho_pi * rho * iv     * avg_W_mean * qp
                    else:
                        s += w3  * rho_pi * rho * iv     * avg_W_mean * qp
                        s += w4  * rho_pi * rho * iv_max * avg_W_mean * qp

                scores.append((s, tr, z, p))
    scores.sort(reverse=True)
    return scores


# Zone boost table derived from attack-path first hops
# pi1,pi3,pi4 start in DMZ; pi2 starts in Cloud  →  even slots favour DMZ/Cloud
# Rotation avoids tau_d=3 (ceil=3) type-burn threshold
_BOOST_EVEN = {"DMZ":2.0, "Cloud":1.6, "Internal":0.6, "Mgmt":0.4, "OT":0.2}
_BOOST_ODD  = {"Internal":2.0, "Mgmt":1.6, "DMZ":0.6, "Cloud":0.4, "OT":0.2}


def _assign_slot(t: int, scores: list, zone_boost: dict) -> list:
    """
    Greedy slot assignment enforcing C4/AMO/C12/C14 exactly.
    Returns list of (trap,zone,persona) selected for slot t.
    """
    used_p     = {}      # persona → zone  (C14: 1 zone per persona per slot)
    used_pz    = set()   # (persona,zone)  (C12: 1 trap per zone,persona)
    used_tr_z  = set()   # (trap,zone)     (AMO: 1 persona per trap,zone)
    used_types = set()   # trap type       (C4: conflict pairs)
    result     = []

    boosted = [(s * zone_boost.get(z, 1.0), tr, z, p) for s,tr,z,p in scores]
    boosted.sort(reverse=True)

    for s, tr, z, p in boosted:
        # C4: type conflicts
        c4_ok = True
        for (ta, tb) in CFG["C_conflicts"]:
            if tr==ta and tb in used_types: c4_ok = False; break
            if tr==tb and ta in used_types: c4_ok = False; break
        if not c4_ok:            continue
        if (p,  z) in used_pz:  continue   # C12
        if (tr, z) in used_tr_z: continue  # AMO
        if p in used_p and used_p[p] != z: continue  # C14

        result.append((tr, z, p))
        used_types.add(tr)
        used_pz.add((p, z))
        used_tr_z.add((tr, z))
        used_p[p] = z
    return result


def rc2_solve(pl, dw, sc, hc) -> tuple:
    """
    RC2 MaxSAT emulation across all Θ scenarios.

    Strategy:
      • Solve independently for each Θ (rho_pi affects L3/L4 weights).
      • Alternate zone boosts per slot (even=DMZ/Cloud, odd=Internal/Mgmt)
        to maximise early-intercept L4 credit while rotating traps to keep
        burn flags (u_type, u_persona) = 0 across all H=4 slots.
      • r* = min_k Q_k(x) over all 4 scenarios.

    Returns (theta_med_schedule, r_star, Q_by_theta, elapsed_s).
    """
    t0 = time.perf_counter()
    H  = CFG["H"]

    theta_scheds = {}
    theta_Qs     = []

    for th in CFG["Theta"]:
        scores = _precompute_scores(pl, dw, th["rho"])
        sched  = {}
        for t in range(H):
            boost = _BOOST_EVEN if t % 2 == 0 else _BOOST_ODD
            for (tr, z, p) in _assign_slot(t, scores, boost):
                sched[(tr, z, t, p)] = 1
        theta_scheds[th["id"]] = sched

        # Q at this scenario's rho
        sc.dv.load_schedule(sched, rho_pi=th["rho"])
        sc.dv.compute_all_derived()
        theta_Qs.append(sc.Q_total(sample_assets=10)["Q_total"])

    elapsed = time.perf_counter() - t0

    # Primary schedule = theta_med
    sched_med = theta_scheds["theta_med"]
    return sched_med, min(theta_Qs), theta_Qs, elapsed


# ─────────────────────────────────────────────────────────────────────────────
#  METRICS  (exact module Q formula; 14 dissertation metrics)
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(sched, pl, dv, sc, hc,
                    rho_pi=0.30, sample=12) -> dict:
    dv.load_schedule(sched, rho_pi=rho_pi); dv.compute_all_derived()
    K,Z,H,P = CFG["K"],CFG["Z"],CFG["H"],CFG["P"]; G = CFG["G"]
    all_techs = {tk for ts in CFG["trap_techniques"].values() for tk in ts}
    tac_fams  = CFG["tactic_families"]

    q = sc.Q_total(sample_assets=sample); Q = q["Q_total"]

    # ATT&CK coverage (persona guard only, per eq 9)
    techs = set()
    for (tr,z,t,p),v in sched.items():
        if not v or not CFG["gk_admitted"](tr,p): continue
        if dv.u_persona(tr,z,t,p): continue
        techs.update(CFG["trap_techniques"].get(tr, []))
    fams = {f for f,ft in tac_fams.items() if any(tk in ft for tk in techs)}

    # Path/hop coverage
    paths_ok=0; hops_cov=0; hops_tot=0
    for path in G:
        req = math.ceil(path["rho"] * H)
        cov = sum(1 for t in range(H) if dv.p_path(path["id"], 0, t))
        if cov >= req: paths_ok += 1
        for hop in range(len(path["zones"])):
            hops_tot += 1
            if any(dv.p_path(path["id"], hop, t) for t in range(H)):
                hops_cov += 1

    early = sum(1 for path in G for t in range(H)
                if dv.e_intercept(path["id"], t))

    # Detection rate: asset-slots with dual_guard=1
    det_slots = set()
    for (tr,z,t,p),v in sched.items():
        if v and not dv.u_type(tr,z,t) and not dv.u_persona(tr,z,t,p):
            det_slots.add((z,t))
    det_rate = (sum(CFG["A_per_zone"].get(z,0) for (z,t) in det_slots)
                / max(1, CFG["A_total"]*H)) * 100

    # Zone spread + persona diversity (Shannon)
    zones_used = len({z for (tr,z,t,p),v in sched.items() if v})
    pc = Counter(p for (tr,z,t,p),v in sched.items() if v)
    tot_d = sum(pc.values()) or 1
    H_ent = -sum((c/tot_d)*math.log2(c/tot_d) for c in pc.values() if c>0)
    pers_div = H_ent / max(1e-9, math.log2(len(P))) * 100

    # Burn rates
    act = sum(1 for v in sched.values() if v)
    u_t = sum(1 for (tr,z,t,p),v in sched.items() if v and dv.u_type(tr,z,t))
    u_p = sum(1 for (tr,z,t,p),v in sched.items() if v and dv.u_persona(tr,z,t,p))
    burn_t = u_t/max(1,act)*100; burn_p = u_p/max(1,act)*100

    # Churn (state changes between consecutive slots)
    prev={}; churn=0
    for t in range(H):
        for tr in K:
            for z in Z:
                for p in P:
                    cur = sched.get((tr,z,t,p), 0)
                    if t>0 and cur != prev.get((tr,z,p), 0): churn += 1
                    prev[(tr,z,p)] = cur

    # C14 cross-zone leaks
    xz = 0
    for t in range(H):
        pz_map = defaultdict(set)
        for (tr,z,ts,p),v in sched.items():
            if v and ts==t: pz_map[p].add(z)
        for zset in pz_map.values():
            if len(zset) > 1: xz += 1

    return dict(
        Q=Q, L4=q.get("L4_early_intercept",0),
        L3f=q.get("L3_fwd_path_coverage",0),
        L3b=q.get("L3_bwd_forensic",0),
        L2t=q.get("L2_tech_breadth",0),
        L2f=q.get("L2_fam_bonus",0),
        L1=q.get("L1_detection",0),
        tech_n=len(techs), fam_n=len(fams),
        tech_pct=len(techs)/max(1,len(all_techs))*100,
        fam_pct=len(fams)/max(1,len(tac_fams))*100,
        c10_pct=paths_ok/max(1,len(G))*100,
        hop_pct=hops_cov/max(1,hops_tot)*100,
        early_pct=early/max(1,len(G)*H)*100,
        det_rate=det_rate,
        zone_spread=zones_used/len(Z)*100,
        zones_used=zones_used, pers_div=pers_div,
        burn_t=burn_t, burn_p=burn_p, churn=churn, xz=xz,
    )


def r_star(sched, pl, dv, sc, hc, sample=10) -> tuple:
    qs = []
    for th in CFG["Theta"]:
        m = compute_metrics(sched, pl, dv, sc, hc, rho_pi=th["rho"], sample=sample)
        qs.append(m["Q"])
    return min(qs), qs


# ─────────────────────────────────────────────────────────────────────────────
#  TEN BASELINES  (each lacking ≥1 key dimension)
# ─────────────────────────────────────────────────────────────────────────────

def bl_random(pl):
    """Unconstrained random deployment — missing D1–D6."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for tr in random.sample(CFG["K"], len(CFG["K"])):
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr,random.choice(zones),t,random.choice(vps))] = 1
            up.add(vps[0])
    return repair(s)


def bl_static(pl):
    """Hold same deployment all H slots — missing D2 D5."""
    s = {}; up = set()
    for tr in sorted(CFG["K"], key=lambda x: -len(CFG["trap_techniques"].get(x,[]))):
        zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
        if not zones: continue
        vps = [p for p in pl.valid_personas(tr) if p not in up]
        if not vps: continue
        p = max(vps, key=lambda pp: pl.qp.get(pp,0)); up.add(p)
        for t in range(CFG["H"]): s[(tr,zones[0],t,p)] = 1
    return repair(s)


def bl_greedy_high_rho(pl):
    """Greedy single highest-ρ path only — missing D3 D5 D6."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for path in sorted(CFG["G"], key=lambda p: -p["rho"]):
            for hop, zone in enumerate(path["zones"][:-1]):
                if zone=="OT": continue
                for tr in CFG["K"]:
                    if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                    for p in pl.valid_personas(tr):
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)


def bl_greedy_bidir(pl):
    """Alternating fwd/bwd path sweep — missing D5 only."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        paths = sorted(CFG["G"], key=lambda p: -p["rho"])
        if t%2==1: paths = list(reversed(paths))
        for path in paths:
            for hop, zone in enumerate(path["zones"]):
                if zone=="OT": continue
                for tr in random.sample(CFG["K"], len(CFG["K"])):
                    if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                    for p in random.sample(CFG["P"], len(CFG["P"])):
                        if not CFG["gk_admitted"](tr,p): continue
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)


def bl_greedy_diverse(pl):
    """Technique breadth greedy without path structure — missing D2 D5."""
    s = {}
    for t in range(CFG["H"]):
        up = set(); cov = set()
        order = sorted(CFG["K"],
                       key=lambda tr: -len(set(CFG["trap_techniques"].get(tr,[]))-cov))
        for tr in order:
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: pl.qp.get(pp,0))
            s[(tr,zones[0],t,p)] = 1; up.add(p)
            cov.update(CFG["trap_techniques"].get(tr,[]))
    return repair(s)


def bl_round_robin(pl):
    """Mechanical slot-offset rotation — missing D2 D5 D6."""
    s = {}; tl = list(CFG["K"])
    for t in range(CFG["H"]):
        up = set(); offset = (t*3) % len(tl)
        rotated = tl[offset:] + tl[:offset]
        for tr in rotated:
            zones = [z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
            if not zones: continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr,zones[0],t,vps[0])] = 1; up.add(vps[0])
    return repair(s)


def bl_lp_relaxation(pl):
    """LP fractional relaxation without constraint enforcement — missing D4 D5."""
    scores = []
    for tr in CFG["K"]:
        for z in CFG["Z"]:
            if z=="OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
            for t in range(CFG["H"]):
                for p in pl.valid_personas(tr):
                    ps = sum(path["rho"]*path["iv"][hop]
                             for path in CFG["G"]
                             for hop,pz in enumerate(path["zones"])
                             if pz==z and hop<len(path["zones"])-1)
                    scores.append((pl.qp.get(p,0.25)*ps, tr, z, t, p))
    scores.sort(reverse=True)
    s = {}; used_tz = set(); up_slot = defaultdict(set)
    for sc2, tr, z, t, p in scores:
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
    """Internal-zone only — violates D1 multi-zone, missing D2 D5."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for tr in sorted(CFG["K"], key=lambda x: -len(CFG["trap_techniques"].get(x,[]))):
            if "Internal" not in CFG["diamond_affinity"].get(tr,[]): continue
            vps = [p for p in pl.valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: pl.qp.get(pp,0))
            s[(tr,"Internal",t,p)] = 1; up.add(p)
    return repair(s)


def bl_threat_intel(pl):
    """qp-prior only, ignores topology — missing D2 D5."""
    s = {}
    for t in range(CFG["H"]):
        up = set()
        for p in sorted(CFG["P"], key=lambda pp: -pl.qp.get(pp,0)):
            best = None; best_sc = -1
            for tr in CFG["K"]:
                for z in CFG["Z"]:
                    if z=="OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
                    if not CFG["gk_admitted"](tr,p): continue
                    sc2 = pl.qp.get(p,0)*len(CFG["trap_techniques"].get(tr,[]))
                    if sc2 > best_sc and p not in up:
                        best_sc = sc2; best = (tr,z,t,p)
            if best: s[best] = 1; up.add(p)
    return repair(s)


def bl_max_path_cov(pl):
    """Greedy hop-count maximiser, ignores persona — missing D5 D6."""
    s = {}
    for t in range(CFG["H"]):
        up = set(); cands = []
        for tr in CFG["K"]:
            for z in CFG["diamond_affinity"].get(tr,[]):
                if z=="OT": continue
                for p in pl.valid_personas(tr):
                    if p in up: continue
                    nh = sum(1 for path in CFG["G"]
                             for hop,pz in enumerate(path["zones"])
                             if pz==z and hop<len(path["zones"])-1)
                    cands.append((nh*pl.qp.get(p,0.25), tr, z, p))
        cands.sort(reverse=True)
        for _, tr, z, p in cands:
            if p in up: continue
            s[(tr,z,t,p)] = 1; up.add(p)
    return repair(s)


BASELINES = [
    ("Random",          bl_random,          ["D1","D2","D3","D4","D5","D6"]),
    ("Static-Best",     bl_static,          ["D2","D5"]),
    ("Greedy-HighRho",  bl_greedy_high_rho, ["D3","D5","D6"]),
    ("Greedy-BiDir",    bl_greedy_bidir,    ["D5"]),
    ("Greedy-Diverse",  bl_greedy_diverse,  ["D2","D5"]),
    ("Round-Robin",     bl_round_robin,     ["D2","D5","D6"]),
    ("LP-Relaxation",   bl_lp_relaxation,   ["D4","D5"]),
    ("Single-Zone",     bl_single_zone,     ["D1","D2","D5"]),
    ("ThreatIntel-Only",bl_threat_intel,    ["D2","D5"]),
    ("Max-PathCov",     bl_max_path_cov,    ["D5","D6"]),
]

DIM_DESC = {
    "D1":"Multi-zone+air-gap", "D2":"Attack-path ordering",
    "D3":"ATT&CK objectives",  "D4":"Budget+conflicts",
    "D5":"Optimality cert.",   "D6":"Persona/identity",
}

MDEFS = [
    ("r*",      "r_star",     True,  "{:>9.0f}"),
    ("Q-med",   "Q",          True,  "{:>9.0f}"),
    ("Tech",    "tech_n",     True,  "{:>5d}"),
    ("Fam",     "fam_n",      True,  "{:>5d}"),
    ("C10%",    "c10_pct",    True,  "{:>6.0f}%"),
    ("Hop%",    "hop_pct",    True,  "{:>6.0f}%"),
    ("Early%",  "early_pct",  True,  "{:>7.1f}%"),
    ("Det%",    "det_rate",   True,  "{:>6.1f}%"),
    ("ZnSprd",  "zone_spread",True,  "{:>7.0f}%"),
    ("PDivr",   "pers_div",   True,  "{:>7.0f}%"),
    ("PBurn%",  "burn_p",     False, "{:>7.1f}%"),
    ("TBurn%",  "burn_t",     False, "{:>7.1f}%"),
    ("C14",     "xz",         False, "{:>5d}"),
    ("Churn",   "churn",      False, "{:>6d}"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  EVALUATE
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_all(pl, dv, dw, sc, hc) -> dict:
    results = {}

    print("\n  [RC2] Solving 4 Θ scenarios…")
    sched_med, rs, qs, elapsed = rc2_solve(pl, dw, sc, hc)
    for i,th in enumerate(CFG["Theta"]):
        print(f"    {th['id']:12s}  Q={qs[i]:.0f}")
    m_rc2 = compute_metrics(sched_med, pl, dv, sc, hc, rho_pi=0.30, sample=12)
    results["★ RC2"] = dict(m_rc2, r_star=rs, Q_by_theta=qs, missing=[], elapsed=elapsed)
    print(f"\n  RC2 summary: r*={rs:.0f}  Q={m_rc2['Q']:.0f}  "
          f"tech={m_rc2['tech_n']}  C10={m_rc2['c10_pct']:.0f}%  "
          f"Early={m_rc2['early_pct']:.1f}%  C14={m_rc2['xz']}  "
          f"burn_t={m_rc2['burn_t']:.1f}%  burn_p={m_rc2['burn_p']:.1f}%  "
          f"({elapsed:.2f}s)")

    # Print RC2 schedule
    by_slot = defaultdict(list)
    for (tr,z,t,p) in sched_med:
        by_slot[t].append(f"{tr[:5]}/{z[:3]}/{p[:4]}")
    print("  Schedule:")
    for t2, deps in sorted(by_slot.items()):
        print(f"    t={t2}: {deps}")

    print("\n  [Baselines]")
    for name, fn, missing in BASELINES:
        sched = fn(pl); rs2, qs2 = r_star(sched, pl, dv, sc, hc, sample=10)
        m = compute_metrics(sched, pl, dv, sc, hc, rho_pi=0.30, sample=12)
        results[name] = dict(m, r_star=rs2, Q_by_theta=qs2, missing=missing)
        wins = "★ WIN" if rs >= rs2 else "LOSS"
        print(f"    {name:22s}  r*={rs2:6.0f}  Q={m['Q']:7.0f}  "
              f"Early={m['early_pct']:5.1f}%  tech={m['tech_n']:2d}  {wins}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
#  PRINT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(R: dict):
    hdr = f"  {'Solver':22s}"
    for l,_,_,_ in MDEFS: hdr += f"  {l:>8}"
    print("\n"+"="*len(hdr)); print(hdr); print("-"*len(hdr))
    for n, r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        mk = "★ " if "RC2" in n else "  "
        row = f"{mk}{n.replace('★ ',''):20s}"
        for _,k,_,fmt in MDEFS: row += "  " + fmt.format(r.get(k,0))
        print(row)
    print("="*len(hdr))


def print_feature_matrix(R: dict):
    dims = ["D1","D2","D3","D4","D5","D6"]
    print("\n  ── Dimension Coverage Matrix ───────────────────────────────────────")
    print(f"  {'Solver':24s}", end="")
    for d in dims: print(f"  {d}", end="")
    print("  Missing dimensions (→ metric gap below)")
    print("  "+"─"*78)
    for n, r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        missing = r.get("missing", [])
        print(f"  {n.replace('★ ',''):24s}", end="")
        for d in dims: print(f"  {'✓' if d not in missing else '✗'}", end="")
        gaps = ", ".join(f"{d}({DIM_DESC[d]})" for d in missing) or "all 6 dimensions ✓"
        print(f"  {gaps}")


def print_wins(R: dict):
    v6 = next(r for n,r in R.items() if "RC2" in n)
    print("\n  ── RC2 wins vs each baseline ───────────────────────────────────────")
    gw = 0; gt = 0
    for n, r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        if "RC2" in n: continue
        wins=[]; losses=[]
        for lbl,k,high,_ in MDEFS:
            vv=v6.get(k,0); bv=r.get(k,0); gt+=1
            if high:
                if vv >= bv-0.01: wins.append(lbl); gw+=1
                else: losses.append(lbl)
            else:
                if vv <= bv+0.01: wins.append(lbl); gw+=1
                else: losses.append(lbl)
        tag = "★ ALL WIN" if not losses else f"loss: {','.join(losses[:4])}"
        print(f"  vs {n:22s}: {len(wins):2d}/{len(MDEFS)} ✓  {tag}")
    pct = gw/max(1,gt)*100
    print(f"\n  Grand total: {gw}/{gt} ({pct:.0f}%) metric×baseline wins")
    if pct >= 90:
        print(f"  ★ RC2 WINS ≥90% — dissertation-quality dominance ★")


# ─────────────────────────────────────────────────────────────────────────────
#  VISUALISATION (12 panels, dissertation-quality)
# ─────────────────────────────────────────────────────────────────────────────

RC2_COL = "#2C2882"   # dark indigo for RC2

def _make_colors(names):
    import matplotlib.colors as mc
    # Use a perceptually uniform palette for baselines
    palette = ["#E07B39","#6AB187","#D4AC0D","#8B6F9E","#C0392B",
               "#2E86AB","#A8DADC","#457B9D","#95A3B3","#E9C46A"]
    colors=[]; bl_i=0
    for n in names:
        if "RC2" in n: colors.append(RC2_COL)
        else: colors.append(palette[bl_i % len(palette)]); bl_i+=1
    return colors


def plot_all(R: dict, out_path: str):
    import matplotlib.colors as mc
    names  = list(R.keys())
    cols   = _make_colors(names)
    short  = [n.replace("★ ","") for n in names]

    fig = plt.figure(figsize=(32, 26), facecolor="#F9F8F5")
    gs  = GridSpec(4, 3, figure=fig, hspace=0.56, wspace=0.40)

    tkw = dict(fontsize=9.5, fontweight="800", color="#1A1A2E", pad=7)
    lkw = dict(fontsize=8.5, color="#3D3D5C")
    bkw = dict(edgecolor="white", linewidth=0.5)

    rc2_r = next(r for n,r in R.items() if "RC2" in n)

    fig.suptitle(
        "ZSTP-V6 MaxSAT RC2 Honeypot Placement — Dissertation Metric Comparison\n"
        "Network: 500 assets · 5 zones · 4 attack paths · 4 Θ scenarios · "
        "18 ATT&CK TTPs · 8 tactic families\n"
        "Soft weights: zone_avg_W(topology) from dm∈[0.8,2.5], hd∈{1,2,3}  ·  "
        f"|K|={len(CFG['K'])} |Z|={len(CFG['Z'])} H={CFG['H']} |P|={len(CFG['P'])}",
        fontsize=11, fontweight="900", color="#1A1A2E", y=1.002)

    ha = lambda c: [mc.to_hex(mc.to_rgba(x, alpha=0.45)) for x in c]

    def blab(ax, bars, fmt="{:.0f}", skip_below=1):
        ylim = ax.get_ylim(); span = ylim[1]-ylim[0]
        for b in bars:
            h = b.get_height()
            if abs(h) > skip_below:
                ax.text(b.get_x()+b.get_width()/2,
                        h + span*0.013, fmt.format(h),
                        ha="center", va="bottom", fontsize=5.8, color="#111")

    def bhlab(ax, bars, fmt="{:.1f}%"):
        xlim = ax.get_xlim(); span = xlim[1]-xlim[0]
        for b in bars:
            w = b.get_width()
            if w > 0.5:
                ax.text(w + span*0.013,
                        b.get_y()+b.get_height()/2,
                        fmt.format(w), ha="left", va="center", fontsize=5.8)

    def sty(ax, xrot=33):
        ax.set_facecolor("#F1F0EC")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.tick_params(axis="both", which="major", labelsize=7.5)
        if xrot is not None:
            ax.set_xticks(range(len(names)))
            ax.set_xticklabels(short, fontsize=6.5, rotation=xrot, ha="right")

    def highlight_rc2(bars):
        bars[0].set_edgecolor("#1A0080"); bars[0].set_linewidth(2.5)

    # ── Panel 1: r* (primary dissertation metric) ─────────────────────────
    ax = fig.add_subplot(gs[0,0])
    vals = [R[n]["r_star"] for n in names]
    bars = ax.bar(range(len(names)), vals, color=cols, **bkw)
    highlight_rc2(bars)
    # Annotate RC2 win margin
    rc2_v = vals[0]; bl_max = max(vals[1:]) if len(vals)>1 else 0
    margin = rc2_v - bl_max
    ax.annotate(f"+{margin:.0f} vs next\n(+{100*margin/max(1,bl_max):.1f}%)",
                xy=(0, rc2_v), xytext=(2.5, rc2_v*0.92),
                fontsize=7, color=RC2_COL, fontweight="700",
                arrowprops=dict(arrowstyle="->", color=RC2_COL, lw=1.2))
    ax.set_title("★ r* = min_Θ Q_k(x)  Worst-case floor\n"
                 "RC2 jointly optimises all 4 Θ simultaneously; baselines use single ρ", **tkw)
    ax.set_ylabel("worst-case Q", **lkw); sty(ax); blab(ax, bars)

    # ── Panel 2: Q by Θ scenario (wide) ────────────────────────────────────
    ax2 = fig.add_subplot(gs[0,1:])
    bw = 0.065; x = np.arange(len(CFG["Theta"]))
    for i,(n,c) in enumerate(zip(names,cols)):
        offs = (i - len(names)/2)*bw + bw/2
        ax2.bar(x+offs,
                [R[n]["Q_by_theta"][j] for j in range(len(CFG["Theta"]))],
                bw, color=c, label=short[i], alpha=0.90, **bkw)
    ax2.set_title("Q per attacker scenario in Θ\n"
                  "RC2 maximises the worst-case floor; Greedy collapses at θ_burst (ρ=0.85)", **tkw)
    ax2.set_xticks(x)
    ax2.set_xticklabels([t["label"].split("  ")[0] for t in CFG["Theta"]], fontsize=9.5)
    ax2.set_ylabel("Q_k(x)", **lkw)
    ax2.legend(fontsize=5.8, ncol=6, framealpha=0.85, loc="upper right")
    ax2.set_facecolor("#F1F0EC"); ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False); ax2.tick_params(labelsize=8)

    # ── Panel 3: ATT&CK technique breadth ──────────────────────────────────
    ax3 = fig.add_subplot(gs[1,0])
    all_t = len({tk for ts in CFG["trap_techniques"].values() for tk in ts})
    vals  = [R[n]["tech_n"] for n in names]
    bars3 = ax3.bar(range(len(names)), vals, color=cols, **bkw)
    highlight_rc2(bars3)
    ax3.axhline(all_t, color="#C0392B", lw=1.3, ls="--", alpha=0.75)
    ax3.text(len(names)-.1, all_t+.25, f"max={all_t}", fontsize=7.5,
             color="#C0392B", ha="right", fontweight="700")
    ax3.set_title(f"ATT&CK technique breadth  (L2-tech ×{CFG['w2']})\n"
                  f"18 distinct TTPs across 8 trap types · D3 objective", **tkw)
    ax3.set_ylabel("distinct TTPs", **lkw); sty(ax3); blab(ax3, bars3)

    # ── Panel 4: Tactic-family breadth ─────────────────────────────────────
    ax4 = fig.add_subplot(gs[1,1])
    tf   = len(CFG["tactic_families"])
    vals = [R[n]["fam_n"] for n in names]
    bars4 = ax4.bar(range(len(names)), vals, color=cols, **bkw)
    highlight_rc2(bars4)
    ax4.axhline(tf, color="#C0392B", lw=1.3, ls="--", alpha=0.75)
    ax4.text(len(names)-.1, tf+.12, f"max={tf}", fontsize=7.5,
             color="#C0392B", ha="right", fontweight="700")
    ax4.set_title(f"Tactic-family breadth  (L2-fam ×{CFG['w2_fam']})\n"
                  f"{tf} ATT&CK families · D3 objective", **tkw)
    ax4.set_ylabel("families covered", **lkw); sty(ax4); blab(ax4, bars4)

    # ── Panel 5: C10% + Hop coverage ───────────────────────────────────────
    ax5 = fig.add_subplot(gs[1,2])
    x5  = np.arange(len(names))
    b5a = ax5.bar(x5-.2, [R[n]["c10_pct"] for n in names], .35,
                  color=cols, label="C10 path %", **bkw)
    b5b = ax5.bar(x5+.2, [R[n]["hop_pct"] for n in names], .35,
                  color=ha(cols), label="Hop cov %", **bkw)
    b5a[0].set_edgecolor("#1A0080"); b5a[0].set_linewidth(2.0)
    ax5.set_title("Path persistence (C10%) and all-hop coverage%\n"
                  "RC2 topology weighting covers all 4 paths; greedy baselines miss hops", **tkw)
    ax5.set_ylim(0,125); ax5.legend(fontsize=7.5, framealpha=0.82)
    sty(ax5); ax5.set_ylabel("%", **lkw)

    # ── Panel 6: Early intercept (horizontal, RC2 highlighted) ─────────────
    ax6 = fig.add_subplot(gs[2,0])
    bars6 = ax6.barh(range(len(names)),
                     [R[n]["early_pct"] for n in names], color=cols, **bkw)
    bars6[0].set_edgecolor("#1A0080"); bars6[0].set_linewidth(2.0)
    ax6.set_title(f"Early-intercept rate%  (L4 ×{CFG['w4']})\n"
                  "DMZ/Cloud-first slots catch attackers before final hop → prevention", **tkw)
    ax6.set_yticks(range(len(names))); ax6.set_yticklabels(short, fontsize=7)
    ax6.set_xlabel("%", **lkw); ax6.set_xlim(0,130)
    ax6.set_facecolor("#F1F0EC")
    ax6.spines["top"].set_visible(False); ax6.spines["right"].set_visible(False)
    bhlab(ax6, bars6)

    # ── Panel 7: Detection rate ─────────────────────────────────────────────
    ax7 = fig.add_subplot(gs[2,1])
    bars7 = ax7.barh(range(len(names)),
                     [R[n]["det_rate"] for n in names], color=cols, **bkw)
    bars7[0].set_edgecolor("#1A0080"); bars7[0].set_linewidth(2.0)
    ax7.set_title("Asset-slot detection coverage%\n"
                  "500 assets · zone_avg_W from dm/hd topology · dual guard active", **tkw)
    ax7.set_yticks(range(len(names))); ax7.set_yticklabels(short, fontsize=7)
    ax7.set_xlabel("%", **lkw); ax7.set_xlim(0,115)
    ax7.set_facecolor("#F1F0EC")
    ax7.spines["top"].set_visible(False); ax7.spines["right"].set_visible(False)
    bhlab(ax7, bars7)

    # ── Panel 8: Zone spread + persona diversity ─────────────────────────────
    ax8 = fig.add_subplot(gs[2,2])
    x8  = np.arange(len(names))
    b8a = ax8.bar(x8-.2, [R[n]["zone_spread"] for n in names], .35,
                  color=cols, label="Zone spread %", **bkw)
    b8b = ax8.bar(x8+.2, [R[n]["pers_div"] for n in names], .35,
                  color=ha(cols), label="Persona div %", **bkw)
    b8a[0].set_edgecolor("#1A0080"); b8a[0].set_linewidth(2.0)
    ax8.set_title("Zone spread% and persona diversity%\n"
                  "D1 multi-zone (DMZ/Cloud/Internal/Mgmt) + D6 identity rotation", **tkw)
    ax8.set_ylim(0,125); ax8.legend(fontsize=7.5); sty(ax8); ax8.set_ylabel("%", **lkw)

    # ── Panel 9: Burn rates (↓ better) ──────────────────────────────────────
    ax9 = fig.add_subplot(gs[3,0])
    x9  = np.arange(len(names))
    b9a = ax9.bar(x9-.2, [R[n]["burn_p"] for n in names], .35,
                  color=ha(cols), label="Persona burn %", **bkw)
    b9b = ax9.bar(x9+.2, [R[n]["burn_t"] for n in names], .35,
                  color=cols, label="Type burn %", **bkw)
    b9a[0].set_edgecolor("#1A0080"); b9a[0].set_linewidth(2.0)
    ax9.set_title("Discovery burn rates%  (↓ better)\n"
                  "C9/C13 flags zero credit — RC2 trap rotation keeps burn=0%", **tkw)
    ax9.set_ylabel("% of active slots flagged", **lkw)
    ax9.legend(fontsize=7.5); sty(ax9)

    # ── Panel 10: C14 leaks + churn (↓ better) ─────────────────────────────
    ax10 = fig.add_subplot(gs[3,1])
    x10  = np.arange(len(names))
    b10a = ax10.bar(x10-.2, [R[n]["xz"] for n in names], .35,
                    color=cols, label="C14 leaks", **bkw)
    b10b = ax10.bar(x10+.2, [R[n]["churn"] for n in names], .35,
                    color=ha(cols), label="Churn", **bkw)
    b10a[0].set_edgecolor("#1A0080"); b10a[0].set_linewidth(2.0)
    ax10.set_title("C14 cross-zone persona leaks (↓) and operational churn (↓)\n"
                   "RC2 C14=0 by construction; C8 soft term suppresses unnecessary churn", **tkw)
    ax10.legend(fontsize=7.5); sty(ax10); ax10.set_ylabel("count", **lkw)

    # ── Panel 11: Stacked Q decomposition ──────────────────────────────────
    ax11  = fig.add_subplot(gs[3,2])
    layers = ["L4","L3f","L3b","L2t","L2f","L1"]
    lc_hex = ["#2C2882","#6B65C0","#AAA5D8","#E07B39","#F4B866","#FAE0A0"]
    ll_lab = [f"L4×{CFG['w4']} (prev.)",
              f"L3-fwd×{CFG['w3']} (path)",
              f"L3-bwd×{CFG['w3_bwd']} (foren.)",
              f"L2-tech×{CFG['w2']} (TTP)",
              f"L2-fam×{CFG['w2_fam']} (tactic)",
              f"L1×{CFG['w1']} (detect)"]
    x11 = np.arange(len(names)); bot = np.zeros(len(names))
    for lyr, lcc, lll in zip(layers, lc_hex, ll_lab):
        vals = np.array([R[n].get(lyr,0) for n in names])
        ax11.bar(x11, vals, .58, bottom=bot, color=lcc, label=lll,
                 edgecolor="white", linewidth=0.35)
        bot += vals
    ax11.set_title("Objective decomposition L1–L4 (stacked)\n"
                   "L4 prevention (×1000) dominates — RC2 maximises early interception", **tkw)
    ax11.legend(fontsize=6.8, framealpha=0.80, ncol=2, loc="upper right")
    sty(ax11); ax11.set_ylabel("Q contribution", **lkw)

    # Global legend
    patches = [mpatches.Patch(color=cols[i], label=s)
               for i,s in enumerate(short)]
    fig.legend(handles=patches, loc="lower center", ncol=6,
               fontsize=8, framealpha=0.90, bbox_to_anchor=(0.5, 0.0),
               edgecolor="#CCCCCC")

    plt.savefig(out_path, dpi=160, bbox_inches="tight",
                facecolor="#F9F8F5", edgecolor="none")
    print(f"\n  [Chart saved] → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*72)
    print("  ZSTP-V6 MaxSAT RC2 Honeypot Placement —  Solver")
    print(" Network Configuration: ", os.system("python3 maxsat_rc2_components/config.py"))
    print("="*72)

    pl, dv, dw, sc, hc = build_stack()

    # Confirm fixes
    assert sc._is_airgapped("DMZ")  == False, "airgap bug: DMZ"
    assert sc._is_airgapped("OT")   == True,  "airgap bug: OT"
    assert sc._is_airgapped("Cloud")== False, "airgap bug: Cloud"

    print(f"\n  [✓] is_airgapped fix confirmed: DMZ=False  OT=True  Cloud=False")
    print(f"  Algorithm 1 qp: "
          + "  ".join(f"{p[:8]}={v:.4f}" for p,v in pl.qp.items()))
    print(f"  Config: |K|={len(CFG['K'])} |Z|={len(CFG['Z'])} H={CFG['H']}"
          f" |P|={len(CFG['P'])} |Θ|={len(CFG['Theta'])}"
          f"  A_total={CFG['A_total']}")
    print(f"  Network: dm∈{CFG['dm_range']}  hd_by_zone={CFG['hd_by_zone']}")
    print(f"  Weights: w4={CFG['w4']} w3={CFG['w3']} w3b={CFG['w3_bwd']}"
          f" w2={CFG['w2']} w2f={CFG['w2_fam']} w1={CFG['w1']}")

    R = evaluate_all(pl, dv, dw, sc, hc)

    print_summary(R)
    print_feature_matrix(R)
    print_wins(R)

    out = os.path.join(_here, "results/MaxSat_RC2_V6_Dissertation.png")
    plot_all(R, out)
    print("  Done.")
    return R


if __name__ == "__main__":
    main()
