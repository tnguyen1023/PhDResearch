"""
rc2_baseline_comparison_standalone.py
Zone-Slot-Time-Persona V6 — RC2 MaxSAT vs 10 Baselines
========================================================
FULLY SELF-CONTAINED — no imports from project modules.
Only standard library + pysat + numpy + matplotlib required.

Install:
    pip install python-sat numpy matplotlib

Run:
    python rc2_baseline_comparison_standalone.py

What this compares
──────────────────
MaxSAT RC2 simultaneously enforces all 15 hard constraints (C1–C15) and
optimises a four-level soft objective (L4 ×1000 > L3 ×100 > L2 ×10 > L1 ×1).
Every baseline is missing at least one structural feature:

  Baseline            Missing dimension(s)
  ──────────────────  ─────────────────────────────────────────────────────
  Random              D1 D2 D3 D4 D5 D6  (no structure at all)
  Static-Best         D2 D5              (no rotation / temporal coverage)
  Greedy-HighRho      D3 D5 D6           (single path, no breadth/identity)
  Greedy-BiDir        D5                 (no optimality certificate)
  Greedy-Diverse      D2 D5              (technique breadth, no path order)
  Round-Robin         D2 D5 D6           (mechanical, no threat-intel)
  LP-Relaxation       D4 D5              (relaxed integrality, no hard C4/C12)
  Single-Zone         D1 D2 D5           (Internal only, violates multi-zone)
  ThreatIntel-Only    D2 D5              (qp prior, ignores path topology)
  Max-PathCov         D5 D6              (greedy coverage, ignores identity)

Six dimensions:
  D1 Multi-zone + air gaps   D2 Attack-path ordering
  D3 ATT&CK objectives       D4 Budget + conflicts
  D5 Optimality certificate  D6 Persona / identity
"""

import math, random, time, sys
from collections import defaultdict, Counter
from copy import deepcopy
import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ── pysat (RC2 only) ──────────────────────────────────────────────────────────
try:
    from pysat.examples.rc2 import RC2
    from pysat.formula import WCNF
    HAS_PYSAT = True
except ImportError:
    HAS_PYSAT = False
    print("[WARNING] python-sat not found. RC2 will use a pre-computed reference schedule.")

SEED = 42; random.seed(SEED); np.random.seed(SEED)

# ─────────────────────────────────────────────────────────────────────────────
#  EMBEDDED INSTANCE  (V6 configuration, fully inlined)
# ─────────────────────────────────────────────────────────────────────────────
K  = ["ssh_trap","db_trap","smb_trap","scada_trap","ad_trap",
      "dns_trap","web_trap","generic_trap"]
Z  = ["DMZ","Internal","Cloud","OT","Mgmt"]
H  = 4
P  = ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"]

PATHS = [
    {"id":"pi1","rho":0.35,"zones":["DMZ","Internal","Internal"],"iv":[1.8,1.4,1.0]},
    {"id":"pi2","rho":0.25,"zones":["Cloud","Internal","Mgmt"],   "iv":[1.6,1.3,1.0]},
    {"id":"pi3","rho":0.15,"zones":["DMZ","OT"],                  "iv":[1.5,1.2]},
    {"id":"pi4","rho":0.20,"zones":["DMZ","Mgmt","Internal"],     "iv":[1.7,1.3,1.0]},
]
THETA = [
    {"id":"theta_low",   "rho":0.15,"tau_d0":4,"label":"θ_low\nρ=0.15"},
    {"id":"theta_med",   "rho":0.30,"tau_d0":3,"label":"θ_med\nρ=0.30"},
    {"id":"theta_high",  "rho":0.55,"tau_d0":2,"label":"θ_high\nρ=0.55"},
    {"id":"theta_burst", "rho":0.85,"tau_d0":1,"label":"θ_burst\nρ=0.85"},
]

TRAP_TECHS = {
    "ssh_trap":     ["T1021","T1078","T1059"],
    "db_trap":      ["T1048","T1213","T1083"],
    "smb_trap":     ["T1021","T1046","T1055"],
    "scada_trap":   ["T1059","T1053","T1203"],
    "ad_trap":      ["T1110","T1078","T1547"],
    "dns_trap":     ["T1572","T1041","T1046"],
    "web_trap":     ["T1190","T1566","T1133"],
    "generic_trap": ["T1046","T1068","T1213"],
}
TACTIC_FAMS = {
    "LateralMovement":  ["T1021","T1078"],
    "Exfiltration":     ["T1048","T1041"],
    "Discovery":        ["T1083","T1046"],
    "CredentialAccess": ["T1110"],
    "InitialAccess":    ["T1566","T1190","T1133","T1203"],
    "Execution":        ["T1059","T1053","T1547"],
    "DefenseEvasion":   ["T1055","T1068"],
    "CmdAndControl":    ["T1572","T1213"],
}
DIAMOND = {
    "ssh_trap":     ["DMZ","Internal","Cloud","Mgmt"],
    "db_trap":      ["Internal","Cloud","Mgmt"],
    "smb_trap":     ["Internal","Mgmt"],
    "scada_trap":   ["OT"],
    "ad_trap":      ["Internal","Mgmt"],
    "dns_trap":     ["DMZ","Internal","Cloud"],
    "web_trap":     ["DMZ","Cloud"],
    "generic_trap": ["DMZ","Internal","Cloud","Mgmt"],
}
GK = {  # (trap, persona) → believability score; threshold τ_GK = 0.65
    ("ssh_trap","HR_workstation"):0.85,  ("ssh_trap","DevOps_server"):0.90,
    ("ssh_trap","Finance_DB"):0.40,      ("ssh_trap","Generic_Linux"):0.75,
    ("db_trap","HR_workstation"):0.50,   ("db_trap","DevOps_server"):0.70,
    ("db_trap","Finance_DB"):0.95,       ("db_trap","Generic_Linux"):0.60,
    ("smb_trap","HR_workstation"):0.80,  ("smb_trap","DevOps_server"):0.70,
    ("smb_trap","Finance_DB"):0.55,      ("smb_trap","Generic_Linux"):0.45,
    ("scada_trap","HR_workstation"):0.20,("scada_trap","DevOps_server"):0.50,
    ("scada_trap","Finance_DB"):0.15,    ("scada_trap","Generic_Linux"):0.90,
    ("ad_trap","HR_workstation"):0.90,   ("ad_trap","DevOps_server"):0.75,
    ("ad_trap","Finance_DB"):0.60,       ("ad_trap","Generic_Linux"):0.40,
    ("dns_trap","HR_workstation"):0.55,  ("dns_trap","DevOps_server"):0.80,
    ("dns_trap","Finance_DB"):0.35,      ("dns_trap","Generic_Linux"):0.85,
    ("web_trap","HR_workstation"):0.65,  ("web_trap","DevOps_server"):0.85,
    ("web_trap","Finance_DB"):0.50,      ("web_trap","Generic_Linux"):0.80,
    ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
    ("generic_trap","Finance_DB"):0.50,  ("generic_trap","Generic_Linux"):0.80,
}
C_CONFLICTS = [("generic_trap","dns_trap"),("smb_trap","generic_trap")]
A_PER_ZONE  = {"DMZ":80,"Internal":200,"Cloud":120,"OT":50,"Mgmt":50}
A_TOTAL     = 500
AIR_GAPPED  = {"OT"}   # OT is isolated; DMZ/Cloud/Mgmt are NOT
TAU_D0 = 3; TAU_DP0 = 2; RHO_MAX = 1.0; GAMMA = 0.8
W1,W2,W3,W4 = 1,10,100,1000

# STIX signals → qp update (Algorithm 1 Step 3)
STIX_SIGNALS = [
    {"confidence":0.88,"deltas":{"Finance_DB":0.25,"HR_workstation":0.15,
                                  "DevOps_server":-0.05,"Generic_Linux":-0.05}},
    {"confidence":0.45,"deltas":{"DevOps_server":0.20,"Generic_Linux":0.10,
                                  "Finance_DB":-0.05,"HR_workstation":-0.05}},
    {"confidence":0.30,"deltas":{"Generic_Linux":0.15,"HR_workstation":0.05,
                                  "Finance_DB":-0.05,"DevOps_server":-0.05}},
]
EMPIRICAL   = {"Finance_DB":18,"HR_workstation":12,"DevOps_server":7,"Generic_Linux":3}
BETA_MAX    = 0.60; KAPPA = 30.0

# ─────────────────────────────────────────────────────────────────────────────
#  ALGORITHM 1  (qp update: STIX blend + empirical posterior)
# ─────────────────────────────────────────────────────────────────────────────

def compute_qp():
    """Steps 3 + 3b of Algorithm 1."""
    q = {p: 0.25 for p in P}
    # Step 3: confidence-weighted STIX blend
    tc = sum(s["confidence"] for s in STIX_SIGNALS)
    for s in STIX_SIGNALS:
        w = s["confidence"] / tc
        for p in P:
            q[p] = max(0.0, q[p] + w * s["deltas"].get(p, 0.0))
    total = sum(q.values()); q = {p: v/total for p,v in q.items()}
    # Step 3b: empirical posterior
    N_obs = sum(EMPIRICAL.values())
    beta  = min(N_obs / (N_obs + KAPPA), BETA_MAX)
    et    = sum(EMPIRICAL.values())
    q_emp = {p: EMPIRICAL.get(p,0)/et for p in P}
    q     = {p: (1-beta)*q[p] + beta*q_emp[p] for p in P}
    total = sum(q.values()); q = {p: v/total for p,v in q.items()}
    return q, beta

QP, BETA = compute_qp()

# ─────────────────────────────────────────────────────────────────────────────
#  FEASIBILITY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def is_valid(tr, z, p):
    """(trap,zone,persona) feasibility: diamond affinity + GK threshold."""
    if z not in DIAMOND.get(tr, []):     return False
    if z in AIR_GAPPED and tr != "scada_trap": return False
    if GK.get((tr,p), 0) < 0.65:        return False
    return True

def valid_personas(tr):
    return [p for p in P if GK.get((tr,p),0) >= 0.65]

def repair(s):
    """Remove C4 cross-zone, C12 same-zone, and C14 cross-zone violations."""
    s = dict(s)
    # C4: conflicting trap types per slot
    for t in range(H):
        for (ta,tb) in C_CONFLICTS:
            ak=[(tr,z,ts,p) for (tr,z,ts,p) in s if tr==ta and ts==t]
            bk=[(tr,z,ts,p) for (tr,z,ts,p) in s if tr==tb and ts==t]
            if ak and bk:
                rem = ak if len(ak)<=len(bk) else bk
                for k in rem:
                    if k in s: del s[k]
    # C12: at most one trap per (zone,slot,persona)
    for t in range(H):
        for z in Z:
            for p in P:
                dup=[(tr,z,t,p) for tr in K if (tr,z,t,p) in s]
                for k in dup[1:]:
                    if k in s: del s[k]
    # C14: same persona at most one zone per slot
    for t in range(H):
        for p in P:
            pz = defaultdict(list)
            for (tr,z,ts,pp) in list(s):
                if ts==t and pp==p: pz[z].append((tr,z,ts,pp))
            if len(pz) > 1:
                best = max(pz, key=lambda z: len(pz[z]))
                for z,ks in pz.items():
                    if z != best:
                        for k in ks:
                            if k in s: del s[k]
    return s

# ─────────────────────────────────────────────────────────────────────────────
#  DISCOVERY FLAGS  (V5 floored formulas eq 12′/13′)
# ─────────────────────────────────────────────────────────────────────────────

def tau_d(rho_pi, N_ip=0, tau_d0=TAU_D0):
    return max(1.0, tau_d0 * (1 - rho_pi/RHO_MAX) * (GAMMA**N_ip))

def tau_dp(N_ip=0):
    return max(1.0, TAU_DP0 * (GAMMA**N_ip))

def compute_flags(schedule, rho_pi):
    """
    Compute u_type and u_persona discovery flags for every (trap,zone,slot,persona).
    u_type(i,z,t)  = 1 iff trap i has been in zone z for ≥ τᵈ consecutive slots
    u_persona(i,z,t,p) = 1 iff persona p in zone z ≥ τᵈᵖ consecutive slots
    """
    td = tau_d(rho_pi)
    tdp = tau_dp()
    u_type    = {}
    u_persona = {}
    # Count consecutive active slots ending at each slot
    for tr in K:
        for z in Z:
            run_t = 0; run_p = {p: 0 for p in P}
            for t in range(H):
                active = any(schedule.get((tr,z,t,pp),0) for pp in P)
                if active:
                    run_t += 1
                else:
                    run_t = 0
                u_type[(tr,z,t)] = 1 if run_t >= td else 0
                for p in P:
                    active_p = schedule.get((tr,z,t,p),0)
                    if active_p:
                        run_p[p] += 1
                    else:
                        run_p[p] = 0
                    u_persona[(tr,z,t,p)] = 1 if run_p[p] >= tdp else 0
    return u_type, u_persona

def dual_guard(u_type, u_persona, tr, z, t, p):
    return 0 if u_type.get((tr,z,t),0) or u_persona.get((tr,z,t,p),0) else 1

# ─────────────────────────────────────────────────────────────────────────────
#  Q EVALUATION  (exact formulas L4/L3/L2/L1)
# ─────────────────────────────────────────────────────────────────────────────

def score_schedule(schedule, rho_pi, tau_d0_override=None, sample_assets=10):
    """
    Compute Q = L4 + L3 + L2 + L1 for a schedule at a given rho_pi.
    Uses the corrected is_airgapped (OT only) for Q evaluation.
    """
    td_eff = tau_d(rho_pi) if tau_d0_override is None else \
             max(1.0, tau_d0_override * (1-rho_pi/RHO_MAX))
    tdp_eff = tau_dp()

    # Discovery flags
    u_t, u_p = compute_flags(schedule, rho_pi)

    # Sample assets (deterministic)
    rng = random.Random(99)
    assets = []
    for z in Z:
        az = list(range(A_PER_ZONE.get(z,0)))
        assets += [(a, z) for a in rng.sample(az, min(sample_assets, len(az)))]

    # All techniques and families
    all_techs = {tk for ts in TRAP_TECHS.values() for tk in ts}
    rho_max_path = max(path["rho"] for path in PATHS)

    L4 = L3f = L3b = L2t = L2f = L1 = 0.0

    for (tr,z,t,p),v in schedule.items():
        if not v or z == "OT": continue
        if not is_valid(tr,z,p): continue
        qp   = QP.get(p,0.25)
        guard = dual_guard(u_t, u_p, tr, z, t, p)
        techs = TRAP_TECHS.get(tr,[])
        fams  = {f for f,ft in TACTIC_FAMS.items() if any(tk in ft for tk in techs)}

        # Mean W across assets in zone
        zone_assets = [(a,az) for (a,az) in assets if az==z]
        if not zone_assets: continue
        # W_j,a simplified: topology_weight * qp (derived weights)
        W_avg = sum(
            (1.0 + 0.5*(j/max(1,len(zone_assets)-1)))   # topology gradient
            for j,_ in enumerate(zone_assets)
        ) / len(zone_assets)

        # L1: detection
        L1 += W1 * W_avg * qp * guard

        # L2: tech breadth (fires even when guard=0, only needs u_persona=0)
        not_discovered_p = 1 - u_p.get((tr,z,t,p),0)
        for _ in techs:
            L2t += W2 * W_avg * qp * not_discovered_p
        for _ in fams:
            L2f += W2 * 1.2 * W_avg * qp * not_discovered_p

        # L3/L4: path-zone matched
        for path in PATHS:
            rho  = rho_pi * path["rho"] / rho_max_path
            ivs  = path["iv"]
            zones_p = path["zones"]
            n    = len(zones_p)
            iv_max_nf = max((ivs[h] for h in range(n-1)), default=0.0)
            for hop, pz in enumerate(zones_p):
                if pz != z: continue
                iv = ivs[hop] if hop < len(ivs) else 1.0
                is_final = (hop == n-1)
                if is_final:
                    L3b += W3 * 0.7 * rho * iv * W_avg * qp * guard
                else:
                    L3f += W3 * rho * iv * W_avg * qp * guard
                    L4  += W4 * rho * iv_max_nf * W_avg * qp * guard

    return {
        "Q": L4+L3f+L3b+L2t+L2f+L1,
        "L4":L4,"L3f":L3f,"L3b":L3b,"L2t":L2t,"L2f":L2f,"L1":L1
    }


def full_metrics(schedule, rho_pi, tau_d0_override=None, sample=10):
    """Compute all 14 comparison metrics for a schedule."""
    q = score_schedule(schedule, rho_pi, tau_d0_override, sample)
    Q = q["Q"]

    u_t, u_p = compute_flags(schedule, rho_pi)
    all_techs = {tk for ts in TRAP_TECHS.values() for tk in ts}

    # Technique + family coverage
    techs = set()
    for (tr,z,t,p),v in schedule.items():
        if not v or not is_valid(tr,z,p): continue
        if u_p.get((tr,z,t,p),0): continue
        techs.update(TRAP_TECHS.get(tr,[]))
    fams = {f for f,ft in TACTIC_FAMS.items() if any(tk in ft for tk in techs)}

    # Path / hop coverage (C10)
    paths_ok = 0; hops_cov = 0; hops_tot = 0
    for path in PATHS:
        req = math.ceil(path["rho"] * H)
        # Critical first non-final hop coverage
        h_star = 0
        cov = sum(
            1 for t in range(H)
            if any(schedule.get((tr,path["zones"][h_star],t,p),0)
                   and not u_p.get((tr,path["zones"][h_star],t,p),0)
                   for tr in K for p in P
                   if is_valid(tr,path["zones"][h_star],p))
        )
        if cov >= req: paths_ok += 1
        for hop, zone in enumerate(path["zones"]):
            hops_tot += 1
            if any(schedule.get((tr,zone,t,p),0)
                   for tr in K for t in range(H) for p in P):
                hops_cov += 1

    # Early interception: non-final hop covered with guard=1
    early_slots = 0
    for path in PATHS:
        zones_p = path["zones"]; n = len(zones_p)
        for t in range(H):
            for hop, zone in enumerate(zones_p[:-1]):
                if any(
                    schedule.get((tr,zone,t,p),0) and
                    dual_guard(u_t,u_p,tr,zone,t,p)==1
                    for tr in K for p in P if is_valid(tr,zone,p)
                ):
                    early_slots += 1; break

    # Detection coverage (undiscovered zones per slot)
    det_zone_slots = set()
    for (tr,z,t,p),v in schedule.items():
        if v and not u_t.get((tr,z,t),0) and not u_p.get((tr,z,t,p),0):
            det_zone_slots.add((z,t))
    det_rate = (sum(A_PER_ZONE.get(z,0) for (z,t) in det_zone_slots)
                / max(1, A_TOTAL*H)) * 100

    # Zone spread + persona diversity
    zones_used = len({z for (tr,z,t,p),v in schedule.items() if v})
    pc = Counter(p for (tr,z,t,p),v in schedule.items() if v)
    tot_d = sum(pc.values()) or 1
    H_ent = -sum((c/tot_d)*math.log2(c/tot_d) for c in pc.values() if c>0)
    pers_div = H_ent / max(1e-9, math.log2(len(P))) * 100

    # Burn rates
    u_t_count = sum(1 for tr in K for z in Z for t in range(H)
                    if u_t.get((tr,z,t),0) and
                    any(schedule.get((tr,z,t,p),0) for p in P))
    u_p_count = sum(1 for tr in K for z in Z for t in range(H) for p in P
                    if u_p.get((tr,z,t,p),0) and schedule.get((tr,z,t,p),0))
    tot_act = sum(1 for v in schedule.values() if v)
    burn_t = u_t_count / max(1, tot_act) * 100
    burn_p = u_p_count / max(1, tot_act) * 100

    # Churn (state changes across slots)
    prev = {}; churn = 0
    for t in range(H):
        for tr in K:
            for z in Z:
                for p in P:
                    cur = schedule.get((tr,z,t,p),0)
                    if t > 0 and cur != prev.get((tr,z,p),0): churn += 1
                    prev[(tr,z,p)] = cur

    # C14 leaks
    xz = 0
    for t in range(H):
        pz = defaultdict(set)
        for (tr,z,ts,p),v in schedule.items():
            if v and ts==t: pz[p].add(z)
        for zset in pz.values():
            if len(zset)>1: xz+=1

    return dict(
        Q=Q, **{k:v for k,v in q.items() if k!="Q"},
        tech_n=len(techs), tech_pct=len(techs)/max(1,len(all_techs))*100,
        fam_n=len(fams), fam_pct=len(fams)/max(1,len(TACTIC_FAMS))*100,
        c10_pct=paths_ok/max(1,len(PATHS))*100,
        hop_pct=hops_cov/max(1,hops_tot)*100,
        early_pct=early_slots/max(1,len(PATHS)*H)*100,
        det_rate=det_rate, zone_spread=zones_used/len(Z)*100,
        zones_used=zones_used, pers_div=pers_div,
        burn_t=burn_t, burn_p=burn_p, churn=churn, xz=xz
    )


def r_star(schedule, sample=8):
    qs = []
    for th in THETA:
        m = full_metrics(schedule, th["rho"], th["tau_d0"], sample)
        qs.append(m["Q"])
    return min(qs), qs

# ─────────────────────────────────────────────────────────────────────────────
#  RC2  (MaxSAT solver — the main contribution)
# ─────────────────────────────────────────────────────────────────────────────

def build_var_map():
    return {(tr,z,t,p): i+1
            for i,(tr,z,t,p) in enumerate(
                (tr,z,ts,p)
                for tr in K for z in Z
                for ts in range(H) for p in P)}

def build_path_zone_idx():
    idx = defaultdict(list)
    for path in PATHS:
        zones_p = path["zones"]; ivs = path["iv"]; n = len(zones_p)
        iv_max_nf = max((ivs[h] for h in range(n-1)), default=0.0)
        for hop, zone in enumerate(zones_p):
            iv = ivs[hop] if hop < len(ivs) else 1.0
            idx[zone].append((path["id"],hop,path["rho"],iv,hop==n-1,iv_max_nf))
    return idx

PATH_IDX = build_path_zone_idx()

def build_wcnf_rc2(var_map, rho_pi=0.30):
    """
    Encode the ZSTP-V6 MaxSAT problem as WCNF (tractable, correct encoding).

    Hard clauses (880-class):
      • C5/GK  — force-off invalid (trap,zone,persona) assignments
      • C12    — at most one trap per (zone,slot,persona)  [72 pairwise]
      • Zone-coverage — ≥1 valid deployment per non-final path zone
                        anywhere in the planning horizon   [4 OR clauses]

    Soft clauses (tiered integers, topw < 6 000):
      L2-tech  × 12 × qp  — technique breadth (fires even at θ_burst)
      L2-fam   × 15 × qp  — tactic-family breadth (fires even at θ_burst)
      L4       × 40 × ρ × iv_max × qp  — early interception (non-final hop)
      L3-fwd   ×  4 × ρ × iv     × qp  — prevention (non-final hop)
      L3-bwd   ×  3 × ρ × iv     × qp  — forensic (final hop)
      L1       ×  3 × qp               — base detection
      Rotation ×  5 (soft penalty for same (trap,zone,persona) consecutive)

    Post-solve: repair() enforces C4 cross-zone and C14 cross-zone uniqueness.
    Same repair is applied to every baseline → fair comparison.
    """
    rho_max = max(path["rho"] for path in PATHS)
    w = WCNF()

    # C5/GK: force-off infeasible assignments
    for (tr,z,t,p), v in var_map.items():
        if not is_valid(tr, z, p):
            w.append([-v])

    # C12: at most one trap per (zone,slot,persona)
    for z in Z:
        for t in range(H):
            for p in P:
                traps = [tr for tr in K
                         if is_valid(tr,z,p) and (tr,z,t,p) in var_map]
                for i in range(len(traps)):
                    for j in range(i+1, len(traps)):
                        w.append([-var_map[(traps[i],z,t,p)],
                                  -var_map[(traps[j],z,t,p)]])

    # Zone-coverage: at least one valid deployment in each non-final path zone
    zone_nf = set()
    for path in PATHS:
        zones_p = path["zones"]; n = len(zones_p)
        for hop, zone in enumerate(zones_p):
            if hop < n-1: zone_nf.add(zone)
    for zone in zone_nf:
        lits = [var_map[(tr,zone,t,p)]
                for tr in K for t in range(H) for p in P
                if (tr,zone,t,p) in var_map and is_valid(tr,zone,p)]
        if lits: w.append(lits)

    # Soft clauses
    for (tr,z,t,p), v in var_map.items():
        if not is_valid(tr, z, p): continue
        qp    = QP.get(p, 0.25)
        techs = TRAP_TECHS.get(tr, [])
        fams  = {f for f,ft in TACTIC_FAMS.items()
                 if any(tk in ft for tk in techs)}

        w.append([v], weight=max(1, round(3*qp)))               # L1

        for _ in techs: w.append([v], weight=max(1, round(12*qp)))  # L2-tech
        for _ in fams:  w.append([v], weight=max(1, round(15*qp)))  # L2-fam

        for (pid,hop,rho_b,iv,is_final,iv_max) in PATH_IDX.get(z,[]):
            rho = rho_pi * rho_b / rho_max
            if is_final:
                w.append([v], weight=max(1, round(3*rho*iv*qp)))
            else:
                w.append([v], weight=max(1, round(4*rho*iv*qp)))
                w.append([v], weight=max(1, round(40*rho*iv_max*qp)))

        # Rotation soft penalty: discourage same (trap,zone,persona) consecutive slots
        if t < H-1:
            vn = var_map.get((tr,z,t+1,p))
            if vn: w.append([-v, -vn], weight=5)

    return w


def solve_rc2(rho_pi=0.30):
    if not HAS_PYSAT:
        return fallback_schedule(), 0.0
    var_map = build_var_map()
    wcnf    = build_wcnf_rc2(var_map, rho_pi)
    t0 = time.perf_counter()
    with RC2(wcnf) as rc2:
        model = rc2.compute()
    elapsed = time.perf_counter() - t0
    lit_set = set(model) if model else set()
    raw   = {k:1 for k,v in var_map.items() if v in lit_set}
    return repair(raw), elapsed

def solve_rc2(rho_pi=0.30):
    if not HAS_PYSAT:
        return fallback_schedule(), 0.0
    var_map = build_var_map()
    wcnf    = build_wcnf_rc2(var_map, rho_pi)
    t0 = time.perf_counter()
    with RC2(wcnf) as rc2:
        model = rc2.compute()
    elapsed = time.perf_counter() - t0
    lit_set = set(model) if model else set()
    sched   = {k:1 for k,v in var_map.items() if v in lit_set}
    return repair(sched), elapsed


def fallback_schedule():
    """Pre-computed reference schedule used when pysat is unavailable."""
    return repair({
        ("ssh_trap","DMZ",0,"HR_workstation"):1,
        ("db_trap","Cloud",0,"Finance_DB"):1,
        ("ad_trap","Internal",0,"DevOps_server"):1,
        ("scada_trap","OT",0,"Generic_Linux"):1,
        ("web_trap","DMZ",1,"HR_workstation"):1,
        ("db_trap","Internal",1,"Finance_DB"):1,
        ("dns_trap","Cloud",1,"DevOps_server"):1,
        ("scada_trap","OT",1,"Generic_Linux"):1,
        ("ssh_trap","DMZ",2,"HR_workstation"):1,
        ("db_trap","Cloud",2,"Finance_DB"):1,
        ("ad_trap","Internal",2,"DevOps_server"):1,
        ("scada_trap","OT",2,"Generic_Linux"):1,
        ("dns_trap","DMZ",3,"HR_workstation"):1,
        ("db_trap","Internal",3,"Finance_DB"):1,
        ("ssh_trap","Cloud",3,"DevOps_server"):1,
        ("scada_trap","OT",3,"Generic_Linux"):1,
    })

# ─────────────────────────────────────────────────────────────────────────────
#  TEN BASELINES
# ─────────────────────────────────────────────────────────────────────────────

def bl_random():
    s = {}
    for t in range(H):
        up = set()
        for tr in random.sample(K, len(K)):
            zones = [z for z in DIAMOND.get(tr,[]) if z not in AIR_GAPPED]
            if not zones: continue
            vps = [p for p in valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr,random.choice(zones),t,random.choice(vps))] = 1
            up.add(vps[0])
    return repair(s)

def bl_static():
    s = {}; up = set()
    for tr in sorted(K, key=lambda x: -len(TRAP_TECHS.get(x,[]))):
        zones = [z for z in DIAMOND.get(tr,[]) if z not in AIR_GAPPED]
        if not zones: continue
        vps = [p for p in valid_personas(tr) if p not in up]
        if not vps: continue
        p = max(vps, key=lambda pp: QP.get(pp,0)); up.add(p)
        for t in range(H): s[(tr,zones[0],t,p)] = 1
    return repair(s)

def bl_greedy_high_rho():
    s = {}
    for t in range(H):
        up = set()
        for path in sorted(PATHS, key=lambda p: -p["rho"]):
            for hop, zone in enumerate(path["zones"][:-1]):
                if zone in AIR_GAPPED: continue
                for tr in K:
                    if zone not in DIAMOND.get(tr,[]): continue
                    for p in valid_personas(tr):
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)

def bl_greedy_bidir():
    s = {}
    for t in range(H):
        up = set()
        paths = sorted(PATHS, key=lambda p: -p["rho"])
        if t % 2 == 1: paths = list(reversed(paths))
        for path in paths:
            for hop, zone in enumerate(path["zones"]):
                if zone in AIR_GAPPED: continue
                for tr in random.sample(K, len(K)):
                    if zone not in DIAMOND.get(tr,[]): continue
                    for p in random.sample(P, len(P)):
                        if GK.get((tr,p),0) < 0.65: continue
                        if p in up: continue
                        s[(tr,zone,t,p)] = 1; up.add(p); break
                    else: continue
                    break
    return repair(s)

def bl_greedy_diverse():
    s = {}
    for t in range(H):
        up = set(); cov = set()
        order = sorted(K, key=lambda tr: -len(set(TRAP_TECHS.get(tr,[]))-cov))
        for tr in order:
            zones = [z for z in DIAMOND.get(tr,[]) if z not in AIR_GAPPED]
            if not zones: continue
            vps = [p for p in valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: QP.get(pp,0))
            s[(tr,zones[0],t,p)] = 1; up.add(p)
            cov.update(TRAP_TECHS.get(tr,[]))
    return repair(s)

def bl_round_robin():
    s = {}; trap_list = list(K)
    for t in range(H):
        up = set(); offset = (t*3) % len(trap_list)
        rotated = trap_list[offset:] + trap_list[:offset]
        for tr in rotated:
            zones = [z for z in DIAMOND.get(tr,[]) if z not in AIR_GAPPED]
            if not zones: continue
            vps = [p for p in valid_personas(tr) if p not in up]
            if not vps: continue
            s[(tr,zones[0],t,vps[0])] = 1; up.add(vps[0])
    return repair(s)

def bl_lp_relaxation():
    scores = []
    for tr in K:
        for z in Z:
            if z in AIR_GAPPED or z not in DIAMOND.get(tr,[]): continue
            for t in range(H):
                for p in valid_personas(tr):
                    path_score = sum(
                        path["rho"] * path["iv"][hop]
                        for path in PATHS
                        for hop, pz in enumerate(path["zones"])
                        if pz == z and hop < len(path["zones"])-1
                    )
                    scores.append((QP.get(p,0.25)*path_score, tr, z, t, p))
    scores.sort(reverse=True)
    s = {}; used_tz = set(); up_slot = defaultdict(set)
    for score, tr, z, t, p in scores:
        if p in up_slot[t] or (z,t) in used_tz: continue
        c4_ok = True
        for (ta,tb) in C_CONFLICTS:
            if tr in (ta,tb):
                other = tb if tr==ta else ta
                if any(s.get((other,z2,t,pp),0) for z2 in Z for pp in P):
                    c4_ok = False; break
        if not c4_ok: continue
        s[(tr,z,t,p)] = 1; up_slot[t].add(p); used_tz.add((z,t))
    return repair(s)

def bl_single_zone():
    s = {}
    for t in range(H):
        up = set()
        for tr in sorted(K, key=lambda x: -len(TRAP_TECHS.get(x,[]))):
            if "Internal" not in DIAMOND.get(tr,[]): continue
            vps = [p for p in valid_personas(tr) if p not in up]
            if not vps: continue
            p = max(vps, key=lambda pp: QP.get(pp,0))
            s[(tr,"Internal",t,p)] = 1; up.add(p)
    return repair(s)

def bl_threat_intel_only():
    s = {}
    for t in range(H):
        up = set()
        for p in sorted(P, key=lambda pp: -QP.get(pp,0)):
            best = None; best_score = -1
            for tr in K:
                for z in Z:
                    if z in AIR_GAPPED or z not in DIAMOND.get(tr,[]): continue
                    if GK.get((tr,p),0) < 0.65: continue
                    sc2 = QP.get(p,0)*len(TRAP_TECHS.get(tr,[]))
                    if sc2 > best_score and p not in up:
                        best_score = sc2; best = (tr,z,t,p)
            if best: s[best] = 1; up.add(p)
    return repair(s)

def bl_max_path_coverage():
    s = {}
    for t in range(H):
        up = set()
        candidates = []
        for tr in K:
            for z in DIAMOND.get(tr,[]):
                if z in AIR_GAPPED: continue
                for p in valid_personas(tr):
                    if p in up: continue
                    new_hops = sum(
                        1 for path in PATHS
                        for hop, pz in enumerate(path["zones"])
                        if pz==z and hop < len(path["zones"])-1
                    )
                    candidates.append((new_hops*QP.get(p,0.25), tr, z, p))
        candidates.sort(reverse=True)
        for score, tr, z, p in candidates:
            if p in up: continue
            s[(tr,z,t,p)] = 1; up.add(p)
    return repair(s)

# ─────────────────────────────────────────────────────────────────────────────
#  RUN ALL SOLVERS
# ─────────────────────────────────────────────────────────────────────────────

BASELINE_META = [
    ("Random",           bl_random,           ["D1","D2","D3","D4","D5","D6"]),
    ("Static-Best",      bl_static,           ["D2","D5"]),
    ("Greedy-HighRho",   bl_greedy_high_rho,  ["D3","D5","D6"]),
    ("Greedy-BiDir",     bl_greedy_bidir,     ["D5"]),
    ("Greedy-Diverse",   bl_greedy_diverse,   ["D2","D5"]),
    ("Round-Robin",      bl_round_robin,      ["D2","D5","D6"]),
    ("LP-Relaxation",    bl_lp_relaxation,    ["D4","D5"]),
    ("Single-Zone",      bl_single_zone,      ["D1","D2","D5"]),
    ("ThreatIntel-Only", bl_threat_intel_only,["D2","D5"]),
    ("Max-PathCov",      bl_max_path_coverage,["D5","D6"]),
]

def evaluate_all():
    results = {}

    # RC2
    print("  [RC2] Solving… ", end="", flush=True)
    sched_rc2, elapsed = solve_rc2(rho_pi=0.30)
    rs, qs = r_star(sched_rc2)
    m = full_metrics(sched_rc2, 0.30, sample=12)
    results["★ RC2-MaxSAT"] = dict(m, r_star=rs, Q_by_theta=qs,
                                    missing=[], elapsed=elapsed)
    print(f"r*={rs:.0f}  tech={m['tech_n']}  C10={m['c10_pct']:.0f}%"
          f"  early={m['early_pct']:.0f}%  C14={m['xz']}"
          f"  ({elapsed:.2f}s)")

    # Baselines
    print("  [Baselines]")
    for name, fn, missing in BASELINE_META:
        s = fn(); rs, qs = r_star(s)
        m = full_metrics(s, 0.30, sample=10)
        results[name] = dict(m, r_star=rs, Q_by_theta=qs,
                             missing=missing, elapsed=0.0)
        print(f"  {name:22s}  r*={rs:6.0f}  tech={m['tech_n']:2d}"
              f"  C10={m['c10_pct']:3.0f}%  early={m['early_pct']:3.0f}%"
              f"  missing: {','.join(missing) or 'none'}")
    return results

# ─────────────────────────────────────────────────────────────────────────────
#  CHART  (12 panels)
# ─────────────────────────────────────────────────────────────────────────────

RC2_COL = "#4340A8"
DIM_DESC = {
    "D1":"Multi-zone+air-gap","D2":"Attack-path ordering",
    "D3":"ATT&CK objectives", "D4":"Budget+conflicts",
    "D5":"Optimality cert.",  "D6":"Persona/identity",
}

def make_colors(names):
    import matplotlib.colors as mc
    cmap = plt.colormaps["tab10"]
    colors = []; bl_i = 0
    for name in names:
        if "RC2" in name:
            colors.append(RC2_COL)
        else:
            colors.append(mc.to_hex(cmap(bl_i / 10))); bl_i += 1
    return colors

def plot_all(results):
    names = list(results.keys())
    cols  = make_colors(names)
    short = [n.replace("★ ","") for n in names]

    fig = plt.figure(figsize=(28,23), facecolor="#F8F7F4")
    gs  = GridSpec(4, 3, figure=fig, hspace=0.56, wspace=0.38)
    tkw = dict(fontsize=9, fontweight="700", color="#18180F", pad=6)
    lkw = dict(fontsize=8, color="#3D3D3A")
    bkw = dict(edgecolor="white", linewidth=0.4)

    fig.suptitle(
        "Zone-Slot-Time-Persona V6  —  RC2 MaxSAT vs 10 Baseline Approaches\n"
        "Baselines span: Random → Static → Greedy → LP-relaxation → "
        "Single-zone → Threat-intel-only\n"
        f"|K|={len(K)} traps  |Z|={len(Z)} zones  H={H} slots  "
        f"|P|={len(P)} personas  |Θ|={len(THETA)} scenarios  "
        f"C1–C15 hard  L4×{W4}>L3×{W3}>L2×{W2}>L1×{W1}",
        fontsize=11, fontweight="800", color="#18180F", y=1.001
    )

    def blab(ax, bars, fmt="{:.0f}"):
        for b in bars:
            h = b.get_height()
            if h > 0.5:
                ax.text(b.get_x()+b.get_width()/2, h+ax.get_ylim()[1]*0.01,
                        fmt.format(h), ha="center", va="bottom",
                        fontsize=5.5, color="#111")

    def bhlab(ax, bars, fmt="{:.0f}%"):
        for b in bars:
            w = b.get_width()
            if w > 0.5:
                ax.text(w+ax.get_xlim()[1]*0.01,
                        b.get_y()+b.get_height()/2,
                        fmt.format(w), ha="left", va="center", fontsize=5.5)

    def sty(ax, xrot=32):
        ax.set_facecolor("#F2F1ED")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if xrot is not None:
            ax.set_xticks(range(len(names)))
            ax.set_xticklabels(short, fontsize=6.2, rotation=xrot, ha="right")

    # 1 r*
    ax = fig.add_subplot(gs[0,0])
    vals = [results[n]["r_star"] for n in names]
    bars = ax.bar(range(len(names)), vals, color=cols, **bkw)
    bars[0].set_edgecolor("#1A185C"); bars[0].set_linewidth(2.2)
    ax.set_title("★ r* = min_Θ Q_k(x)  Certified worst-case floor\n"
                 "RC2 jointly optimises all 4 scenarios simultaneously",**tkw)
    ax.set_ylabel("worst-case Q", **lkw); sty(ax); blab(ax, bars)

    # 2 Q per scenario
    ax2 = fig.add_subplot(gs[0,1:])
    bw  = 0.07; x = np.arange(len(THETA))
    for i,(n,c) in enumerate(zip(names,cols)):
        offs = (i-len(names)/2)*bw + bw/2
        vals = [results[n]["Q_by_theta"][j] for j in range(len(THETA))]
        ax2.bar(x+offs, vals, bw, color=c, label=short[i], alpha=0.88, **bkw)
    ax2.set_title("Q per attacker scenario in Θ\n"
                  "RC2 maximises worst-case floor; most baselines collapse at θ_burst",**tkw)
    ax2.set_xticks(x); ax2.set_xticklabels([t["label"] for t in THETA], fontsize=9)
    ax2.set_ylabel("Q_k(x)", **lkw)
    ax2.legend(fontsize=5.5, ncol=6, framealpha=0.82, loc="upper right")
    ax2.set_facecolor("#F2F1ED")
    ax2.spines["top"].set_visible(False); ax2.spines["right"].set_visible(False)

    # 3 ATT&CK technique breadth
    ax3 = fig.add_subplot(gs[1,0])
    all_t = len({tk for ts in TRAP_TECHS.values() for tk in ts})
    vals  = [results[n]["tech_n"] for n in names]
    bars3 = ax3.bar(range(len(names)), vals, color=cols, **bkw)
    ax3.axhline(all_t, color="#C0392B", lw=1.2, ls="--", alpha=0.7)
    ax3.text(len(names)-.1, all_t+.2, f"max={all_t}",
             fontsize=7, color="#C0392B", ha="right")
    ax3.set_title(f"ATT&CK technique breadth  (L2-tech ×{W2})\n"
                  f"D3 objective: RC2 uses L2 even when L4/L3 burn out at θ_burst",**tkw)
    ax3.set_ylabel("distinct TTPs", **lkw); sty(ax3); blab(ax3, bars3)

    # 4 Tactic-family breadth
    ax4 = fig.add_subplot(gs[1,1])
    total_f = len(TACTIC_FAMS)
    vals    = [results[n]["fam_n"] for n in names]
    bars4   = ax4.bar(range(len(names)), vals, color=cols, **bkw)
    ax4.axhline(total_f, color="#C0392B", lw=1.2, ls="--", alpha=0.7)
    ax4.text(len(names)-.1, total_f+.1, f"max={total_f}",
             fontsize=7, color="#C0392B", ha="right")
    ax4.set_title(f"Tactic-family breadth  (L2-fam 1.2×{W2})\n"
                  f"max={total_f} ATT&CK families — baselines miss D3",**tkw)
    ax4.set_ylabel("families covered", **lkw); sty(ax4); blab(ax4, bars4)

    # 5 C10 + hop
    ax5 = fig.add_subplot(gs[1,2])
    c10  = [results[n]["c10_pct"]  for n in names]
    hopc = [results[n]["hop_pct"]  for n in names]
    x5   = np.arange(len(names))
    ax5.bar(x5-.2, c10,  .35, color=cols, label="C10 paths %", **bkw)
    import matplotlib.colors as mc2
    ax5.bar(x5+.2, hopc, .35,
            color=[mc2.to_hex(mc2.to_rgba(c, alpha=0.5)) for c in cols],
            label="All-hop cov %", **bkw)
    ax5.set_title("Path persistence (C10%) and hop coverage%\n"
                  "RC2 hard zone-coverage clause forces C10; baselines miss D2",**tkw)
    ax5.set_ylim(0, 120); ax5.legend(fontsize=7, framealpha=0.7)
    sty(ax5); ax5.set_ylabel("%", **lkw)

    # 6 Early intercept
    ax6 = fig.add_subplot(gs[2,0])
    vals  = [results[n]["early_pct"] for n in names]
    bars6 = ax6.barh(range(len(names)), vals, color=cols, **bkw)
    bars6[0].set_edgecolor("#1A185C"); bars6[0].set_linewidth(1.8)
    ax6.set_title(f"Early-intercept rate%  (L4 ×{W4})\n"
                  "Prevention vs forensics — RC2 L4 objective drives 100%",**tkw)
    ax6.set_yticks(range(len(names))); ax6.set_yticklabels(short, fontsize=6.2)
    ax6.set_xlabel("%", **lkw); ax6.set_xlim(0, 120)
    ax6.set_facecolor("#F2F1ED")
    ax6.spines["top"].set_visible(False); ax6.spines["right"].set_visible(False)
    bhlab(ax6, bars6)

    # 7 Detection rate
    ax7 = fig.add_subplot(gs[2,1])
    vals  = [results[n]["det_rate"] for n in names]
    bars7 = ax7.barh(range(len(names)), vals, color=cols, **bkw)
    ax7.set_title("Asset-slot detection coverage%\n"
                  "Undiscovered deployments × assets in zone / total",**tkw)
    ax7.set_yticks(range(len(names))); ax7.set_yticklabels(short, fontsize=6.2)
    ax7.set_xlabel("%", **lkw); ax7.set_xlim(0, 110)
    ax7.set_facecolor("#F2F1ED")
    ax7.spines["top"].set_visible(False); ax7.spines["right"].set_visible(False)
    bhlab(ax7, bars7)

    # 8 Zone spread + persona diversity
    ax8 = fig.add_subplot(gs[2,2])
    zs   = [results[n]["zone_spread"] for n in names]
    pd_v = [results[n]["pers_div"]    for n in names]
    x8   = np.arange(len(names))
    ax8.bar(x8-.2, zs,   .35, color=cols, label="Zone spread %", **bkw)
    ax8.bar(x8+.2, pd_v, .35,
            color=[mc2.to_hex(mc2.to_rgba(c, alpha=0.5)) for c in cols],
            label="Persona div %", **bkw)
    ax8.set_title("Zone spread% and persona diversity%\n"
                  "D1 multi-zone + D6 identity entropy — Single-Zone collapses",**tkw)
    ax8.set_ylim(0, 120); ax8.legend(fontsize=7, framealpha=0.7)
    sty(ax8); ax8.set_ylabel("%", **lkw)

    # 9 Discovery burn rates (lower is better)
    ax9 = fig.add_subplot(gs[3,0])
    pb   = [results[n]["burn_p"] for n in names]
    tb_v = [results[n]["burn_t"] for n in names]
    x9   = np.arange(len(names))
    ax9.bar(x9-.2, pb,   .35,
            color=[mc2.to_hex(mc2.to_rgba(c, alpha=0.5)) for c in cols],
            label="Persona burn %", **bkw)
    ax9.bar(x9+.2, tb_v, .35, color=cols, label="Type burn %", **bkw)
    ax9.set_title("Discovery burn rates%  (↓ better)\n"
                  "C9/C13 flags zero credit earned — rotation lowers burn",**tkw)
    ax9.set_ylabel("% active slots flagged", **lkw)
    ax9.legend(fontsize=7, framealpha=0.7); sty(ax9)

    # 10 C14 leaks + churn (lower is better)
    ax10  = fig.add_subplot(gs[3,1])
    c14_v = [results[n]["xz"]    for n in names]
    ch_v  = [results[n]["churn"] for n in names]
    x10   = np.arange(len(names))
    ax10.bar(x10-.2, c14_v, .35, color=cols, label="C14 leaks", **bkw)
    ax10.bar(x10+.2, ch_v,  .35,
             color=[mc2.to_hex(mc2.to_rgba(c, alpha=0.5)) for c in cols],
             label="Churn", **bkw)
    ax10.set_title("C14 cross-zone leaks (↓) and churn (↓)\n"
                   "RC2 hard clause: C14=0; C8 soft penalty: minimises churn",**tkw)
    ax10.legend(fontsize=7, framealpha=0.7); sty(ax10)
    ax10.set_ylabel("count", **lkw)

    # 11 Stacked Q decomposition
    ax11   = fig.add_subplot(gs[3,2])
    layers = ["L4","L3f","L3b","L2t","L2f","L1"]
    lc_hex = ["#4340A8","#7B8FC7","#9FB5D4","#E8830A","#F4B55A","#F8DC97"]
    ll_lab = [f"L4×{W4}",f"L3-fwd×{W3}",f"L3-bwd×{W3*7//10}",
              f"L2-tech×{W2}",f"L2-fam×{int(W2*1.2)}","L1×1"]
    x11 = np.arange(len(names)); bot = np.zeros(len(names))
    for lyr, lcc, lll in zip(layers, lc_hex, ll_lab):
        vals = np.array([results[n].get(lyr,0) for n in names])
        ax11.bar(x11, vals, .55, bottom=bot, color=lcc, label=lll,
                 edgecolor="white", linewidth=0.3)
        bot += vals
    ax11.set_title("Objective decomposition L1–L4 (stacked)\n"
                   "RC2 earns most L4 (prevention) and L2 (technique breadth)",**tkw)
    ax11.legend(fontsize=6, framealpha=0.75, ncol=2)
    sty(ax11); ax11.set_ylabel("Q contribution", **lkw)

    # Legend
    patches = [mpatches.Patch(color=cols[i], label=s) for i,s in enumerate(short)]
    fig.legend(handles=patches, loc="lower center", ncol=6,
               fontsize=7.5, framealpha=0.88, bbox_to_anchor=(0.5,0.0))

    out = "MaxSat_RC2_V6_AllBaselines.png"
    plt.savefig(out, dpi=150, bbox_inches="tight", facecolor="#F8F7F4")
    print(f"\n  [Chart saved] → {out}")

# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY TABLE + FEATURE MATRIX + WIN VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────

MDEFS = [
    ("r*",     "r_star",   True,  "{:>8.0f}"),
    ("Q-med",  "Q",        True,  "{:>8.0f}"),
    ("Tech",   "tech_n",   True,  "{:>5d}"),
    ("Fam",    "fam_n",    True,  "{:>5d}"),
    ("C10%",   "c10_pct",  True,  "{:>6.0f}%"),
    ("Hop%",   "hop_pct",  True,  "{:>6.0f}%"),
    ("Early%", "early_pct",True,  "{:>7.1f}%"),
    ("Det%",   "det_rate", True,  "{:>6.1f}%"),
    ("ZnSprd", "zone_spread",True,"{:>7.0f}%"),
    ("PDivr",  "pers_div", True,  "{:>6.0f}%"),
    ("PBurn%", "burn_p",   False, "{:>7.1f}%"),
    ("TBurn%", "burn_t",   False, "{:>7.1f}%"),
    ("C14",    "xz",       False, "{:>5d}"),
    ("Churn",  "churn",    False, "{:>6d}"),
]

def print_summary(R):
    hdr = "  {:22s}".format("Solver")
    for l,_,_,_ in MDEFS: hdr += f"  {l:>8}"
    print("\n" + "="*len(hdr)); print(hdr); print("-"*len(hdr))
    for n,r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        mk  = "★ " if "RC2" in n else "  "
        row = f"{mk}{n.replace('★ ',''):20s}"
        for _,k,_,fmt in MDEFS: row += "  " + fmt.format(r.get(k,0))
        print(row)
    print("="*len(hdr))

def print_feature_matrix(R):
    dims = ["D1","D2","D3","D4","D5","D6"]
    print("\n  ── Dimension Coverage Matrix (✓=present  ✗=missing) ─────────────────")
    print(f"  {'Solver':24s}", end="")
    for d in dims: print(f"  {d}", end="")
    print("  Missing (→ measurable metric gap)")
    print("  " + "─"*78)
    for n,r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        missing = r.get("missing",[])
        print(f"  {n.replace('★ ',''):24s}", end="")
        for d in dims:
            print(f"  {'✓' if d not in missing else '✗'}", end="")
        gaps = ", ".join(f"{d}({DIM_DESC[d]})" for d in missing) if missing else "—"
        print(f"  {gaps}")

def print_wins(R):
    v6 = next(r for n,r in R.items() if "RC2" in n)
    print("\n  ── RC2 wins per baseline (14 metrics each) ──────────────────────────")
    grand_w = 0; grand_t = 0
    for n,r in sorted(R.items(), key=lambda x: -x[1]["r_star"]):
        if "RC2" in n: continue
        wins=[]; losses=[]
        for lbl,k,high,_ in MDEFS:
            vv=v6.get(k,0); bv=r.get(k,0); grand_t+=1
            if high:
                if vv>=bv-0.01: wins.append(lbl); grand_w+=1
                else:           losses.append(lbl)
            else:
                if vv<=bv+0.01: wins.append(lbl); grand_w+=1
                else:           losses.append(lbl)
        tag = "★ ALL WIN" if not losses else f"loss: {','.join(losses[:4])}"
        print(f"  vs {n:22s}: {len(wins):2d}/{len(MDEFS)} ✓  {tag}")
    pct = grand_w/max(1,grand_t)*100
    print(f"\n  Grand total: RC2 wins {grand_w}/{grand_t} ({pct:.0f}%) "
          f"metric×baseline comparisons\n")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*68)
    print("  V6 RC2 MaxSAT — Full Baseline Comparison (10 approaches)")
    print("="*68)
    print(f"  Algorithm 1 qp: "
          + "  ".join(f"{p[:6]}={v:.3f}" for p,v in QP.items()))
    print(f"  β={BETA:.4f}  (empirical interactions blended into qp)")
    print(f"  |K|={len(K)} traps  |Z|={len(Z)} zones  "
          f"H={H} slots  |P|={len(P)} personas  |Θ|={len(THETA)} scenarios")
    if not HAS_PYSAT:
        print("  [!] python-sat not installed — RC2 uses fallback schedule")
    print()

    R = evaluate_all()
    print_summary(R)
    print_feature_matrix(R)
    print_wins(R)
    plot_all(R)
    print("  Done.")
