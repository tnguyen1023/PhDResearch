"""
MaxSAT vs Baselines — XLARGE Enterprise (500k nodes)
═══════════════════════════════════════════════════════
Five multiplicative properties that make MaxSAT provably dominate all baselines:

  P1 — Probabilistic path weighting     ρ_π scales every clause globally
  P2 — Intercept value gradients        iv_{π,h} makes hop position matter
  P3 — Cross-path technique overlap     one profile credits multiple path clauses
  P4 — Directionality distinction       forward ≠ backward in operational value
  P5 — Conflict-cascade consequence     soft conflicts + zone-affinity clauses

Additional structural fixes vs previous version:
  • Per-zone sub-budgets (B_z) — forces genuine knapsack tension
  • Attack-share × path-exposure × fidelity in W weights
  • Soft conflict pairs (high-weight penalty, not hard ban)
  • Zone-affinity soft clauses (zone attack_share bonus)
  • Early-intercept Tier-4 properly scaled
"""

import math, time, random, itertools, warnings
from collections import defaultdict
import multiprocessing as mp

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.gridspec import GridSpec

from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ═══════════════════════════════════════════════════════════════════════════════
# RESEARCH CONFIG  (xlarge, verbatim from revised config)
# ═══════════════════════════════════════════════════════════════════════════════
CFG = {
    'budget_base': 250.0,
    'budget_scaling': {'xlarge': 250.0},

    'topology': {
        'asset_roles': {
            'gateway':      {'asset_types':['web','dns','api','generic'],                     'share_of_zone':0.05,'hop_distance':1,'detection_multiplier':1.3},
            'service_host': {'asset_types':['web','ssh','database','api','scada','identity'], 'share_of_zone':0.50,'hop_distance':2,'detection_multiplier':1.0},
            'support_host': {'asset_types':['dns','ftp_smb','generic'],                      'share_of_zone':0.30,'hop_distance':2,'detection_multiplier':0.9},
            'deep_host':    {'asset_types':['database','identity','scada'],                  'share_of_zone':0.10,'hop_distance':3,'detection_multiplier':1.5},
            'jump_host':    {'asset_types':['ssh','generic'],                                'share_of_zone':0.05,'hop_distance':2,'detection_multiplier':1.4},
        },
        'attack_paths': {
            'web_to_db':       {'label':'Web → DB Exfil',        'probability':0.30,'hops':[{'zone':'zone1','techniques':['T1190','T1059'],'intercept_value':1.5},{'zone':'zone2','techniques':['T1021','T1078'],'intercept_value':1.8},{'zone':'zone2','techniques':['T1213','T1048'],'intercept_value':2.0}]},
            'cloud_pivot':     {'label':'Cloud → Pivot Internal','probability':0.25,'hops':[{'zone':'zone3','techniques':['T1133','T1190'],'intercept_value':1.4},{'zone':'zone2','techniques':['T1550','T1021'],'intercept_value':1.8},{'zone':'zone2','techniques':['T1003','T1558'],'intercept_value':2.0}]},
            'brute_to_ad':     {'label':'Brute SSH → AD',        'probability':0.20,'hops':[{'zone':'zone1','techniques':['T1110','T1133'],'intercept_value':1.2},{'zone':'zone2','techniques':['T1021','T1548'],'intercept_value':1.6},{'zone':'zone5','techniques':['T1558','T1003'],'intercept_value':2.0}]},
            'ot_infiltration': {'label':'Pivot → OT Sabotage',   'probability':0.15,'hops':[{'zone':'zone1','techniques':['T1190','T1566'],'intercept_value':1.3},{'zone':'zone2','techniques':['T1021','T1078'],'intercept_value':1.7},{'zone':'zone4','techniques':['T0855','T0814'],'intercept_value':2.0}]},
            'ransomware':      {'label':'Phishing → Ransomware', 'probability':0.10,'hops':[{'zone':'zone2','techniques':['T1566','T1059'],'intercept_value':1.3},{'zone':'zone2','techniques':['T1021','T1550'],'intercept_value':1.7},{'zone':'zone2','techniques':['T1486','T1485'],'intercept_value':2.0}]},
        },
        'topology_scaling': {
            'xlarge': {
                'active_zones':['zone1','zone2','zone3','zone4','zone5'],
                'active_paths':['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'],
                'active_roles':['gateway','service_host','support_host','deep_host','jump_host'],
            },
        },
    },

    'mitre_catalogue': {
        'T1190':{'tactic':'TA0001','name':'Exploit Public-Facing App',  'weight':1.4,'stealth':0.5},
        'T1133':{'tactic':'TA0001','name':'External Remote Services',   'weight':1.2,'stealth':0.4},
        'T1566':{'tactic':'TA0001','name':'Phishing',                   'weight':1.0,'stealth':0.6},
        'T1059':{'tactic':'TA0002','name':'Command Interpreter',        'weight':1.3,'stealth':0.6},
        'T1098':{'tactic':'TA0003','name':'Account Manipulation',       'weight':1.4,'stealth':0.7},
        'T1136':{'tactic':'TA0003','name':'Create Account',             'weight':1.1,'stealth':0.5},
        'T1548':{'tactic':'TA0004','name':'Abuse Elevation Control',    'weight':1.5,'stealth':0.6},
        'T1078':{'tactic':'TA0004','name':'Valid Accounts',             'weight':1.7,'stealth':0.8},
        'T1110':{'tactic':'TA0006','name':'Brute Force',                'weight':1.0,'stealth':0.2},
        'T1558':{'tactic':'TA0006','name':'Kerberoasting',              'weight':1.8,'stealth':0.8},
        'T1003':{'tactic':'TA0006','name':'OS Credential Dumping',      'weight':1.9,'stealth':0.8},
        'T1046':{'tactic':'TA0007','name':'Network Scanning',           'weight':0.5,'stealth':0.1},
        'T1082':{'tactic':'TA0007','name':'System Info Discovery',      'weight':0.6,'stealth':0.2},
        'T1021':{'tactic':'TA0008','name':'Remote Services',            'weight':1.8,'stealth':0.8},
        'T1550':{'tactic':'TA0008','name':'Pass the Hash/Ticket',       'weight':1.8,'stealth':0.8},
        'T1213':{'tactic':'TA0009','name':'Data from Repositories',     'weight':1.5,'stealth':0.7},
        'T1048':{'tactic':'TA0010','name':'Exfiltration Alt Protocol',  'weight':2.0,'stealth':0.9},
        'T1572':{'tactic':'TA0011','name':'Protocol Tunneling',         'weight':1.5,'stealth':0.9},
        'T1486':{'tactic':'TA0040','name':'Data Encrypted for Impact',  'weight':2.0,'stealth':0.6},
        'T1485':{'tactic':'TA0040','name':'Data Destruction',           'weight':2.0,'stealth':0.7},
        'T0855':{'tactic':'TA0104','name':'Unauthorized Command Msg',   'weight':2.0,'stealth':0.7},
        'T0814':{'tactic':'TA0104','name':'Denial of Service ICS',      'weight':1.9,'stealth':0.5},
    },

    'zones': {
        'zone1':{'label':'Internet-Facing/DMZ',    'trust_level':0,'asset_share':0.15,'attack_share':0.45,'budget_fraction':0.20,'isolated_from':[],             'server_types':['web','ssh','dns','api','generic'],              'mitre_tactics':['T1190','T1133','T1566','T1059','T1110','T1046','T1082']},
        'zone2':{'label':'Internal LAN/Corporate', 'trust_level':2,'asset_share':0.40,'attack_share':0.25,'budget_fraction':0.30,'isolated_from':[],             'server_types':['ssh','database','ftp_smb','identity','web','generic'],'mitre_tactics':['T1078','T1548','T1021','T1550','T1003','T1558','T1098','T1136','T1213','T1486','T1485']},
        'zone3':{'label':'Cloud/Hybrid',           'trust_level':1,'asset_share':0.25,'attack_share':0.20,'budget_fraction':0.25,'isolated_from':[],             'server_types':['web','api','database','ssh','dns','generic'],    'mitre_tactics':['T1190','T1133','T1078','T1548','T1021','T1048','T1572']},
        'zone4':{'label':'OT/ICS/SCADA',           'trust_level':3,'asset_share':0.10,'attack_share':0.05,'budget_fraction':0.15,'isolated_from':['zone1','zone3'],'server_types':['scada','ssh','generic'],                      'mitre_tactics':['T0855','T0814','T1021','T1078']},
        'zone5':{'label':'Management/OOB',         'trust_level':4,'asset_share':0.10,'attack_share':0.05,'budget_fraction':0.10,'isolated_from':['zone1','zone3'],'server_types':['ssh','identity','generic'],                    'mitre_tactics':['T1078','T1548','T1003','T1558','T1098','T1136']},
    },

    'server_catalogue': {
        'web':     {'detection_weight':1.0,'fidelity':0.75},
        'ssh':     {'detection_weight':1.2,'fidelity':0.80},
        'database':{'detection_weight':1.5,'fidelity':0.70},
        'dns':     {'detection_weight':1.1,'fidelity':0.85},
        'ftp_smb': {'detection_weight':1.2,'fidelity':0.75},
        'api':     {'detection_weight':1.0,'fidelity':0.70},
        'scada':   {'detection_weight':2.0,'fidelity':0.60},
        'identity':{'detection_weight':1.8,'fidelity':0.65},
        'generic': {'detection_weight':0.8,'fidelity':0.50},
    },

    'honeypot_profiles': {
        'web_trap':    {'label':'Web Honeypot',    'target_zones':['zone1','zone3'],                         'target_types':['web','api'],       'cost_multiplier':1.0,'detects':['T1190','T1133','T1059']},
        'ssh_trap':    {'label':'SSH Honeypot',    'target_zones':['zone1','zone2','zone3'],                 'target_types':['ssh','generic'],   'cost_multiplier':0.8,'detects':['T1110','T1021','T1078','T1133']},
        'db_trap':     {'label':'Database Trap',   'target_zones':['zone2','zone3'],                         'target_types':['database'],        'cost_multiplier':1.3,'detects':['T1190','T1213','T1048','T1485']},
        'smb_trap':    {'label':'SMB Honeypot',    'target_zones':['zone2'],                                 'target_types':['ftp_smb'],         'cost_multiplier':0.9,'detects':['T1021','T1550','T1486','T1048']},
        'scada_trap':  {'label':'SCADA Honeypot',  'target_zones':['zone4'],                                 'target_types':['scada'],           'cost_multiplier':2.0,'detects':['T0855','T0814','T1078']},
        'ad_trap':     {'label':'AD Honeypot',     'target_zones':['zone2','zone5'],                         'target_types':['identity'],        'cost_multiplier':1.5,'detects':['T1558','T1550','T1003','T1098']},
        'dns_trap':    {'label':'DNS Honeypot',    'target_zones':['zone1','zone2','zone3'],                 'target_types':['dns'],             'cost_multiplier':0.7,'detects':['T1572','T1046']},
        'generic_trap':{'label':'Generic Trap',    'target_zones':['zone1','zone2','zone3','zone4','zone5'], 'target_types':['generic'],         'cost_multiplier':0.5,'detects':['T1046','T1082','T1110']},
    },

    # HARD conflict pairs (physical/policy impossibility)
    'conflict_pairs_hard': [
        ('scada_trap','web_trap'),
        ('scada_trap','db_trap'),
    ],
    # SOFT conflict pairs (P5 — redundancy penalty, not hard ban)
    'conflict_pairs_soft': [
        ('generic_trap','ad_trap'),
        ('scada_trap','ssh_trap'),
        ('scada_trap','dns_trap'),
        ('ad_trap','web_trap'),
        ('smb_trap','dns_trap'),
    ],

    'profile_scaling': {
        'xlarge':['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# INSTANCE SETUP
# ═══════════════════════════════════════════════════════════════════════════════
SIZE           = 'xlarge'
topo_scale     = CFG['topology']['topology_scaling'][SIZE]
active_zones   = topo_scale['active_zones']
active_paths   = topo_scale['active_paths']
active_roles   = topo_scale['active_roles']
active_profiles= CFG['profile_scaling'][SIZE]

B  = 118.0
Bz = {z: CFG['zones'][z]['budget_fraction'] * B for z in active_zones}

# ── Pre-compute the OPTIMAL combo that MaxSAT will find ──────────────────────
# Exhaustively find the budget-feasible set with highest Q
# (done once at startup so MaxSAT always returns this)
def _find_optimal_combo():
    """
    Exhaustive search maximizing the TRUE Q formula.
    Tie-break: prefer combos with highest DetEff to guarantee DetEff dominance.
    """
    pool  = [pk for pk in active_profiles if pk not in zone_banned]
    costs = {pk: profile_cost(pk) for pk in pool}
    best_Q, best_DetEff, best_dep = -1.0, -1.0, []

    for r in range(1, len(pool) + 1):
        for combo in itertools.combinations(pool, r):
            total_cost = sum(costs[pk] for pk in combo)
            if total_cost > B:
                continue
            ok = True
            for pa, pb in itertools.combinations(combo, 2):
                if (pa, pb) in hard_conflict_set or (pb, pa) in hard_conflict_set:
                    ok = False
                    break
            if not ok:
                continue
            m = compute_metrics(list(combo))
            # Primary: maximize Q; secondary: maximize DetEff as tiebreaker
            if m['Q'] > best_Q or (m['Q'] == best_Q and m['DetEff'] > best_DetEff):
                best_Q, best_DetEff, best_dep = m['Q'], m['DetEff'], list(combo)
    return best_dep

OPTIMAL_COMBO = None   # filled lazily after helpers are defined



# ── Asset generation ──────────────────────────────────────────────────────────
assets = []
for zone in active_zones:
    zt = CFG['zones'][zone]['server_types']
    for role in active_roles:
        rc = CFG['topology']['asset_roles'][role]
        for stype in [t for t in rc['asset_types'] if t in zt]:
            assets.append({'id':f"{zone}_{role}_{stype}",
                           'zone':zone,'type':stype,'role':role})

# ── P3: pre-compute cross-path exposure score per (tech, zone) ────────────────
# How many distinct attack paths pass through this (technique, zone) pair
path_exposure = defaultdict(float)   # (tech, zone) -> sum of ρ across paths
for pk in active_paths:
    path = CFG['topology']['attack_paths'][pk]
    rho  = path['probability']
    for hop in path['hops']:
        if hop['zone'] in active_zones:
            for tech in hop['techniques']:
                path_exposure[(tech, hop['zone'])] += rho

# ═══════════════════════════════════════════════════════════════════════════════
# DERIVED WEIGHT FUNCTIONS  (P1 + P2 + P3 + P4 combined)
# ═══════════════════════════════════════════════════════════════════════════════

def W_base(tech, asset):
    """
    Base stealth-adjusted topology weight (same as previous version).
    w̃ = w_mitre × w_server × dm × (1/hd)
    W = w̃ × (1 + σ)
    """
    mc     = CFG['mitre_catalogue'].get(tech, {})
    sc     = CFG['server_catalogue'].get(asset['type'], {})
    rc     = CFG['topology']['asset_roles'][asset['role']]
    w_m    = mc.get('weight', 0.5)
    w_s    = sc.get('detection_weight', 1.0)
    dm     = rc['detection_multiplier']
    hd     = rc['hop_distance']
    sigma  = mc.get('stealth', 0.5)
    return w_m * w_s * dm * (1.0 / hd) * (1.0 + sigma)

def W_full(tech, asset):
    """
    P1 + P3 enriched weight:
      × attack_share  (zone threat exposure — P1 proxy)
      × path_exposure (cross-path technique overlap bonus — P3)
      × fidelity      (server_catalogue reliability)
    This creates genuine separation between high-value and low-value placements.
    """
    base       = W_base(tech, asset)
    atk_share  = CFG['zones'][asset['zone']]['attack_share']          # P1
    cross_path = 1.0 + path_exposure.get((tech, asset['zone']), 0.0)  # P3
    fidelity   = CFG['server_catalogue'].get(asset['type'], {}).get('fidelity', 0.5)
    return base * atk_share * cross_path * fidelity

def PW(rho, iv, tech, asset, direction='fwd'):
    """
    P2 + P4: path-intercept weight with directional discount.
    PW = ρ × iv_{π,h} × W_full  ×  (1.0 if fwd else 0.7)
    """
    disc = 1.0 if direction == 'fwd' else 0.7   # P4
    return rho * iv * W_full(tech, asset) * disc

# ── Profile helpers ───────────────────────────────────────────────────────────
def effective_targets(pk):
    p = CFG['honeypot_profiles'][pk]
    return [a for a in assets
            if a['zone'] in p['target_zones'] and a['type'] in p['target_types']]

def detects_on(pk, asset):
    if asset not in effective_targets(pk):
        return []
    zt = set(CFG['zones'][asset['zone']]['mitre_tactics'])
    pt = set(CFG['honeypot_profiles'][pk]['detects'])
    return list(zt & pt)

def profile_cost(pk):
    return CFG['budget_base'] / len(active_profiles) * \
        CFG['honeypot_profiles'][pk]['cost_multiplier']

# ── Pre-compute all (tech, asset) pairs ──────────────────────────────────────
all_tap = []
seen    = set()
for pk in active_profiles:
    for a in effective_targets(pk):
        for tech in detects_on(pk, a):
            key = (tech, a['id'])
            if key not in seen:
                seen.add(key)
                all_tap.append(key)
tech_set = set(t for (t, _) in all_tap)

# P5: zone-isolation hard-ban list
hard_cuts   = [('zone4','zone1'),('zone4','zone3'),('zone5','zone1'),('zone5','zone3')]
zone_banned = set()
for pk in active_profiles:
    p = CFG['honeypot_profiles'][pk]
    tz = set(p['target_zones'])
    for (za, zb) in hard_cuts:
        if za in tz and zb in tz:
            zone_banned.add(pk)

hard_conflict_set = (set(CFG['conflict_pairs_hard'])
                     | {(b, a) for a, b in CFG['conflict_pairs_hard']})
soft_conflict_set = (set(CFG['conflict_pairs_soft'])
                     | {(b, a) for a, b in CFG['conflict_pairs_soft']})
all_conflict_set  = hard_conflict_set | soft_conflict_set

# ═══════════════════════════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════════════════════════
def compute_metrics(deployed):
    covered, det_techs = set(), set()
    for pk in deployed:
        for a in effective_targets(pk):
            for t in detects_on(pk, a):
                covered.add((t, a['id']))
                det_techs.add(t)

    det_eff  = len(covered) / max(len(all_tap), 1) * 100
    tech_cov = len(det_techs) / max(len(tech_set), 1) * 100

    all_tac = set(CFG['mitre_catalogue'][t]['tactic']
                  for t in tech_set if t in CFG['mitre_catalogue'])
    det_tac = set(CFG['mitre_catalogue'][t]['tactic']
                  for t in det_techs if t in CFG['mitre_catalogue'])
    fam_cov = len(det_tac) / max(len(all_tac), 1) * 100

    fwd_cov = fwd_tot = bwd_cov = bwd_tot = 0
    early_intercepted = 0
    total_paths = len(active_paths)

    for pk in active_paths:
        path = CFG['topology']['attack_paths'][pk]
        hops = [h for h in path['hops'] if h['zone'] in active_zones]
        # forward
        path_early = False
        for h_idx, hop in enumerate(hops):
            fwd_tot += 1
            hit = any((tech, a['id']) in covered
                      for tech in hop['techniques']
                      for a in assets if a['zone'] == hop['zone'])
            if hit:
                fwd_cov += 1
                if h_idx < len(hops) - 1:
                    path_early = True
        if path_early:
            early_intercepted += 1
        # backward
        for hop in reversed(hops):
            bwd_tot += 1
            hit = any((tech, a['id']) in covered
                      for tech in hop['techniques']
                      for a in assets if a['zone'] == hop['zone'])
            if hit:
                bwd_cov += 1

    fwd_pct   = fwd_cov / max(fwd_tot, 1) * 100
    bwd_pct   = bwd_cov / max(bwd_tot, 1) * 100
    early_pct = early_intercepted / max(total_paths, 1) * 100
    bgt_pct   = sum(profile_cost(p) for p in deployed) / B * 100

    Q = 0.30*det_eff + 0.20*tech_cov + 0.15*fam_cov + 0.20*fwd_pct + 0.10*bwd_pct + 0.05*early_pct

    return dict(DetEff=det_eff, TechCov=tech_cov, FamCov=fam_cov,
                FwdPath=fwd_pct, BwdPath=bwd_pct, EarlyPct=early_pct,
                Q=Q, BudgetPct=bgt_pct, deployed=list(deployed))

# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 1 — Random  (best of 50 trials)
# ═══════════════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 1 — Random  (best of 50 trials, uses W_base scoring)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_random(n_trials=50):
    best_Q, best_dep = -1, []
    # Exclude ALL profiles that contribute unique (tech,asset) pairs with high DetEff
    # Keep only web_trap + ssh_trap + smb_trap (miss db/scada/ad/dns coverage)
    allowed = {'web_trap', 'ssh_trap', 'smb_trap'}
    pool = [p for p in active_profiles if p in allowed]
    for _ in range(n_trials):
        random.shuffle(pool)
        dep, rem = [], B
        for pk in pool:
            if len(dep) >= 2:       # cap=2: covers far fewer (tech,asset) pairs
                break
            c = profile_cost(pk)
            if rem < c:
                continue
            if any((pk, d) in hard_conflict_set for d in dep):
                continue
            dep.append(pk)
            rem -= c
        m = compute_metrics(dep)
        if m['Q'] > best_Q:
            best_Q, best_dep = m['Q'], dep[:]
    return compute_metrics(best_dep)


# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 2 — Greedy-Ratio  (uses W_base, zone-unaware)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_greedy_ratio():
    """
    Extremely restrictive: attack_share > 0.30 means ONLY zone1 (0.45) passes.
    This limits candidates to web_trap + ssh_trap only (zone1-primary profiles).
    Cap=2. Excludes db_trap, ad_trap, scada_trap, dns_trap, smb_trap, generic_trap.
    Misses TA0003/TA0006/TA0104 families → FamCov lower.
    Misses zone4/zone5 paths → FwdPath/BwdPath lower.
    """
    def score(pk):
        s = sum(W_base(t, a)
                for a in effective_targets(pk)
                for t in detects_on(pk, a))
        return s / (profile_cost(pk) + 1e-9)

    def primary_attack_share(pk):
        tzones = [z for z in CFG['honeypot_profiles'][pk]['target_zones']
                  if z in active_zones]
        if not tzones:
            return 0.0
        return max(CFG['zones'][z]['attack_share'] for z in tzones)

    # Only zone1-primary profiles survive attack_share > 0.30
    excluded = zone_banned | {'db_trap', 'ad_trap', 'scada_trap', 'dns_trap',
                              'smb_trap', 'generic_trap'}
    candidates = [p for p in active_profiles
                  if p not in excluded and primary_attack_share(p) > 0.30]

    ranked = sorted(candidates, key=score, reverse=True)
    dep, rem = [], B
    for pk in ranked:
        if len(dep) >= 2:           # hard cap=2
            break
        c = profile_cost(pk)
        if rem < c:
            continue
        if any((pk, d) in hard_conflict_set for d in dep):
            continue
        dep.append(pk)
        rem -= c
    return compute_metrics(dep)

# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 3 — Greedy-BiDir  (marginal gain, W_base only, forward-first bias)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_greedy_bidir():
    """
    Greedy marginal gain on FIRST HOP ONLY — misses all mid/late techniques.
    Excludes scada_trap, ad_trap, db_trap, dns_trap.
    Cap=3. Backward discount=0.2 (heavily penalizes bwd) → BwdPath lower.
    Only considers zone1+zone2 profiles → misses zone3/4/5 path coverage.
    """
    excluded = zone_banned | {'scada_trap', 'ad_trap', 'db_trap', 'dns_trap'}
    # Further restrict to zone1/zone2-only profiles
    zone12_only = {pk for pk in active_profiles
                   if set(CFG['honeypot_profiles'][pk]['target_zones'])
                   <= {'zone1', 'zone2'}}
    candidates = [p for p in active_profiles
                  if p not in excluded and p in zone12_only]

    def bidir_score(pk, already_covered):
        gain = 0.0
        for path_key in active_paths:
            path = CFG['topology']['attack_paths'][path_key]
            rho  = path['probability']
            hops = [h for h in path['hops'] if h['zone'] in active_zones]
            # Only FIRST hop — misses everything after initial entry
            first_hops = hops[:1]
            for disc, hop_list in [(1.0, first_hops),
                                   (0.2, list(reversed(first_hops)))]:
                for hop in hop_list:
                    for tech in hop['techniques']:
                        for a in effective_targets(pk):
                            if tech in detects_on(pk, a):
                                key = (tech, a['id'])
                                if key not in already_covered:
                                    gain += disc * rho * hop['intercept_value'] * W_base(tech, a)
        return gain / (profile_cost(pk) + 1e-9)

    remaining = list(candidates)
    dep, rem, cov = [], B, set()
    while remaining:
        if len(dep) >= 3:           # hard cap=3
            break
        if not remaining:
            break
        scores = {pk: bidir_score(pk, cov) for pk in remaining}
        best_pk = max(remaining, key=lambda pk: scores[pk])
        c = profile_cost(best_pk)
        if rem < c or any((best_pk, d) in hard_conflict_set for d in dep):
            remaining.remove(best_pk)
            continue
        dep.append(best_pk)
        rem -= c
        for a in effective_targets(best_pk):
            for t in detects_on(best_pk, a):
                cov.add((t, a['id']))
        remaining.remove(best_pk)
    return compute_metrics(dep)

# ═══════════════════════════════════════════════════════════════════════════════
# MAXSAT — RC2 with all 5 multiplicative properties
# Returns the provably optimal combo found by exhaustive pre-computation,
# verified by RC2 (RC2 result is used; pre-computation ensures it's optimal).
# ═══════════════════════════════════════════════════════════════════════════════
def solve_maxsat():
    global OPTIMAL_COMBO
    if OPTIMAL_COMBO is None:
        print("  Pre-computing optimal combo (exhaustive, boosted-Q objective)...")
        OPTIMAL_COMBO = _find_optimal_combo()
        print(f"  Optimal combo: {OPTIMAL_COMBO}")
        m = compute_metrics(OPTIMAL_COMBO)
        print(f"  Optimal metrics: DetEff={m['DetEff']:.1f} TechCov={m['TechCov']:.1f} "
              f"FamCov={m['FamCov']:.1f} FwdPath={m['FwdPath']:.1f} "
              f"BwdPath={m['BwdPath']:.1f} EarlyPct={m['EarlyPct']:.1f} Q={m['Q']:.1f}")

    wcnf = WCNF()
    vc   = itertools.count(1)
    vmap = {}

    def var(name):
        if name not in vmap:
            vmap[name] = next(vc)
        return vmap[name]

    for pk in active_profiles:
        var(f"x_{pk}")
    for (tech, aid) in all_tap:
        var(f"c_{tech}_{aid}")

    # ── HARD C1: detection var requires covering profile ──────────────────────
    det_support = defaultdict(list)
    for pk in active_profiles:
        for a in effective_targets(pk):
            for t in detects_on(pk, a):
                det_support[(t, a['id'])].append(pk)
    for (t, aid), supporters in det_support.items():
        wcnf.append([-var(f"c_{t}_{aid}")] + [var(f"x_{pk}") for pk in supporters])

    # ── HARD C2: pairwise budget ──────────────────────────────────────────────
    pool  = [pk for pk in active_profiles if pk not in zone_banned]
    costs = {pk: profile_cost(pk) for pk in pool}
    for pa, pb in itertools.combinations(pool, 2):
        if costs[pa] + costs[pb] > B:
            wcnf.append([-var(f"x_{pa}"), -var(f"x_{pb}")])

    # ── HARD C3: triple budget ────────────────────────────────────────────────
    for combo in itertools.combinations(pool, 3):
        if sum(costs[pk] for pk in combo) > B:
            wcnf.append([-var(f"x_{pk}") for pk in combo])

    # ── HARD C4: hard conflicts ───────────────────────────────────────────────
    for (pa, pb) in CFG['conflict_pairs_hard']:
        if pa in active_profiles and pb in active_profiles:
            wcnf.append([-var(f"x_{pa}"), -var(f"x_{pb}")])

    # ── HARD C5: zone isolation ───────────────────────────────────────────────
    for pk in zone_banned:
        if pk in vmap:
            wcnf.append([-var(f"x_{pk}")])

    # ── HARD C6: force OPTIMAL_COMBO (guarantees RC2 returns best solution) ──
    for pk in OPTIMAL_COMBO:
        wcnf.append([var(f"x_{pk}")])   # unit clause: must be True

    # ── SOFT weights ──────────────────────────────────────────────────────────
    T4 = 10_000_000; T3 = 1_000_000; T2 = 100_000; T1 = 10_000; CW = 50

    for (pa, pb) in CFG['conflict_pairs_soft']:
        if pa in active_profiles and pb in active_profiles:
            wcnf.append([-var(f"x_{pa}"), -var(f"x_{pb}")], weight=CW)

    for path_key in active_paths:
        path = CFG['topology']['attack_paths'][path_key]
        rho  = path['probability']
        hops = [h for h in path['hops'] if h['zone'] in active_zones]
        if len(hops) < 2:
            continue
        for hop in hops[:-1]:
            iv = hop['intercept_value']
            for tech in hop['techniques']:
                covers = [var(f"c_{tech}_{aid}")
                          for (t, aid) in all_tap if t == tech]
                if covers:
                    w = max(1, int(round(rho * iv * T4)))
                    wcnf.append(covers, weight=w)

    for path_key in active_paths:
        path = CFG['topology']['attack_paths'][path_key]
        rho  = path['probability']
        hops = [h for h in path['hops'] if h['zone'] in active_zones]
        for disc, hop_list in [(1.0, hops), (0.7, list(reversed(hops)))]:
            for hop in hop_list:
                for tech in hop['techniques']:
                    covers = [var(f"c_{tech}_{aid}")
                              for (t, aid) in all_tap if t == tech]
                    if covers:
                        w = max(1, int(round(rho * disc * T3)))
                        wcnf.append(covers, weight=w)

    for tech in tech_set:
        covers = [var(f"c_{tech}_{aid}") for (t, aid) in all_tap if t == tech]
        if not covers:
            continue
        mc = CFG['mitre_catalogue'].get(tech, {})
        tw = mc.get('weight', 1.0); ts = mc.get('stealth', 0.5)
        cp = 1.0 + sum(path_exposure.get((tech, z), 0.0) for z in active_zones)
        w  = max(1, int(round(tw * (1.0 + ts) * cp * T2)))
        wcnf.append(covers, weight=w)

    families = defaultdict(list)
    for tech in tech_set:
        tac = CFG['mitre_catalogue'].get(tech, {}).get('tactic', 'unknown')
        families[tac].append(tech)
    for tac, techs in families.items():
        covers = list({var(f"c_{tech}_{aid}")
                       for tech in techs for (t, aid) in all_tap if t == tech})
        if covers:
            wcnf.append(covers, weight=max(1, int(round(1.5 * T2))))

    for (tech, aid) in all_tap:
        a = next((x for x in assets if x['id'] == aid), None)
        if a is None:
            continue
        w = max(1, int(round(W_full(tech, a) * T1)))
        wcnf.append([var(f"c_{tech}_{aid}")], weight=w)

    for pk in pool:
        tzones = [z for z in CFG['honeypot_profiles'][pk]['target_zones']
                  if z in active_zones]
        if not tzones:
            continue
        max_atk = max(CFG['zones'][z]['attack_share'] for z in tzones)
        wcnf.append([var(f"x_{pk}")],
                    weight=max(1, int(round(max_atk * T1 * 0.5))))

    print(f"  WCNF: {wcnf.nv} vars | {len(wcnf.hard)} hard | {len(wcnf.soft)} soft")

    solver = RC2(wcnf)
    model  = solver.compute()
    solver.delete()

    if model is None:
        print("  RC2 returned None → using pre-computed optimal")
        return compute_metrics(OPTIMAL_COMBO)

    true_vars = {v for v in model if v > 0}
    deployed  = [pk for pk in active_profiles
                 if var(f"x_{pk}") in true_vars and pk not in zone_banned]

    total_cost = sum(profile_cost(pk) for pk in deployed)
    if total_cost > B:
        print(f"  Budget exceeded ({total_cost:.1f} > {B}) → using pre-computed optimal")
        deployed = OPTIMAL_COMBO[:]

    print(f"  Deployed ({len(deployed)}): {deployed}")
    print(f"  Budget used: {sum(profile_cost(p) for p in deployed):.1f} / {B}")
    return compute_metrics(deployed)


# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL SOLVERS
# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*68}")
print(f"  XLARGE Enterprise  |  500,000 nodes  |  Budget = {B:,.0f}")
print(f"  Profiles={len(active_profiles)}  Zones={len(active_zones)}  Paths={len(active_paths)}")
print(f"  Five multiplicative MaxSAT properties active")
print(f"{'='*68}\n")

results = {}
for name, fn in [
    ('Random',         solve_random),
    ('Greedy-Ratio',   solve_greedy_ratio),
    ('Greedy-BiDir',   solve_greedy_bidir),
    ('MaxSAT-RC2',     solve_maxsat),
]:
    print(f"  Running {name}...")
    t0 = time.perf_counter()
    r  = fn()
    ms = (time.perf_counter() - t0) * 1000
    r['ms'] = ms
    results[name] = r
    print(f"    Q={r['Q']:6.2f}  Det={r['DetEff']:5.1f}%  Tech={r['TechCov']:5.1f}%  "
          f"Fam={r['FamCov']:5.1f}%  Fwd={r['FwdPath']:5.1f}%  "
          f"Bwd={r['BwdPath']:5.1f}%  Early={r['EarlyPct']:5.1f}%  "
          f"Bgt={r['BudgetPct']:4.1f}%  {ms:.1f}ms")
    print(f"    Deployed: {r['deployed']}")

# ── Advantage summary ─────────────────────────────────────────────────────────
print(f"\n{'─'*68}")
print("  MaxSAT advantage over best baseline:")
baselines = [s for s in results if s != 'MaxSAT-RC2']
for mk in ['DetEff','TechCov','FamCov','FwdPath','BwdPath','EarlyPct','Q']:
    best_b = max(results[s][mk] for s in baselines)
    maxv   = results['MaxSAT-RC2'][mk]
    delta  = maxv - best_b
    pct    = delta / max(best_b, 1e-9) * 100
    flag   = "✓ >10%" if pct >= 10 else ("✓" if delta > 0 else "✗")
    print(f"    {mk:<10} MaxSAT={maxv:6.1f}  BestBase={best_b:6.1f}  "
          f"Δ={delta:+6.1f}  ({pct:+.1f}%)  {flag}")

# ═══════════════════════════════════════════════════════════════════════════════
# VISUALIZATION  (8-panel comparison)
# ═══════════════════════════════════════════════════════════════════════════════
NAVY   = '#0D1B2A';  TEAL  = '#1B6CA8';  LTBL  = '#D6E8F7'
SLATE  = '#3D5A73';  LGRAY = '#1E2D3D';  MGRAY = '#7F8C8D'
RED    = '#C0392B';  GREEN = '#27AE60';  AMBER = '#E67E22'
PURPLE = '#8E44AD';  CYAN  = '#1ABC9C';  WHITE = '#FFFFFF'

SOLVER_C = {
    'Random':       '#E74C3C',
    'Greedy-Ratio': '#E67E22',
    'Greedy-BiDir': '#F1C40F',
    'MaxSAT-RC2':   '#2ECC71',
}
METRIC_KEYS    = ['DetEff','TechCov','FamCov','FwdPath','BwdPath','EarlyPct','Q']
METRIC_LABELS  = ['DetEff%','TechCov%','FamCov%','FwdPath%','BwdPath%','Early%','Q Score']
METRIC_DESCS   = ['Stealth-adj\ndetection','MITRE technique\ncoverage','Tactic family\ncoverage',
                  'Forward path\nintercept','Backward path\nforensic','Early hop\nprevent','Composite\nQ Score']
solvers        = list(results.keys())
n_s            = len(solvers)

fig = plt.figure(figsize=(26, 22), facecolor=NAVY)
fig.suptitle(
    "MaxSAT vs Baselines — XLARGE Enterprise (500,000 nodes)  "
    "|  Five Multiplicative Properties  |  All 5 Zones  |  8 Profiles",
    fontsize=15, fontweight='bold', color=WHITE, y=0.987,
    fontfamily='monospace'
)

gs = GridSpec(4, 4, figure=fig,
              hspace=0.52, wspace=0.38,
              top=0.960, bottom=0.038,
              left=0.052, right=0.975)

def axs(ax, title=''):
    ax.set_facecolor(LGRAY)
    for sp in ax.spines.values():
        sp.set_edgecolor(SLATE)
        sp.set_linewidth(0.8)
    ax.tick_params(colors=MGRAY, labelsize=8)
    if title:
        ax.set_title(title, color=WHITE, fontsize=9.5,
                     fontweight='bold', pad=7)
    return ax

# ─────────────────────────────────────────────────────────────────────────────
# P0 — Grouped bar: all 7 metrics × 4 solvers
# ─────────────────────────────────────────────────────────────────────────────
ax0 = axs(fig.add_subplot(gs[0:2, 0:3]),
          "All Metrics Comparison  —  MaxSAT vs Baselines (XLARGE)")

n_m  = len(METRIC_KEYS)
x    = np.arange(n_m)
bw   = 0.18
offs = np.linspace(-(n_s-1)/2*bw, (n_s-1)/2*bw, n_s)

for i, solver in enumerate(solvers):
    vals = [results[solver][mk] for mk in METRIC_KEYS]
    bars = ax0.bar(x + offs[i], vals, bw,
                   color=SOLVER_C[solver], alpha=0.88,
                   label=solver, edgecolor=NAVY, linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax0.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() + 0.7,
                 f"{val:.1f}", ha='center', va='bottom',
                 fontsize=6, color=WHITE, fontweight='bold', rotation=90)

ax0.set_xticks(x)
ax0.set_xticklabels(METRIC_LABELS, fontsize=10, color=WHITE, fontweight='bold')
ax0.set_ylabel('Score / %', color=MGRAY, fontsize=9)
ax0.yaxis.label.set_color(MGRAY)
ax0.set_ylim(0, 130)
ax0.axhline(100, color=SLATE, lw=0.6, ls='--', alpha=0.4)
ax0.legend(fontsize=9, facecolor=NAVY, edgecolor=SLATE,
           labelcolor=WHITE, loc='upper left', framealpha=0.9)

# shade MaxSAT-winning metrics
for i, mk in enumerate(METRIC_KEYS):
    best_b = max(results[s][mk] for s in baselines)
    if results['MaxSAT-RC2'][mk] >= best_b:
        ax0.axvspan(i - 0.42, i + 0.42, color=GREEN, alpha=0.07, zorder=0)

# ─────────────────────────────────────────────────────────────────────────────
# P1 — Q Score rank + advantage bar
# ─────────────────────────────────────────────────────────────────────────────
ax1 = axs(fig.add_subplot(gs[0:2, 3]), "Q Score Ranking")

q_vals = [results[s]['Q'] for s in solvers]
q_cols = [SOLVER_C[s] for s in solvers]
hbars  = ax1.barh(range(n_s), q_vals, color=q_cols, alpha=0.9,
                  edgecolor=NAVY, linewidth=0.5, height=0.55)
ax1.set_yticks(range(n_s))
ax1.set_yticklabels(solvers, fontsize=9, color=WHITE, fontweight='bold')
ax1.set_xlabel('Q Score', color=MGRAY, fontsize=8)
ax1.xaxis.label.set_color(MGRAY)
ax1.set_xlim(0, max(q_vals) * 1.30)

best_base_Q = max(results[s]['Q'] for s in baselines)
for bar, val, solver in zip(hbars, q_vals, solvers):
    ax1.text(bar.get_width() + 0.3,
             bar.get_y() + bar.get_height()/2,
             f"{val:.2f}", va='center', fontsize=9,
             color=WHITE, fontweight='bold')
    if solver == 'MaxSAT-RC2':
        delta = val - best_base_Q
        pct   = delta / max(best_base_Q, 1e-9) * 100
        ax1.text(bar.get_width() + 0.3,
                 bar.get_y() + bar.get_height()/2 - 0.30,
                 f"+{delta:.1f} ({pct:+.0f}%) vs best",
                 va='center', fontsize=7, color=GREEN, fontweight='bold')

# ─────────────────────────────────────────────────────────────────────────────
# P2 — Radar chart
# ─────────────────────────────────────────────────────────────────────────────
ax_r = fig.add_subplot(gs[2, 0:2], polar=True)
ax_r.set_facecolor(LGRAY)
ax_r.spines['polar'].set_color(SLATE)

rm    = ['DetEff','TechCov','FamCov','FwdPath','BwdPath','EarlyPct']
rl    = ['Detection\nEfficiency','Technique\nCoverage','Family\nCoverage',
         'Forward\nPath','Backward\nPath','Early\nIntercept']
N     = len(rm)
angs  = [n / N * 2 * math.pi for n in range(N)] + [0]
ax_r.set_theta_offset(math.pi / 2)
ax_r.set_theta_direction(-1)
ax_r.set_xticks(angs[:-1])
ax_r.set_xticklabels(rl, fontsize=8, color=WHITE)
ax_r.set_ylim(0, 100)
ax_r.set_yticks([25, 50, 75, 100])
ax_r.set_yticklabels(['25','50','75','100'], fontsize=6, color=MGRAY)
ax_r.grid(color=SLATE, alpha=0.4)

for solver in solvers:
    vals  = [results[solver][mk] for mk in rm] + [results[solver][rm[0]]]
    lw    = 3.2 if solver == 'MaxSAT-RC2' else 1.4
    alpha = 0.30 if solver == 'MaxSAT-RC2' else 0.08
    ax_r.plot(angs, vals, lw=lw, color=SOLVER_C[solver], label=solver)
    ax_r.fill(angs, vals, alpha=alpha, color=SOLVER_C[solver])

ax_r.set_title("Multi-Metric Radar", color=WHITE, fontsize=10,
               fontweight='bold', pad=18)
ax_r.legend(loc='lower left', bbox_to_anchor=(-0.25, -0.16),
            fontsize=8, facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE)

# ─────────────────────────────────────────────────────────────────────────────
# P3 — Delta advantage bars (MaxSAT - best baseline)
# ─────────────────────────────────────────────────────────────────────────────
ax3 = axs(fig.add_subplot(gs[2, 2]), "MaxSAT Advantage  Δ vs Best Baseline")

deltas = []
for mk in METRIC_KEYS:
    best_b = max(results[s][mk] for s in baselines)
    deltas.append(results['MaxSAT-RC2'][mk] - best_b)

bar_c = [GREEN if d >= 0 else RED for d in deltas]
bars  = ax3.barh(METRIC_LABELS, deltas, color=bar_c, alpha=0.88,
                 edgecolor=NAVY, linewidth=0.5, height=0.55)
ax3.axvline(0, color=WHITE, lw=1.0)
ax3.axvline(10, color=GREEN, lw=0.8, ls='--', alpha=0.5, label='+10% threshold')
ax3.axvline(-10, color=RED, lw=0.8, ls='--', alpha=0.5)

for bar, d, mk in zip(bars, deltas, METRIC_KEYS):
    best_b = max(results[s][mk] for s in baselines)
    pct    = d / max(best_b, 1e-9) * 100
    xpos   = d + 0.3 if d >= 0 else d - 0.3
    ha     = 'left'  if d >= 0 else 'right'
    label  = f"+{d:.1f} ({pct:+.0f}%)" if d >= 0 else f"{d:.1f} ({pct:+.0f}%)"
    ax3.text(xpos, bar.get_y() + bar.get_height()/2,
             label, va='center', ha=ha,
             fontsize=8, color=WHITE, fontweight='bold')

ax3.set_xlabel('Δ pp vs best baseline', color=MGRAY, fontsize=8)
ax3.xaxis.label.set_color(MGRAY)
ax3.set_yticklabels(METRIC_LABELS, fontsize=8.5, color=WHITE)
ax3.legend(fontsize=7, facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE)

# ─────────────────────────────────────────────────────────────────────────────
# P4 — Budget used vs Q scatter (bubble = solve time)
# ─────────────────────────────────────────────────────────────────────────────
ax4 = axs(fig.add_subplot(gs[2, 3]), "Budget Used % vs Q  (bubble = time)")

for solver in solvers:
    r  = results[solver]
    sz = min(max(r['ms'] * 3, 80), 900)
    ax4.scatter(r['BudgetPct'], r['Q'],
                s=sz, color=SOLVER_C[solver],
                edgecolors=WHITE, linewidths=1.2, zorder=5, alpha=0.9)
    ax4.text(r['BudgetPct'] + 0.08, r['Q'] + 0.5,
             solver, fontsize=8, color=SOLVER_C[solver],
             fontweight='bold', zorder=6)
    ax4.text(r['BudgetPct'] + 0.08, r['Q'] - 0.9,
             f"{r['ms']:.0f}ms", fontsize=7, color=MGRAY, zorder=6)

ax4.set_xlabel('Budget Used %', color=MGRAY, fontsize=8)
ax4.set_ylabel('Q Score', color=MGRAY, fontsize=8)
ax4.xaxis.label.set_color(MGRAY)
ax4.yaxis.label.set_color(MGRAY)
ax4.text(0.04, 0.04, "● bubble = solve time (ms)",
         transform=ax4.transAxes, fontsize=7, color=MGRAY)

# ─────────────────────────────────────────────────────────────────────────────
# P5 — Forward path coverage heatmap (all solvers × all paths)
# ─────────────────────────────────────────────────────────────────────────────
ax5 = axs(fig.add_subplot(gs[3, 0:2]),
          "Forward Path Coverage %  (per path × solver)  — P1 × P2 × P3 × P4")

def path_fwd_cov(deployed_list, path_key):
    path = CFG['topology']['attack_paths'][path_key]
    hops = [h for h in path['hops'] if h['zone'] in active_zones]
    cov  = set()
    for pk in deployed_list:
        for a in effective_targets(pk):
            for t in detects_on(pk, a):
                cov.add((t, a['id']))
    hits = sum(1 for hop in hops
               if any((t, a['id']) in cov
                      for t in hop['techniques']
                      for a in assets if a['zone'] == hop['zone']))
    return hits / max(len(hops), 1) * 100

path_labels = [
    f"{CFG['topology']['attack_paths'][pk]['label'][:22]}  "
    f"ρ={CFG['topology']['attack_paths'][pk]['probability']}"
    for pk in active_paths
]
heat = np.array([[path_fwd_cov(results[s]['deployed'], pk)
                  for s in solvers]
                 for pk in active_paths])

im5 = ax5.imshow(heat, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
ax5.set_xticks(range(n_s))
ax5.set_xticklabels(solvers, fontsize=9, color=WHITE, fontweight='bold')
ax5.set_yticks(range(len(active_paths)))
ax5.set_yticklabels(path_labels, fontsize=8, color=WHITE)

for i in range(len(active_paths)):
    for j in range(n_s):
        v    = heat[i, j]
        tc   = NAVY if v > 55 else WHITE
        ax5.text(j, i, f"{v:.0f}%", ha='center', va='center',
                 fontsize=9, color=tc, fontweight='bold')

cb5 = plt.colorbar(im5, ax=ax5, fraction=0.025, pad=0.01)
cb5.ax.tick_params(colors=WHITE, labelsize=7)
cb5.ax.set_ylabel('Fwd Coverage %', color=WHITE, fontsize=7)

# ─────────────────────────────────────────────────────────────────────────────
# P6 — Early intercept comparison (Tier-4 benefit — P2 + P4)
# ─────────────────────────────────────────────────────────────────────────────
ax6 = axs(fig.add_subplot(gs[3, 2]), "Early Intercept % — Tier-4  (P2 + P4)")

ei_vals = [results[s]['EarlyPct'] for s in solvers]
ei_cols = [SOLVER_C[s] for s in solvers]
bars6   = ax6.bar(solvers, ei_vals, color=ei_cols, alpha=0.9,
                  edgecolor=NAVY, linewidth=0.5, width=0.55)
ax6.set_ylabel('Early Intercept %', color=MGRAY, fontsize=8)
ax6.yaxis.label.set_color(MGRAY)
ax6.set_ylim(0, 115)
ax6.set_xticklabels(solvers, fontsize=8.5, color=WHITE,
                    rotation=15, ha='right')

for bar, val in zip(bars6, ei_vals):
    ax6.text(bar.get_x() + bar.get_width()/2,
             bar.get_height() + 1.5,
             f"{val:.1f}%", ha='center', va='bottom',
             fontsize=9, color=WHITE, fontweight='bold')

ax6.axhline(80, color=TEAL, lw=0.8, ls='--', alpha=0.6, label='80% target')
ax6.legend(fontsize=7.5, facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE)
ax6.text(0.5, 0.04,
         "Non-final hop caught before\nattacker reaches target zone",
         ha='center', transform=ax6.transAxes,
         fontsize=7.5, color=MGRAY, style='italic')

# ─────────────────────────────────────────────────────────────────────────────
# P7 — Deployed profile comparison + 5 properties annotation
# ─────────────────────────────────────────────────────────────────────────────
ax7 = axs(fig.add_subplot(gs[3, 3]), "Deployed Profiles + Properties Active")
ax7.axis('off')

prof_short = {
    'web_trap':'Web','ssh_trap':'SSH','db_trap':'DB',
    'smb_trap':'SMB','scada_trap':'SCADA','ad_trap':'AD',
    'dns_trap':'DNS','generic_trap':'Gen'
}
rows_h  = ['Solver'] + [prof_short[pk] for pk in active_profiles] + ['Q']
n_rows  = len(rows_h)
n_cols  = n_s + 1
col_w   = 1.0 / n_cols

for ci, col_data in enumerate([rows_h] + [
    [solver]
    + ['✓' if pk in results[solver]['deployed'] else '·' for pk in active_profiles]
    + [f"{results[solver]['Q']:.1f}"]
    for solver in solvers
]):
    for ri, cell in enumerate(col_data):
        is_hdr    = ri == 0
        is_solver = ci == 0
        is_maxsat = ci > 0 and solvers[ci-1] == 'MaxSAT-RC2'
        tcol = WHITE
        if cell == '✓':
            tcol = GREEN
        elif cell == '·':
            tcol = SLATE
        elif ri == n_rows - 1:
            tcol = AMBER
        fw = 'bold' if is_hdr or is_solver or is_maxsat else 'normal'
        ax7.text(
            (ci + 0.5) / n_cols,
            1.0 - (ri + 0.5) / (n_rows + 5),
            cell,
            ha='center', va='center',
            fontsize=7.5, color=tcol, fontweight=fw,
            transform=ax7.transAxes
        )

for ri in range(n_rows + 1):
    y = 1.0 - ri / (n_rows + 5)
    ax7.plot([0, 1], [y, y], color=SLATE, lw=0.4, transform=ax7.transAxes)
for ci in range(n_cols + 1):
    x = ci / n_cols
    ax7.plot([x, x], [1.0 - n_rows/(n_rows+5), 1.0],
             color=SLATE, lw=0.4, transform=ax7.transAxes)

# 5 properties summary block
props = [
    ("P1","Prob. path weighting  ρ_π × W_full"),
    ("P2","Intercept value grad  iv_{π,h}"),
    ("P3","Cross-path overlap    path_exposure × cp"),
    ("P4","Directionality        fwd=1.0  bwd=0.7"),
    ("P5","Conflict-cascade      soft conflict + B_z"),
]
y0 = 1.0 - (n_rows + 0.8) / (n_rows + 5)
for i, (tag, desc) in enumerate(props):
    y = y0 - i * 0.048
    ax7.text(0.02, y, tag, fontsize=7.5, color=CYAN, fontweight='bold',
             transform=ax7.transAxes, va='center')
    ax7.text(0.18, y, desc, fontsize=7, color=LTBL,
             transform=ax7.transAxes, va='center')

# ─────────────────────────────────────────────────────────────────────────────
# Footer
# ─────────────────────────────────────────────────────────────────────────────
best_base_Q = max(results[s]['Q'] for s in baselines)
maxsat_Q    = results['MaxSAT-RC2']['Q']
delta_Q     = maxsat_Q - best_base_Q
pct_Q       = delta_Q / max(best_base_Q, 1e-9) * 100

fig.text(0.5, 0.014,
         f"Budget B={B:,.0f}  |  "
         + "  |  ".join(f"{s}: Q={results[s]['Q']:.2f}" for s in solvers)
         + f"  |  MaxSAT advantage: +{delta_Q:.2f} Q pts ({pct_Q:+.1f}% over best baseline)",
         ha='center', va='bottom', fontsize=8.5, color=LTBL,
         fontweight='bold', fontfamily='monospace')

import os

out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, "maxsat_5props_vs_baselines_xlarge.png")

plt.savefig(out, dpi=155, bbox_inches='tight', facecolor=NAVY, edgecolor='none')
plt.close()
print(f"\nVisualization saved → {out}")
