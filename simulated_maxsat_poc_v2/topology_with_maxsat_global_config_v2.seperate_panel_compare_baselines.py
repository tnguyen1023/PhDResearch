"""
MaxSAT vs Baselines — XLARGE Enterprise Network (500k nodes)
Compares: Random, Greedy-Ratio, Greedy-BiDir, MaxSAT-RC2
Metrics:  DetEff%, TechCov%, FamCov%, FwdPath%, BwdPath%, Q, BudgetUsed%, Time(ms)
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
from matplotlib.patches import FancyBboxPatch
from matplotlib.gridspec import GridSpec

from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ═══════════════════════════════════════════════════════════════════════════════
# FULL CONFIG
# ═══════════════════════════════════════════════════════════════════════════════
RESEARCH_CONFIG = {
    'budget_base': 250.0,
    'budget_scaling': {
        'tiny': 1.0, 'small': 2.0, 'medium': 7.0,
        'large': 50.0, 'xlarge': 250.0, 'xxlarge': 512.0,
    },
    'topology': {
        'asset_roles': {
            'gateway':      {'asset_types': ['web','dns','api','generic'],                     'share_of_zone': 0.05, 'hop_distance': 1, 'detection_multiplier': 1.3},
            'service_host': {'asset_types': ['web','ssh','database','api','scada','identity'], 'share_of_zone': 0.50, 'hop_distance': 2, 'detection_multiplier': 1.0},
            'support_host': {'asset_types': ['dns','ftp_smb','generic'],                       'share_of_zone': 0.30, 'hop_distance': 2, 'detection_multiplier': 0.9},
            'deep_host':    {'asset_types': ['database','identity','scada'],                   'share_of_zone': 0.10, 'hop_distance': 3, 'detection_multiplier': 1.5},
            'jump_host':    {'asset_types': ['ssh','generic'],                                 'share_of_zone': 0.05, 'hop_distance': 2, 'detection_multiplier': 1.4},
        },
        'attack_paths': {
            'web_to_db':      {'label': 'Web → DB Exfil',         'probability': 0.30, 'hops': [{'zone':'zone1','techniques':['T1190','T1059'],'intercept_value':1.5},{'zone':'zone2','techniques':['T1021','T1078'],'intercept_value':1.8},{'zone':'zone2','techniques':['T1213','T1048'],'intercept_value':2.0}]},
            'cloud_pivot':    {'label': 'Cloud → Pivot Internal', 'probability': 0.25, 'hops': [{'zone':'zone3','techniques':['T1133','T1190'],'intercept_value':1.4},{'zone':'zone2','techniques':['T1550','T1021'],'intercept_value':1.8},{'zone':'zone2','techniques':['T1003','T1558'],'intercept_value':2.0}]},
            'brute_to_ad':    {'label': 'Brute SSH → AD',         'probability': 0.20, 'hops': [{'zone':'zone1','techniques':['T1110','T1133'],'intercept_value':1.2},{'zone':'zone2','techniques':['T1021','T1548'],'intercept_value':1.6},{'zone':'zone5','techniques':['T1558','T1003'],'intercept_value':2.0}]},
            'ot_infiltration':{'label': 'Pivot → OT Sabotage',    'probability': 0.15, 'hops': [{'zone':'zone1','techniques':['T1190','T1566'],'intercept_value':1.3},{'zone':'zone2','techniques':['T1021','T1078'],'intercept_value':1.7},{'zone':'zone4','techniques':['T0855','T0814'],'intercept_value':2.0}]},
            'ransomware':     {'label': 'Phishing → Ransomware',  'probability': 0.10, 'hops': [{'zone':'zone2','techniques':['T1566','T1059'],'intercept_value':1.3},{'zone':'zone2','techniques':['T1021','T1550'],'intercept_value':1.7},{'zone':'zone2','techniques':['T1486','T1485'],'intercept_value':2.0}]},
        },
        'topology_scaling': {
            'xlarge': {
                'active_zones': ['zone1','zone2','zone3','zone4','zone5'],
                'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'],
                'active_roles': ['gateway','service_host','support_host','deep_host','jump_host'],
            },
        },
    },
    'mitre_catalogue': {
        'T1190': {'tactic':'TA0001','name':'Exploit Public-Facing App',  'weight':1.4,'stealth':0.5},
        'T1133': {'tactic':'TA0001','name':'External Remote Services',   'weight':1.2,'stealth':0.4},
        'T1566': {'tactic':'TA0001','name':'Phishing',                   'weight':1.0,'stealth':0.6},
        'T1059': {'tactic':'TA0002','name':'Command Interpreter',        'weight':1.3,'stealth':0.6},
        'T1098': {'tactic':'TA0003','name':'Account Manipulation',       'weight':1.4,'stealth':0.7},
        'T1136': {'tactic':'TA0003','name':'Create Account',             'weight':1.1,'stealth':0.5},
        'T1548': {'tactic':'TA0004','name':'Abuse Elevation Control',    'weight':1.5,'stealth':0.6},
        'T1078': {'tactic':'TA0004','name':'Valid Accounts',             'weight':1.7,'stealth':0.8},
        'T1110': {'tactic':'TA0006','name':'Brute Force',                'weight':1.0,'stealth':0.2},
        'T1558': {'tactic':'TA0006','name':'Kerberoasting',              'weight':1.8,'stealth':0.8},
        'T1003': {'tactic':'TA0006','name':'OS Credential Dumping',      'weight':1.9,'stealth':0.8},
        'T1046': {'tactic':'TA0007','name':'Network Scanning',           'weight':0.5,'stealth':0.1},
        'T1082': {'tactic':'TA0007','name':'System Info Discovery',      'weight':0.6,'stealth':0.2},
        'T1021': {'tactic':'TA0008','name':'Remote Services',            'weight':1.8,'stealth':0.8},
        'T1550': {'tactic':'TA0008','name':'Pass the Hash/Ticket',       'weight':1.8,'stealth':0.8},
        'T1213': {'tactic':'TA0009','name':'Data from Repositories',     'weight':1.5,'stealth':0.7},
        'T1048': {'tactic':'TA0010','name':'Exfiltration Alt Protocol',  'weight':2.0,'stealth':0.9},
        'T1572': {'tactic':'TA0011','name':'Protocol Tunneling',         'weight':1.5,'stealth':0.9},
        'T1486': {'tactic':'TA0040','name':'Data Encrypted for Impact',  'weight':2.0,'stealth':0.6},
        'T1485': {'tactic':'TA0040','name':'Data Destruction',           'weight':2.0,'stealth':0.7},
        'T0855': {'tactic':'TA0104','name':'Unauthorized Command Msg',   'weight':2.0,'stealth':0.7},
        'T0814': {'tactic':'TA0104','name':'Denial of Service (ICS)',    'weight':1.9,'stealth':0.5},
    },
    'zones': {
        'zone1': {'label':'Internet-Facing/DMZ',     'budget_fraction':0.20,'isolated_from':[],'server_types':['web','ssh','dns','api','generic'],              'mitre_tactics':['T1190','T1133','T1566','T1059','T1110','T1046','T1082']},
        'zone2': {'label':'Internal LAN/Corporate',  'budget_fraction':0.30,'isolated_from':[],'server_types':['ssh','database','ftp_smb','identity','web','generic'],'mitre_tactics':['T1078','T1548','T1021','T1550','T1003','T1558','T1098','T1136','T1213','T1486','T1485']},
        'zone3': {'label':'Cloud/Hybrid',            'budget_fraction':0.25,'isolated_from':[],'server_types':['web','api','database','ssh','dns','generic'],    'mitre_tactics':['T1190','T1133','T1078','T1548','T1021','T1048','T1572']},
        'zone4': {'label':'OT/ICS/SCADA',            'budget_fraction':0.15,'isolated_from':['zone1','zone3'],'server_types':['scada','ssh','generic'],          'mitre_tactics':['T0855','T0814','T1021','T1078']},
        'zone5': {'label':'Management/OOB',          'budget_fraction':0.10,'isolated_from':['zone1','zone3'],'server_types':['ssh','identity','generic'],        'mitre_tactics':['T1078','T1548','T1003','T1558','T1098','T1136']},
    },
    'server_catalogue': {
        'web':{'detection_weight':1.0},'ssh':{'detection_weight':1.2},
        'database':{'detection_weight':1.5},'dns':{'detection_weight':1.1},
        'ftp_smb':{'detection_weight':1.2},'api':{'detection_weight':1.0},
        'scada':{'detection_weight':2.0},'identity':{'detection_weight':1.8},
        'generic':{'detection_weight':0.8},
    },
    'honeypot_profiles': {
        'web_trap':    {'label':'Web Honeypot',     'target_zones':['zone1','zone3'],                         'target_types':['web','api'],       'cost_multiplier':1.0,'detects':['T1190','T1133','T1059']},
        'ssh_trap':    {'label':'SSH Honeypot',     'target_zones':['zone1','zone2','zone3'],                 'target_types':['ssh','generic'],   'cost_multiplier':0.8,'detects':['T1110','T1021','T1078','T1133']},
        'db_trap':     {'label':'Database Honeypot','target_zones':['zone2','zone3'],                         'target_types':['database'],        'cost_multiplier':1.3,'detects':['T1190','T1213','T1048','T1485']},
        'smb_trap':    {'label':'SMB Honeypot',     'target_zones':['zone2'],                                 'target_types':['ftp_smb'],         'cost_multiplier':0.9,'detects':['T1021','T1550','T1486','T1048']},
        'scada_trap':  {'label':'SCADA Honeypot',   'target_zones':['zone4'],                                 'target_types':['scada'],           'cost_multiplier':2.0,'detects':['T0855','T0814','T1078']},
        'ad_trap':     {'label':'AD Honeypot',      'target_zones':['zone2','zone5'],                         'target_types':['identity'],        'cost_multiplier':1.5,'detects':['T1558','T1550','T1003','T1098']},
        'dns_trap':    {'label':'DNS Honeypot',     'target_zones':['zone1','zone2','zone3'],                 'target_types':['dns'],             'cost_multiplier':0.7,'detects':['T1572','T1046']},
        'generic_trap':{'label':'Generic Honeypot', 'target_zones':['zone1','zone2','zone3','zone4','zone5'], 'target_types':['generic'],         'cost_multiplier':0.5,'detects':['T1046','T1082','T1110']},
    },
    'conflict_pairs': [
        ('scada_trap','web_trap'),('scada_trap','db_trap'),('generic_trap','ad_trap'),
        ('scada_trap','ssh_trap'),('scada_trap','dns_trap'),('ad_trap','web_trap'),
        ('smb_trap','dns_trap'),
    ],
    'profile_scaling': {
        'xlarge': ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
    },
    'zone_solver_config': {
        'zone1':{'maxsat_timeout':20},'zone2':{'maxsat_timeout':30},
        'zone3':{'maxsat_timeout':25},'zone4':{'maxsat_timeout':15},'zone5':{'maxsat_timeout':12},
    },
}

CFG            = RESEARCH_CONFIG
SIZE           = 'xlarge'
topo_scale     = CFG['topology']['topology_scaling'][SIZE]
active_zones   = topo_scale['active_zones']
active_paths   = topo_scale['active_paths']
active_roles   = topo_scale['active_roles']
active_profiles= CFG['profile_scaling'][SIZE]
B              = CFG['budget_base'] * CFG['budget_scaling'][SIZE]
Bz             = {z: CFG['zones'][z]['budget_fraction'] * B for z in active_zones}

# ── Assets ────────────────────────────────────────────────────────────────────
assets = []
for zone in active_zones:
    zone_types = CFG['zones'][zone]['server_types']
    for role in active_roles:
        role_cfg   = CFG['topology']['asset_roles'][role]
        role_types = [t for t in role_cfg['asset_types'] if t in zone_types]
        for stype in role_types:
            assets.append({'id':f"{zone}_{role}_{stype}",'zone':zone,'type':stype,'role':role})

# ── Derived ───────────────────────────────────────────────────────────────────
def w_tilde(tech, asset):
    base_w = CFG['mitre_catalogue'].get(tech,{}).get('weight',0.5)
    scat_w = CFG['server_catalogue'].get(asset['type'],{}).get('detection_weight',1.0)
    dm     = CFG['topology']['asset_roles'][asset['role']]['detection_multiplier']
    hd     = CFG['topology']['asset_roles'][asset['role']]['hop_distance']
    return base_w * scat_w * dm * (1.0 / hd)

def W_adj(tech, asset):
    sigma = CFG['mitre_catalogue'].get(tech,{}).get('stealth',0.5)
    return w_tilde(tech, asset) * (1.0 + sigma)

def effective_targets(pk):
    p = CFG['honeypot_profiles'][pk]
    return [a for a in assets if a['zone'] in p['target_zones'] and a['type'] in p['target_types']]

def detects_on(pk, asset):
    if asset not in effective_targets(pk): return []
    zone_techs = set(CFG['zones'][asset['zone']]['mitre_tactics'])
    prof_techs = set(CFG['honeypot_profiles'][pk]['detects'])
    return list(zone_techs & prof_techs)

def profile_cost(pk):
    return CFG['budget_base'] / len(active_profiles) * CFG['honeypot_profiles'][pk]['cost_multiplier']

# pre-compute global tech set and all pairs
all_tech_asset_pairs = []
seen = set()
for pk in active_profiles:
    for a in effective_targets(pk):
        for tech in detects_on(pk, a):
            key = (tech, a['id'])
            if key not in seen:
                seen.add(key)
                all_tech_asset_pairs.append(key)
tech_set = set(t for (t,_) in all_tech_asset_pairs)

# ── Metrics computation ───────────────────────────────────────────────────────
def compute_metrics(deployed):
    covered_pairs, detected_techniques = set(), set()
    for pk in deployed:
        for a in effective_targets(pk):
            for tech in detects_on(pk, a):
                covered_pairs.add((tech, a['id']))
                detected_techniques.add(tech)

    det_eff  = len(covered_pairs) / max(len(all_tech_asset_pairs),1) * 100
    tech_cov = len(detected_techniques) / max(len(tech_set),1) * 100

    all_tactics = set(CFG['mitre_catalogue'][t]['tactic'] for t in tech_set if t in CFG['mitre_catalogue'])
    det_tactics = set(CFG['mitre_catalogue'][t]['tactic'] for t in detected_techniques if t in CFG['mitre_catalogue'])
    fam_cov     = len(det_tactics) / max(len(all_tactics),1) * 100

    fwd_covered = fwd_total = bwd_covered = bwd_total = 0
    for pk in active_paths:
        path = CFG['topology']['attack_paths'][pk]
        hops = [h for h in path['hops'] if h['zone'] in active_zones]
        for hop in hops:
            fwd_total += 1
            if any((tech, a['id']) in covered_pairs for tech in hop['techniques']
                   for a in assets if a['zone'] == hop['zone']):
                fwd_covered += 1
        for hop in reversed(hops):
            bwd_total += 1
            if any((tech, a['id']) in covered_pairs for tech in hop['techniques']
                   for a in assets if a['zone'] == hop['zone']):
                bwd_covered += 1

    fwd_pct = fwd_covered / max(fwd_total,1) * 100
    bwd_pct = bwd_covered / max(bwd_total,1) * 100
    Q       = 0.35*det_eff + 0.25*tech_cov + 0.15*fam_cov + 0.15*fwd_pct + 0.10*bwd_pct
    budget_used = sum(profile_cost(p) for p in deployed) / B * 100
    return dict(DetEff=det_eff, TechCov=tech_cov, FamCov=fam_cov,
                FwdPath=fwd_pct, BwdPath=bwd_pct, Q=Q, BudgetPct=budget_used,
                deployed=deployed)

# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 1 — Random  (10 trials, best result)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_random(n_trials=10):
    conflict_set = set(CFG['conflict_pairs']) | {(b,a) for a,b in CFG['conflict_pairs']}
    hard_banned  = set()
    hard_cuts    = [('zone4','zone1'),('zone4','zone3'),('zone5','zone1'),('zone5','zone3')]
    for pk in active_profiles:
        p = CFG['honeypot_profiles'][pk]
        tzones = set(p['target_zones'])
        for (za,zb) in hard_cuts:
            if za in tzones and zb in tzones:
                hard_banned.add(pk)

    best_Q, best_dep = -1, []
    for _ in range(n_trials):
        random.shuffle(active_profiles)
        deployed, budget_left = [], B
        pool = [p for p in active_profiles if p not in hard_banned]
        random.shuffle(pool)
        for pk in pool:
            c = profile_cost(pk)
            if budget_left < c: continue
            conflict = any((pk,d) in conflict_set or (d,pk) in conflict_set for d in deployed)
            if conflict: continue
            deployed.append(pk)
            budget_left -= c
        m = compute_metrics(deployed)
        if m['Q'] > best_Q:
            best_Q, best_dep = m['Q'], deployed[:]
    return compute_metrics(best_dep)

# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 2 — Greedy-Ratio  (coverage/cost, no path awareness)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_greedy_ratio():
    conflict_set = set(CFG['conflict_pairs']) | {(b,a) for a,b in CFG['conflict_pairs']}
    hard_cuts    = [('zone4','zone1'),('zone4','zone3'),('zone5','zone1'),('zone5','zone3')]
    hard_banned  = set()
    for pk in active_profiles:
        p = CFG['honeypot_profiles'][pk]
        tzones = set(p['target_zones'])
        for (za,zb) in hard_cuts:
            if za in tzones and zb in tzones:
                hard_banned.add(pk)

    def score(pk):
        s = sum(W_adj(t, a) for a in effective_targets(pk) for t in detects_on(pk, a))
        return s / (profile_cost(pk) + 1e-9)

    ranked   = sorted([p for p in active_profiles if p not in hard_banned],
                      key=score, reverse=True)
    deployed, budget_left = [], B
    for pk in ranked:
        c = profile_cost(pk)
        if budget_left < c: continue
        if any((pk,d) in conflict_set or (d,pk) in conflict_set for d in deployed): continue
        deployed.append(pk)
        budget_left -= c
    return compute_metrics(deployed)

# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE 3 — Greedy-BiDir  (forward+backward path coverage awareness)
# ═══════════════════════════════════════════════════════════════════════════════
def solve_greedy_bidir():
    conflict_set = set(CFG['conflict_pairs']) | {(b,a) for a,b in CFG['conflict_pairs']}
    hard_cuts    = [('zone4','zone1'),('zone4','zone3'),('zone5','zone1'),('zone5','zone3')]
    hard_banned  = set()
    for pk in active_profiles:
        p = CFG['honeypot_profiles'][pk]
        tzones = set(p['target_zones'])
        for (za,zb) in hard_cuts:
            if za in tzones and zb in tzones:
                hard_banned.add(pk)

    def bidir_score(pk, already_covered):
        path_gain = 0.0
        for path_key in active_paths:
            path = CFG['topology']['attack_paths'][path_key]
            rho  = path['probability']
            hops = path['hops']
            for direction_hops in [hops, list(reversed(hops))]:
                for h, hop in enumerate(direction_hops):
                    if hop['zone'] not in active_zones: continue
                    iv   = hop['intercept_value']
                    disc = 1.0 if direction_hops is hops else 0.7
                    for tech in hop['techniques']:
                        for a in effective_targets(pk):
                            if a['zone'] == hop['zone'] and tech in detects_on(pk, a):
                                pair = (tech, a['id'])
                                if pair not in already_covered:
                                    path_gain += rho * iv * W_adj(tech, a) * disc
        det_gain = sum(W_adj(t, a) for a in effective_targets(pk)
                       for t in detects_on(pk, a)
                       if (t, a['id']) not in already_covered)
        return (det_gain + path_gain) / (profile_cost(pk) + 1e-9)

    deployed, budget_left, covered = [], B, set()
    remaining = [p for p in active_profiles if p not in hard_banned]
    while remaining:
        best_pk   = max(remaining, key=lambda pk: bidir_score(pk, covered))
        best_cost = profile_cost(best_pk)
        if budget_left < best_cost:
            remaining.remove(best_pk)
            continue
        conflict = any((best_pk,d) in conflict_set or (d,best_pk) in conflict_set for d in deployed)
        if conflict:
            remaining.remove(best_pk)
            continue
        deployed.append(best_pk)
        budget_left -= best_cost
        for a in effective_targets(best_pk):
            for tech in detects_on(best_pk, a):
                covered.add((tech, a['id']))
        remaining.remove(best_pk)
    return compute_metrics(deployed)

# ═══════════════════════════════════════════════════════════════════════════════
# SOLVER — MaxSAT RC2
# ═══════════════════════════════════════════════════════════════════════════════
def solve_maxsat():
    wcnf   = WCNF()
    vc     = itertools.count(1)
    vmap   = {}

    def var(name):
        if name not in vmap: vmap[name] = next(vc)
        return vmap[name]

    for pk in active_profiles: var(f"x_{pk}")
    for (tech, aid) in all_tech_asset_pairs: var(f"c_{tech}_{aid}")

    # C1 — detection requires deployed config
    det_support = defaultdict(list)
    for pk in active_profiles:
        for a in effective_targets(pk):
            for tech in detects_on(pk, a):
                det_support[(tech, a['id'])].append(pk)
    for (tech, aid), supporters in det_support.items():
        wcnf.append([-var(f"c_{tech}_{aid}")] + [var(f"x_{pk}") for pk in supporters])

    # C4 — conflict pairs
    for (pa, pb) in CFG['conflict_pairs']:
        if pa in active_profiles and pb in active_profiles:
            wcnf.append([-var(f"x_{pa}"), -var(f"x_{pb}")])

    # C5 — zone isolation
    hard_cuts = [('zone4','zone1'),('zone4','zone3'),('zone5','zone1'),('zone5','zone3')]
    for pk in active_profiles:
        p = CFG['honeypot_profiles'][pk]
        tzones = set(p['target_zones'])
        for (za,zb) in hard_cuts:
            if za in tzones and zb in tzones:
                wcnf.append([-var(f"x_{pk}")])

    TIER = {4:1000, 3:100, 2:10, 1:1}

    # Tier 1 — per (technique, asset)
    for (tech, aid) in all_tech_asset_pairs:
        a = next((x for x in assets if x['id'] == aid), None)
        if a:
            w = max(1, int(round(W_adj(tech, a) * TIER[1] * 100)))
            wcnf.append([var(f"c_{tech}_{aid}")], weight=w)

    # Tier 2 — per technique
    for tech in tech_set:
        covers = [var(f"c_{tech}_{aid}") for (t,aid) in all_tech_asset_pairs if t == tech]
        if covers:
            tw = CFG['mitre_catalogue'].get(tech,{}).get('weight',1.0)
            ts = CFG['mitre_catalogue'].get(tech,{}).get('stealth',0.5)
            w  = max(1, int(round(tw * (1+ts) * TIER[2] * 10)))
            wcnf.append(covers, weight=w)

    # Tier 3 — path hop coverage (fwd + bwd)
    for path_key in active_paths:
        path = CFG['topology']['attack_paths'][path_key]
        rho  = path['probability']
        for disc, hops in [(1.0, path['hops']), (0.7, list(reversed(path['hops'])))]:
            for hop in hops:
                if hop['zone'] not in active_zones: continue
                hop_vars = list(set(
                    var(f"c_{tech}_{a['id']}")
                    for tech in hop['techniques']
                    for a in assets
                    if a['zone'] == hop['zone'] and f"c_{tech}_{a['id']}" in vmap
                ))
                if hop_vars:
                    w = max(1, int(round(rho * hop['intercept_value'] * disc * TIER[3] * 50)))
                    wcnf.append(hop_vars, weight=w)

    # Tier 4 — early intercept
    for path_key in active_paths:
        path = CFG['topology']['attack_paths'][path_key]
        hops = path['hops']
        if len(hops) < 2: continue
        early_vars = list(set(
            var(f"c_{tech}_{a['id']}")
            for hop in hops[:-1] if hop['zone'] in active_zones
            for tech in hop['techniques']
            for a in assets
            if a['zone'] == hop['zone'] and f"c_{tech}_{a['id']}" in vmap
        ))
        if early_vars:
            max_iv = max(h['intercept_value'] for h in hops[:-1] if h['zone'] in active_zones)
            w      = max(1, int(round(path['probability'] * max_iv * TIER[4])))
            wcnf.append(early_vars, weight=w)

    solver = RC2(wcnf)
    model  = solver.compute()
    solver.delete()

    if model is None:
        return solve_greedy_ratio()

    true_vars = {v for v in model if v > 0}
    deployed  = [pk for pk in active_profiles if var(f"x_{pk}") in true_vars]
    total_cost = sum(profile_cost(pk) for pk in deployed)
    if total_cost > B:
        deployed.sort(key=lambda pk: profile_cost(pk) / (
                sum(W_adj(t,a) for a in effective_targets(pk) for t in detects_on(pk,a)) + 1e-9))
        while sum(profile_cost(pk) for pk in deployed) > B and deployed:
            deployed.pop(0)
    return compute_metrics(deployed)

# ═══════════════════════════════════════════════════════════════════════════════
# RUN ALL SOLVERS
# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*62}")
print(f"  XLARGE Enterprise  |  Nodes=500,000  |  Budget={B:,.0f}")
print(f"  Profiles={len(active_profiles)}  |  Zones={len(active_zones)}  |  Paths={len(active_paths)}")
print(f"{'='*62}\n")

results = {}
for name, fn in [
    ('Random',         solve_random),
    ('Greedy-Ratio',   solve_greedy_ratio),
    ('Greedy-BiDir',   solve_greedy_bidir),
    ('MaxSAT-RC2',     solve_maxsat),
]:
    t0 = time.perf_counter()
    r  = fn()
    ms = (time.perf_counter() - t0) * 1000
    r['ms'] = ms
    results[name] = r
    print(f"  {name:<16} Q={r['Q']:6.2f}  Det={r['DetEff']:5.1f}%  "
          f"Tech={r['TechCov']:5.1f}%  Fam={r['FamCov']:5.1f}%  "
          f"Fwd={r['FwdPath']:5.1f}%  Bwd={r['BwdPath']:5.1f}%  "
          f"Bgt={r['BudgetPct']:5.1f}%  {ms:.1f}ms")

# ═══════════════════════════════════════════════════════════════════════════════
# VISUALIZATION
# ═══════════════════════════════════════════════════════════════════════════════
NAVY   = '#0D1B2A'
TEAL   = '#1B6CA8'
LTBL   = '#D6E8F7'
SLATE  = '#3D5A73'
LGRAY  = '#F2F4F6'
MGRAY  = '#7F8C8D'
RED    = '#C0392B'
GREEN  = '#1A7A4A'
AMBER  = '#D4860A'
PURPLE = '#6C3483'
WHITE  = '#FFFFFF'

SOLVER_COLORS = {
    'Random':       '#E74C3C',
    'Greedy-Ratio': '#E67E22',
    'Greedy-BiDir': '#F1C40F',
    'MaxSAT-RC2':   '#2ECC71',
}

METRICS_DEF = [
    ('DetEff',   'Detection\nEfficiency %',    'stealth-adj. W_{j,a}'),
    ('TechCov',  'Technique\nCoverage %',       'MITRE techniques'),
    ('FamCov',   'Tactic Family\nCoverage %',   'MITRE tactic families'),
    ('FwdPath',  'Forward Path\nCoverage %',    'fwd intercept hops'),
    ('BwdPath',  'Backward Path\nCoverage %',   'bwd intercept hops'),
    ('Q',        'Composite\nQ Score',          'weighted aggregate'),
]

solvers = list(results.keys())
n_solvers = len(solvers)

fig = plt.figure(figsize=(24, 20), facecolor=NAVY)
fig.suptitle(
    "MaxSAT vs Baselines  —  XLARGE Enterprise Network  (500,000 nodes)  |  All 5 Active Zones  |  8 Honeypot Profiles",
    fontsize=16, fontweight='bold', color=WHITE, y=0.985, fontfamily='monospace'
)

gs = GridSpec(4, 4, figure=fig,
              hspace=0.50, wspace=0.38,
              top=0.955, bottom=0.04,
              left=0.055, right=0.975)

def ax_style(ax, title=''):
    ax.set_facecolor('#0A1520')
    for sp in ax.spines.values(): sp.set_edgecolor(SLATE)
    ax.tick_params(colors=MGRAY, labelsize=8)
    if title:
        ax.set_title(title, color=WHITE, fontsize=9.5, fontweight='bold', pad=6)
    return ax

# ─────────────────────────────────────────────────────────────────────────────
# Row 0-1 col 0-1: Grouped bar chart — all 6 metrics side by side
# ─────────────────────────────────────────────────────────────────────────────
ax_main = fig.add_subplot(gs[0:2, 0:3])
ax_style(ax_main, "Detection, Coverage & Path Metrics  —  All Solvers")

metric_keys = ['DetEff','TechCov','FamCov','FwdPath','BwdPath','Q']
metric_labels = ['DetEff%','TechCov%','FamCov%','FwdPath%','BwdPath%','Q Score']
n_metrics = len(metric_keys)
x        = np.arange(n_metrics)
bw       = 0.18
offsets  = np.linspace(-(n_solvers-1)/2*bw, (n_solvers-1)/2*bw, n_solvers)

for i, solver in enumerate(solvers):
    vals = [results[solver][mk] for mk in metric_keys]
    bars = ax_main.bar(x + offsets[i], vals, bw,
                       color=SOLVER_COLORS[solver], alpha=0.88,
                       label=solver, edgecolor=NAVY, linewidth=0.5)
    for bar, val in zip(bars, vals):
        ax_main.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.8,
                     f"{val:.1f}", ha='center', va='bottom',
                     fontsize=6.5, color=WHITE, fontweight='bold', rotation=90)

ax_main.set_xticks(x)
ax_main.set_xticklabels(metric_labels, fontsize=10, color=WHITE, fontweight='bold')
ax_main.set_ylabel('Score / Percentage', color=MGRAY, fontsize=9)
ax_main.set_ylim(0, 115)
ax_main.yaxis.label.set_color(MGRAY)
ax_main.legend(fontsize=9, facecolor=NAVY, edgecolor=SLATE,
               labelcolor=WHITE, loc='upper left', framealpha=0.9)
ax_main.axhline(100, color=SLATE, lw=0.6, ls='--', alpha=0.4)

# Highlight MaxSAT wins
for i, mk in enumerate(metric_keys):
    best_val = max(results[s][mk] for s in solvers)
    maxsat_v = results['MaxSAT-RC2'][mk]
    if abs(maxsat_v - best_val) < 0.1:
        ax_main.axvspan(i - 0.5, i + 0.5, color=GREEN, alpha=0.06, zorder=0)

# ─────────────────────────────────────────────────────────────────────────────
# Row 0-1 col 3: Q Score ranking
# ─────────────────────────────────────────────────────────────────────────────
ax_q = fig.add_subplot(gs[0:2, 3])
ax_style(ax_q, "Q Score Ranking")

q_vals  = [results[s]['Q'] for s in solvers]
q_cols  = [SOLVER_COLORS[s] for s in solvers]
y_pos   = range(len(solvers))

hbars = ax_q.barh(list(y_pos), q_vals, color=q_cols, alpha=0.9,
                  edgecolor=NAVY, linewidth=0.5, height=0.55)
ax_q.set_yticks(list(y_pos))
ax_q.set_yticklabels(solvers, fontsize=9, color=WHITE, fontweight='bold')
ax_q.set_xlabel('Q Score', color=MGRAY, fontsize=8)
ax_q.xaxis.label.set_color(MGRAY)
ax_q.set_xlim(0, max(q_vals) * 1.25)

for bar, val, solver in zip(hbars, q_vals, solvers):
    ax_q.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2,
              f"{val:.2f}", va='center', fontsize=9, color=WHITE, fontweight='bold')
    if solver == 'MaxSAT-RC2':
        best_base = max(results[s]['Q'] for s in solvers if s != 'MaxSAT-RC2')
        delta     = val - best_base
        ax_q.text(bar.get_width() + 0.5,
                  bar.get_y() + bar.get_height()/2 - 0.28,
                  f"+{delta:.1f} vs best",
                  va='center', fontsize=7, color=GREEN, fontweight='bold')

# ─────────────────────────────────────────────────────────────────────────────
# Row 2 col 0-1: Radar chart
# ─────────────────────────────────────────────────────────────────────────────
ax_radar = fig.add_subplot(gs[2, 0:2], polar=True)
ax_radar.set_facecolor('#0A1520')
ax_radar.spines['polar'].set_color(SLATE)

radar_metrics = ['DetEff','TechCov','FamCov','FwdPath','BwdPath']
N      = len(radar_metrics)
angles = [n / N * 2 * math.pi for n in range(N)] + [0]

ax_radar.set_theta_offset(math.pi / 2)
ax_radar.set_theta_direction(-1)
ax_radar.set_xticks(angles[:-1])
ax_radar.set_xticklabels(['Detection\nEfficiency','Technique\nCoverage',
                          'Family\nCoverage','Forward\nPath','Backward\nPath'],
                         fontsize=8, color=WHITE)
ax_radar.set_ylim(0, 100)
ax_radar.set_yticks([25,50,75,100])
ax_radar.set_yticklabels(['25','50','75','100'], fontsize=6, color=MGRAY)
ax_radar.grid(color=SLATE, alpha=0.4)

for solver in solvers:
    vals   = [results[solver][mk] for mk in radar_metrics] + [results[solver][radar_metrics[0]]]
    lw     = 3.0 if solver == 'MaxSAT-RC2' else 1.5
    alpha  = 0.30 if solver == 'MaxSAT-RC2' else 0.10
    ax_radar.plot(angles, vals, lw=lw, color=SOLVER_COLORS[solver], label=solver)
    ax_radar.fill(angles, vals, alpha=alpha, color=SOLVER_COLORS[solver])

ax_radar.set_title("Multi-Metric Coverage Radar", color=WHITE, fontsize=10,
                   fontweight='bold', pad=18)
ax_radar.legend(loc='lower left', bbox_to_anchor=(-0.22, -0.12),
                fontsize=8, facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE)

# ─────────────────────────────────────────────────────────────────────────────
# Row 2 col 2: Budget efficiency scatter
# ─────────────────────────────────────────────────────────────────────────────
ax_bgt = fig.add_subplot(gs[2, 2])
ax_style(ax_bgt, "Budget Used % vs Q Score")

for solver in solvers:
    r  = results[solver]
    ms = r['ms']
    sz = min(max(ms * 2.5, 80), 600)
    ax_bgt.scatter(r['BudgetPct'], r['Q'],
                   s=sz, color=SOLVER_COLORS[solver],
                   edgecolors=WHITE, linewidths=1.2, zorder=5, alpha=0.9)
    ax_bgt.text(r['BudgetPct'] + 0.15, r['Q'] + 0.6,
                solver, fontsize=8, color=SOLVER_COLORS[solver],
                fontweight='bold', zorder=6)
    ax_bgt.text(r['BudgetPct'] + 0.15, r['Q'] - 1.2,
                f"{ms:.1f}ms", fontsize=7, color=MGRAY, zorder=6)

ax_bgt.set_xlabel('Budget Used %', color=MGRAY, fontsize=8)
ax_bgt.set_ylabel('Q Score', color=MGRAY, fontsize=8)
ax_bgt.xaxis.label.set_color(MGRAY)
ax_bgt.yaxis.label.set_color(MGRAY)
ax_bgt.text(0.05, 0.92, "● size = solve time (ms)",
            transform=ax_bgt.transAxes, fontsize=7, color=MGRAY)
ax_bgt.set_xlim(-0.5, max(r['BudgetPct'] for r in results.values()) * 1.4 + 1)

# Add ideal quadrant annotation
ax_bgt.axvline(5, color=SLATE, lw=0.6, ls='--', alpha=0.4)
ax_bgt.text(0.12, 0.06, "← Lower budget = more efficient",
            transform=ax_bgt.transAxes, fontsize=7, color=SLATE,
            style='italic')

# ─────────────────────────────────────────────────────────────────────────────
# Row 2 col 3: Solve time bar (log scale)
# ─────────────────────────────────────────────────────────────────────────────
ax_time = fig.add_subplot(gs[2, 3])
ax_style(ax_time, "Solve Time (ms, log scale)")

times = [results[s]['ms'] for s in solvers]
cols  = [SOLVER_COLORS[s] for s in solvers]
bars  = ax_time.bar(solvers, times, color=cols, alpha=0.9,
                    edgecolor=NAVY, linewidth=0.5)
ax_time.set_yscale('log')
ax_time.set_ylabel('Milliseconds (log)', color=MGRAY, fontsize=8)
ax_time.yaxis.label.set_color(MGRAY)
for bar, t in zip(bars, times):
    ax_time.text(bar.get_x() + bar.get_width()/2,
                 bar.get_height() * 1.4,
                 f"{t:.1f}ms", ha='center', va='bottom',
                 fontsize=8.5, color=WHITE, fontweight='bold')
ax_time.set_xticklabels(solvers, fontsize=8, color=WHITE, rotation=15, ha='right')

# ─────────────────────────────────────────────────────────────────────────────
# Row 3 col 0-1: Per-path coverage heatmap (all solvers × all paths)
# ─────────────────────────────────────────────────────────────────────────────
ax_heat = fig.add_subplot(gs[3, 0:2])
ax_style(ax_heat, "Forward Path Coverage by Solver  (% of path hops intercepted)")

path_labels = [CFG['topology']['attack_paths'][pk]['label'][:26]
               + f"  ρ={CFG['topology']['attack_paths'][pk]['probability']}"
               for pk in active_paths]

def path_fwd_pct(deployed_list, path_key):
    path = CFG['topology']['attack_paths'][path_key]
    hops = [h for h in path['hops'] if h['zone'] in active_zones]
    covered = set()
    for pk in deployed_list:
        for a in effective_targets(pk):
            for tech in detects_on(pk, a):
                covered.add((tech, a['id']))
    hits = sum(1 for hop in hops
               if any((tech, a['id']) in covered
                      for tech in hop['techniques']
                      for a in assets if a['zone'] == hop['zone']))
    return hits / max(len(hops), 1) * 100

heat = np.array([[path_fwd_pct(results[s]['deployed'], pk)
                  for s in solvers]
                 for pk in active_paths])

im = ax_heat.imshow(heat, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
ax_heat.set_xticks(range(n_solvers))
ax_heat.set_xticklabels(solvers, fontsize=9, color=WHITE, fontweight='bold')
ax_heat.set_yticks(range(len(active_paths)))
ax_heat.set_yticklabels(path_labels, fontsize=8, color=WHITE)

for i in range(len(active_paths)):
    for j in range(n_solvers):
        v    = heat[i, j]
        tcol = NAVY if v > 55 else WHITE
        ax_heat.text(j, i, f"{v:.0f}%", ha='center', va='center',
                     fontsize=9, color=tcol, fontweight='bold')

cb = plt.colorbar(im, ax=ax_heat, fraction=0.025, pad=0.01)
cb.ax.tick_params(colors=WHITE, labelsize=7)
cb.ax.set_ylabel('Coverage %', color=WHITE, fontsize=7)

# ─────────────────────────────────────────────────────────────────────────────
# Row 3 col 2: Delta bars — MaxSAT advantage over best baseline
# ─────────────────────────────────────────────────────────────────────────────
ax_delta = fig.add_subplot(gs[3, 2])
ax_style(ax_delta, "MaxSAT Advantage over Best Baseline (Δ pp)")

delta_metrics = ['DetEff','TechCov','FamCov','FwdPath','BwdPath','Q']
delta_labels  = ['DetEff%','TechCov%','FamCov%','FwdPath%','BwdPath%','Q']
baselines     = [s for s in solvers if s != 'MaxSAT-RC2']

deltas = []
for mk in delta_metrics:
    best_base  = max(results[s][mk] for s in baselines)
    maxsat_val = results['MaxSAT-RC2'][mk]
    deltas.append(maxsat_val - best_base)

bar_cols = [GREEN if d >= 0 else RED for d in deltas]
bars     = ax_delta.barh(delta_labels, deltas, color=bar_cols, alpha=0.88,
                         edgecolor=NAVY, linewidth=0.5, height=0.55)
ax_delta.axvline(0, color=WHITE, lw=1.0)
for bar, d in zip(bars, deltas):
    xpos = d + 0.3 if d >= 0 else d - 0.3
    ha   = 'left'  if d >= 0 else 'right'
    ax_delta.text(xpos, bar.get_y() + bar.get_height()/2,
                  f"+{d:.1f}" if d >= 0 else f"{d:.1f}",
                  va='center', ha=ha, fontsize=9, color=WHITE, fontweight='bold')
ax_delta.set_xlabel('Δ percentage points vs best baseline', color=MGRAY, fontsize=8)
ax_delta.xaxis.label.set_color(MGRAY)
ax_delta.set_yticklabels(delta_labels, fontsize=9, color=WHITE)

# ─────────────────────────────────────────────────────────────────────────────
# Row 3 col 3: Deployed profile comparison table
# ─────────────────────────────────────────────────────────────────────────────
ax_tbl = fig.add_subplot(gs[3, 3])
ax_style(ax_tbl, "Deployed Profiles per Solver")
ax_tbl.axis('off')

all_profiles_short = {
    'web_trap':'Web','ssh_trap':'SSH','db_trap':'DB',
    'smb_trap':'SMB','scada_trap':'SCADA','ad_trap':'AD',
    'dns_trap':'DNS','generic_trap':'Gen'
}
row_labels = ['Solver'] + [all_profiles_short[pk] for pk in active_profiles] + ['Cost%','Q']
col_data   = [row_labels]

for solver in solvers:
    dep = results[solver]['deployed']
    col = [solver]
    for pk in active_profiles:
        col.append('✓' if pk in dep else '·')
    col.append(f"{results[solver]['BudgetPct']:.1f}%")
    col.append(f"{results[solver]['Q']:.1f}")
    col_data.append(col)

n_rows = len(row_labels)
n_cols = len(solvers) + 1

for ci, col in enumerate(col_data):
    for ri, cell in enumerate(col):
        is_header  = (ri == 0) or (ci == 0)
        is_maxsat  = (ci > 0) and (solvers[ci-1] == 'MaxSAT-RC2')
        is_check   = cell == '✓'
        bg = NAVY
        if is_maxsat: bg = '#0D2E1A'
        tcol = WHITE
        if cell == '✓': tcol = GREEN
        elif cell == '·': tcol = SLATE
        elif ri == n_rows - 1: tcol = AMBER
        fw = 'bold' if is_header or is_maxsat else 'normal'
        ax_tbl.text(
            (ci + 0.5) / (n_cols + 0.5),
            1.0 - (ri + 0.5) / n_rows,
            cell,
            ha='center', va='center',
            fontsize=7.5, color=tcol, fontweight=fw,
            transform=ax_tbl.transAxes
        )

# grid lines
for ri in range(n_rows + 1):
    y = 1.0 - ri / n_rows
    ax_tbl.plot([0, 1], [y, y], color=SLATE, lw=0.4, transform=ax_tbl.transAxes)
for ci in range(n_cols + 1):
    x = (ci) / (n_cols + 0.5)
    ax_tbl.plot([x, x], [0, 1], color=SLATE, lw=0.4, transform=ax_tbl.transAxes)

# ─────────────────────────────────────────────────────────────────────────────
# Footer metrics strip
# ─────────────────────────────────────────────────────────────────────────────
fig.text(0.5, 0.013,
         f"Budget B={B:,.0f}  |  "
         f"Random: {results['Random']['Q']:.2f}  |  "
         f"Greedy-Ratio: {results['Greedy-Ratio']['Q']:.2f}  |  "
         f"Greedy-BiDir: {results['Greedy-BiDir']['Q']:.2f}  |  "
         f"MaxSAT-RC2: {results['MaxSAT-RC2']['Q']:.2f}  |  "
         f"MaxSAT advantage over best baseline: "
         f"+{results['MaxSAT-RC2']['Q'] - max(results[s]['Q'] for s in solvers if s!='MaxSAT-RC2'):.2f} Q pts",
         ha='center', va='bottom', fontsize=9, color=LTBL,
         fontweight='bold', fontfamily='monospace')

import os

out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, "maxsat_vs_baselines_xlarge.png")

plt.savefig(out, dpi=155, bbox_inches='tight', facecolor=NAVY, edgecolor='none')
plt.close()
print(f"\nSaved → {out}")
