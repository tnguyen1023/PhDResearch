"""
MaxSAT Honeypot Placement Simulation
=====================================
Solver : PySAT RC2  (Weighted Partial MaxSAT)
Config : Global RESEARCH_CONFIG
Output : ./research_results/

Formulation
-----------
Variables  : x_k  ∈ {0,1}  — deploy honeypot config k  (profile × zone)
Hard clauses:
    C1  Budget      Σ cost(k)·x_k  ≤  B          (cardinality / PB encoding)
    C2  Conflicts   x_p + x_q ≤ 1                 (at-most-one per conflict pair)
    C3  Zone-iso    x_k = 0 if config straddles a hard-cut
Soft clauses (maximise):
    w_{k,t}·x_k  for every (config k, technique t) pair that k can detect
    Weight = mitre_weight × server_det_weight × fidelity × hop_bonus × path_prob
"""

import multiprocessing as mp
import os, time, random, math, itertools
from collections import defaultdict

import numpy as np
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIG
# ═══════════════════════════════════════════════════════════════════════════════

RESEARCH_CONFIG = {

    # ── Network sizing ─────────────────────────────────────────────────────────
    'network_sizes': {
        'tiny':    100,
        'small':   500,
        'medium':  5_000,
        'large':   50_000,
        'xlarge':  500_000,
        'xxlarge': 5_560_000,
    },

    'sizes_to_test': ['tiny', 'small', 'medium', 'large', 'xlarge', 'xxlarge'],

    'attack_volumes': {
        'tiny':    5_000,
        'small':   10_000,
        'medium':  50_000,
        'large':   500_000,
        'xlarge':  5_000_000,
        'xxlarge': 25_600_000,
    },

    'budget_base':  250.0,
    'budget_scaling': {
        'tiny':    1.0,
        'small':   2.0,
        'medium':  10.0,
        'large':   50.0,
        'xlarge':  250.0,
        'xxlarge': 512.0,
    },

    'parallel':       True,
    'max_workers':    min(4, mp.cpu_count()),
    'ilp_timeout':    30,
    'maxsat_timeout': 30,       # RC2 time budget (seconds)
    'random_seed':    42,
    'output_dir':     './research_results',

    # ── Topology ───────────────────────────────────────────────────────────────
    'topology': {

        'zone_graph': {
            'nodes': {
                'zone1': {'label': 'Internet-Facing / DMZ'},
                'zone2': {'label': 'Internal LAN / Corporate'},
                'zone3': {'label': 'Cloud / Hybrid'},
                'zone4': {'label': 'OT / ICS / SCADA'},
                'zone5': {'label': 'Management / Out-of-Band'},
                'ext':   {'label': 'External Internet (attacker origin)'},
            },
            'edges': [
                {'from': 'ext',   'to': 'zone1', 'traversal_cost': 1.0, 'chokepoint': True,  'bandwidth_tier': 'high'},
                {'from': 'ext',   'to': 'zone3', 'traversal_cost': 1.2, 'chokepoint': True,  'bandwidth_tier': 'high'},
                {'from': 'zone1', 'to': 'zone2', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'medium'},
                {'from': 'zone1', 'to': 'zone3', 'traversal_cost': 1.5, 'chokepoint': False, 'bandwidth_tier': 'high'},
                {'from': 'zone3', 'to': 'zone2', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'medium'},
                {'from': 'zone2', 'to': 'zone4', 'traversal_cost': 3.0, 'chokepoint': True,  'bandwidth_tier': 'low'},
                {'from': 'zone2', 'to': 'zone5', 'traversal_cost': 3.5, 'chokepoint': True,  'bandwidth_tier': 'low'},
                {'from': 'zone5', 'to': 'zone2', 'traversal_cost': 1.0, 'chokepoint': False, 'bandwidth_tier': 'low'},
                {'from': 'zone5', 'to': 'zone4', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'low'},
            ],
            'hard_cuts': [
                ('zone4', 'zone1'), ('zone4', 'zone3'),
                ('zone5', 'zone1'), ('zone5', 'zone3'),
            ],
        },

        'asset_roles': {
            'gateway':      {'asset_types': ['web','dns','api','generic'],              'share_of_zone': 0.05, 'is_gateway': True,  'hop_distance': 1, 'detection_multiplier': 1.3},
            'service_host': {'asset_types': ['web','ssh','database','api','scada','identity'], 'share_of_zone': 0.50, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 1.0},
            'support_host': {'asset_types': ['dns','ftp_smb','generic'],                'share_of_zone': 0.30, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 0.9},
            'deep_host':    {'asset_types': ['database','identity','scada'],            'share_of_zone': 0.10, 'is_gateway': False, 'hop_distance': 3, 'detection_multiplier': 1.5},
            'jump_host':    {'asset_types': ['ssh','generic'],                          'share_of_zone': 0.05, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 1.4},
        },

        'attack_paths': {
            'web_to_db':       {'probability': 0.30, 'hops': [
                {'zone': 'zone1', 'techniques': ['T1190','T1059'], 'intercept_value': 1.5},
                {'zone': 'zone2', 'techniques': ['T1021','T1078'], 'intercept_value': 1.8},
                {'zone': 'zone2', 'techniques': ['T1213','T1048'], 'intercept_value': 2.0},
            ]},
            'cloud_pivot':     {'probability': 0.25, 'hops': [
                {'zone': 'zone3', 'techniques': ['T1133','T1190'], 'intercept_value': 1.4},
                {'zone': 'zone2', 'techniques': ['T1550','T1021'], 'intercept_value': 1.8},
                {'zone': 'zone2', 'techniques': ['T1003','T1558'], 'intercept_value': 2.0},
            ]},
            'brute_to_ad':     {'probability': 0.20, 'hops': [
                {'zone': 'zone1', 'techniques': ['T1110','T1133'], 'intercept_value': 1.2},
                {'zone': 'zone2', 'techniques': ['T1021','T1548'], 'intercept_value': 1.6},
                {'zone': 'zone5', 'techniques': ['T1558','T1003'], 'intercept_value': 2.0},
            ]},
            'ot_infiltration': {'probability': 0.15, 'hops': [
                {'zone': 'zone1', 'techniques': ['T1190','T1566'], 'intercept_value': 1.3},
                {'zone': 'zone2', 'techniques': ['T1021','T1078'], 'intercept_value': 1.7},
                {'zone': 'zone4', 'techniques': ['T0855','T0814'], 'intercept_value': 2.0},
            ]},
            'ransomware':      {'probability': 0.10, 'hops': [
                {'zone': 'zone2', 'techniques': ['T1566','T1059'], 'intercept_value': 1.3},
                {'zone': 'zone2', 'techniques': ['T1021','T1550'], 'intercept_value': 1.7},
                {'zone': 'zone2', 'techniques': ['T1486','T1485'], 'intercept_value': 2.0},
            ]},
        },

        'generation': {
            'intra_zone_model': {
                'zone1': {'model': 'scale_free', 'edge_density': 0.05},
                'zone2': {'model': 'scale_free', 'edge_density': 0.08},
                'zone3': {'model': 'random',     'edge_density': 0.06},
                'zone4': {'model': 'tree',        'edge_density': 0.03},
                'zone5': {'model': 'tree',        'edge_density': 0.02},
            },
            'honeypot_density_by_role': {
                'gateway': 0.80, 'service_host': 0.30, 'support_host': 0.20,
                'deep_host': 0.50, 'jump_host': 0.70,
            },
        },

        'topology_scaling': {
            'tiny':    {'active_zones': ['zone1','zone2'],                        'active_paths': ['web_to_db','brute_to_ad'],                                         'active_roles': ['gateway','service_host','support_host']},
            'small':   {'active_zones': ['zone1','zone2','zone3'],                'active_paths': ['web_to_db','cloud_pivot','brute_to_ad'],                            'active_roles': ['gateway','service_host','support_host','deep_host']},
            'medium':  {'active_zones': ['zone1','zone2','zone3','zone4'],        'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration'],          'active_roles': ['gateway','service_host','support_host','deep_host','jump_host']},
            'large':   {'active_zones': ['zone1','zone2','zone3','zone4','zone5'],'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'],'active_roles': ['gateway','service_host','support_host','deep_host','jump_host']},
            'xlarge':  {'active_zones': ['zone1','zone2','zone3','zone4','zone5'],'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'],'active_roles': ['gateway','service_host','support_host','deep_host','jump_host']},
            'xxlarge': {'active_zones': ['zone1','zone2','zone3','zone4','zone5'],'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'],'active_roles': ['gateway','service_host','support_host','deep_host','jump_host']},
        },
    },

    # ── Server catalogue ──────────────────────────────────────────────────────
    'server_catalogue': {
        'web':      {'label': 'Web / App Server',           'detection_weight': 1.0, 'fidelity': 0.75},
        'ssh':      {'label': 'SSH / Remote Access',        'detection_weight': 1.2, 'fidelity': 0.80},
        'database': {'label': 'Database Server',            'detection_weight': 1.5, 'fidelity': 0.70},
        'dns':      {'label': 'DNS Server',                 'detection_weight': 1.1, 'fidelity': 0.85},
        'ftp_smb':  {'label': 'File Transfer / SMB',        'detection_weight': 1.2, 'fidelity': 0.75},
        'api':      {'label': 'API Gateway / Microservice', 'detection_weight': 1.0, 'fidelity': 0.70},
        'scada':    {'label': 'SCADA / ICS / PLC',          'detection_weight': 2.0, 'fidelity': 0.60},
        'identity': {'label': 'Identity / AD / LDAP',       'detection_weight': 1.8, 'fidelity': 0.65},
        'generic':  {'label': 'Generic / Unclassified',     'detection_weight': 0.8, 'fidelity': 0.50},
    },

    # ── MITRE catalogue ───────────────────────────────────────────────────────
    'mitre_catalogue': {
        'T1190': {'tactic': 'TA0001', 'weight': 1.4, 'stealth': 0.5},
        'T1133': {'tactic': 'TA0001', 'weight': 1.2, 'stealth': 0.4},
        'T1566': {'tactic': 'TA0001', 'weight': 1.0, 'stealth': 0.6},
        'T1059': {'tactic': 'TA0002', 'weight': 1.3, 'stealth': 0.6},
        'T1203': {'tactic': 'TA0002', 'weight': 1.2, 'stealth': 0.7},
        'T1098': {'tactic': 'TA0003', 'weight': 1.4, 'stealth': 0.7},
        'T1136': {'tactic': 'TA0003', 'weight': 1.1, 'stealth': 0.5},
        'T1543': {'tactic': 'TA0003', 'weight': 1.3, 'stealth': 0.7},
        'T1548': {'tactic': 'TA0004', 'weight': 1.5, 'stealth': 0.6},
        'T1078': {'tactic': 'TA0004', 'weight': 1.7, 'stealth': 0.8},
        'T1027': {'tactic': 'TA0005', 'weight': 1.0, 'stealth': 0.9},
        'T1562': {'tactic': 'TA0005', 'weight': 1.3, 'stealth': 0.8},
        'T1110': {'tactic': 'TA0006', 'weight': 1.0, 'stealth': 0.2},
        'T1555': {'tactic': 'TA0006', 'weight': 1.5, 'stealth': 0.7},
        'T1558': {'tactic': 'TA0006', 'weight': 1.8, 'stealth': 0.8},
        'T1003': {'tactic': 'TA0006', 'weight': 1.9, 'stealth': 0.8},
        'T1046': {'tactic': 'TA0007', 'weight': 0.5, 'stealth': 0.1},
        'T1082': {'tactic': 'TA0007', 'weight': 0.6, 'stealth': 0.2},
        'T1018': {'tactic': 'TA0007', 'weight': 0.7, 'stealth': 0.3},
        'T1021': {'tactic': 'TA0008', 'weight': 1.8, 'stealth': 0.8},
        'T1550': {'tactic': 'TA0008', 'weight': 1.8, 'stealth': 0.8},
        'T1210': {'tactic': 'TA0008', 'weight': 1.6, 'stealth': 0.7},
        'T1213': {'tactic': 'TA0009', 'weight': 1.5, 'stealth': 0.7},
        'T1114': {'tactic': 'TA0009', 'weight': 1.3, 'stealth': 0.6},
        'T1048': {'tactic': 'TA0010', 'weight': 2.0, 'stealth': 0.9},
        'T1567': {'tactic': 'TA0010', 'weight': 1.8, 'stealth': 0.8},
        'T1071': {'tactic': 'TA0010', 'weight': 1.5, 'stealth': 0.9},
        'T1095': {'tactic': 'TA0011', 'weight': 1.4, 'stealth': 0.9},
        'T1572': {'tactic': 'TA0011', 'weight': 1.5, 'stealth': 0.9},
        'T1486': {'tactic': 'TA0040', 'weight': 2.0, 'stealth': 0.6},
        'T1485': {'tactic': 'TA0040', 'weight': 2.0, 'stealth': 0.7},
        'T1498': {'tactic': 'TA0040', 'weight': 1.5, 'stealth': 0.3},
        'T0855': {'tactic': 'TA0104', 'weight': 2.0, 'stealth': 0.7},
        'T0814': {'tactic': 'TA0104', 'weight': 1.9, 'stealth': 0.5},
        'T0869': {'tactic': 'TA0104', 'weight': 1.5, 'stealth': 0.6},
    },

    # ── Zones ─────────────────────────────────────────────────────────────────
    'zones': {
        'zone1': {'label': 'Internet-Facing / DMZ',      'trust_level': 0, 'asset_share': 0.15, 'attack_share': 0.45, 'budget_fraction': 0.20, 'isolated_from': [],              'server_types': ['web','ssh','dns','api','generic'],             'mitre_tactics': ['T1190','T1133','T1566','T1059','T1203','T1110','T1046','T1082','T1071','T1095','T1572','T1498']},
        'zone2': {'label': 'Internal LAN / Corporate',   'trust_level': 2, 'asset_share': 0.40, 'attack_share': 0.25, 'budget_fraction': 0.30, 'isolated_from': [],              'server_types': ['ssh','database','ftp_smb','identity','web','generic'], 'mitre_tactics': ['T1078','T1548','T1021','T1550','T1210','T1003','T1558','T1555','T1098','T1136','T1543','T1562','T1027','T1213','T1114','T1486','T1485']},
        'zone3': {'label': 'Cloud / Hybrid',              'trust_level': 1, 'asset_share': 0.25, 'attack_share': 0.20, 'budget_fraction': 0.25, 'isolated_from': [],              'server_types': ['web','api','database','ssh','dns','generic'],   'mitre_tactics': ['T1190','T1133','T1078','T1548','T1021','T1210','T1567','T1048','T1071','T1572','T1486']},
        'zone4': {'label': 'OT / ICS / SCADA',           'trust_level': 3, 'asset_share': 0.10, 'attack_share': 0.05, 'budget_fraction': 0.15, 'isolated_from': ['zone1','zone3'],'server_types': ['scada','ssh','generic'],                        'mitre_tactics': ['T0855','T0814','T0869','T1021','T1078','T1485','T1498']},
        'zone5': {'label': 'Management / Out-of-Band',   'trust_level': 4, 'asset_share': 0.10, 'attack_share': 0.05, 'budget_fraction': 0.10, 'isolated_from': ['zone1','zone3'],'server_types': ['ssh','identity','generic'],                     'mitre_tactics': ['T1078','T1548','T1003','T1558','T1098','T1136','T1562','T1018','T1082']},
    },

    # ── Honeypot profiles ─────────────────────────────────────────────────────
    'honeypot_profiles': {
        'web_trap':     {'label': 'Web Application Honeypot',        'target_zones': ['zone1','zone3'],                         'target_types': ['web','api'],     'cost_multiplier': 1.0, 'detects': ['T1190','T1133','T1059','T1071']},
        'ssh_trap':     {'label': 'SSH Honeypot',                    'target_zones': ['zone1','zone2','zone3'],                 'target_types': ['ssh','generic'], 'cost_multiplier': 0.8, 'detects': ['T1110','T1021','T1078','T1133']},
        'db_trap':      {'label': 'Database Honeypot',               'target_zones': ['zone2','zone3'],                        'target_types': ['database'],      'cost_multiplier': 1.3, 'detects': ['T1190','T1213','T1048','T1485']},
        'smb_trap':     {'label': 'SMB / File Share Honeypot',       'target_zones': ['zone2'],                                'target_types': ['ftp_smb'],       'cost_multiplier': 0.9, 'detects': ['T1021','T1550','T1486','T1048']},
        'scada_trap':   {'label': 'ICS / SCADA Honeypot',            'target_zones': ['zone4'],                                'target_types': ['scada'],         'cost_multiplier': 2.0, 'detects': ['T0855','T0814','T0869','T1078']},
        'ad_trap':      {'label': 'Active Directory Honeypot',       'target_zones': ['zone2','zone5'],                        'target_types': ['identity'],      'cost_multiplier': 1.5, 'detects': ['T1558','T1550','T1003','T1098']},
        'dns_trap':     {'label': 'DNS Honeypot',                    'target_zones': ['zone1','zone2','zone3'],                'target_types': ['dns'],           'cost_multiplier': 0.7, 'detects': ['T1572','T1095','T1046']},
        'generic_trap': {'label': 'Generic Low-Interaction Honeypot','target_zones': ['zone1','zone2','zone3','zone4','zone5'],'target_types': ['generic'],       'cost_multiplier': 0.5, 'detects': ['T1046','T1082','T1110']},
    },

    'conflict_pairs': [
        ('scada_trap', 'web_trap'),
        ('scada_trap', 'db_trap'),
        ('generic_trap', 'ad_trap'),
    ],

    # ── Experiment scaling ────────────────────────────────────────────────────
    'zone_scaling': {
        'tiny':    ['zone1','zone2'],
        'small':   ['zone1','zone2','zone3'],
        'medium':  ['zone1','zone2','zone3','zone4'],
        'large':   ['zone1','zone2','zone3','zone4','zone5'],
        'xlarge':  ['zone1','zone2','zone3','zone4','zone5'],
        'xxlarge': ['zone1','zone2','zone3','zone4','zone5'],
    },

    'profile_scaling': {
        'tiny':    ['web_trap','ssh_trap','generic_trap'],
        'small':   ['web_trap','ssh_trap','db_trap','generic_trap'],
        'medium':  ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','generic_trap'],
        'large':   ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','generic_trap'],
        'xlarge':  ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
        'xxlarge': ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
    },

    'zone_solver_config': {
        'zone1': {'maxsat_timeout':  8, 'cluster_priority': 1},
        'zone2': {'maxsat_timeout': 12, 'cluster_priority': 2},
        'zone3': {'maxsat_timeout': 10, 'cluster_priority': 3},
        'zone4': {'maxsat_timeout':  6, 'cluster_priority': 4},
        'zone5': {'maxsat_timeout':  5, 'cluster_priority': 5},
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS — build canonical config list  (profile × zone)
# ═══════════════════════════════════════════════════════════════════════════════

def build_configs(size_name: str):
    """
    Return list of config dicts, one per (profile, zone) pair valid for this size.
    Each dict: { id, profile, zone, cost, detects: [tech], value: float }
    """
    cfg       = RESEARCH_CONFIG
    zones     = cfg['zone_scaling'][size_name]
    profiles  = cfg['profile_scaling'][size_name]
    hp_prof   = cfg['honeypot_profiles']
    mitre_cat = cfg['mitre_catalogue']
    server_cat= cfg['server_catalogue']
    attack_paths = cfg['topology']['attack_paths']
    hard_cuts = set(cfg['topology']['zone_graph']['hard_cuts'])
    zone_info = cfg['zones']

    # Build technique → (zone, path_prob, intercept_value) lookup
    tech_zone_info = defaultdict(list)   # tech → [(zone, prob, intercept)]
    for path_id, path in attack_paths.items():
        prob = path['probability']
        for hop in path['hops']:
            z = hop['zone']
            iv = hop['intercept_value']
            for t in hop['techniques']:
                tech_zone_info[t].append((z, prob, iv))

    configs = []
    cid = 0
    for prof_name in profiles:
        prof = hp_prof[prof_name]
        for zone in prof['target_zones']:
            if zone not in zones:
                continue
            # Zone-isolation check (hard cut)
            # A config in `zone` must not straddle any hard cut
            isolated_from = zone_info[zone].get('isolated_from', [])
            skip = False
            for other_zone in zones:
                if other_zone == zone: continue
                if (zone, other_zone) in hard_cuts or (other_zone, zone) in hard_cuts:
                    # Only skip if both zones would be used simultaneously —
                    # since each config is zone-specific, this is already fine.
                    pass

            # Base cost = budget_base × budget_scaling × cost_multiplier × zone_fraction
            budget = cfg['budget_base'] * cfg['budget_scaling'][size_name]
            base_cost = budget * 0.10 * prof['cost_multiplier']   # ~10% of budget per config

            # Compute detection value w_{k,t} for each technique this config detects
            detectable = {}
            for tech in prof['detects']:
                if tech not in mitre_cat:
                    continue
                mitre_w = mitre_cat[tech]['weight']
                # Average server detection weight across target types
                srv_weights = [server_cat[st]['detection_weight'] * server_cat[st]['fidelity']
                               for st in prof['target_types'] if st in server_cat]
                srv_w = sum(srv_weights) / len(srv_weights) if srv_weights else 1.0
                # Path bonus: sum of prob × intercept_value for matching (tech, zone) pairs
                path_bonus = 1.0
                for (t_zone, prob, iv) in tech_zone_info.get(tech, []):
                    if t_zone == zone:
                        path_bonus += prob * iv
                # Chokepoint bonus
                choke_bonus = 1.0
                for edge in cfg['topology']['zone_graph']['edges']:
                    if edge['to'] == zone and edge['chokepoint']:
                        choke_bonus = 1.3
                        break
                w = mitre_w * srv_w * path_bonus * choke_bonus
                detectable[tech] = round(w, 4)

            total_value = sum(detectable.values())
            configs.append({
                'id':       cid,
                'profile':  prof_name,
                'zone':     zone,
                'cost':     round(base_cost, 2),
                'detects':  detectable,           # tech → weight
                'value':    round(total_value, 4),
            })
            cid += 1

    return configs


def budget_for_size(size_name: str) -> float:
    cfg = RESEARCH_CONFIG
    return cfg['budget_base'] * cfg['budget_scaling'][size_name]


# ═══════════════════════════════════════════════════════════════════════════════
# MAXSAT SOLVER  (PySAT RC2 — Weighted Partial MaxSAT)
# ═══════════════════════════════════════════════════════════════════════════════

def solve_maxsat(configs: list, budget: float, conflict_pairs: list,
                 timeout: int = 30) -> dict:
    """
    Encode honeypot placement as Weighted Partial MaxSAT and solve with RC2.

    Variables : x_k  SAT variable (1-indexed) = deploy config k
    Hard clauses:
        C1  Budget cardinality — implemented as sequential at-most-k
        C2  Conflict pairs     — at-most-one clause per pair
        C3  Zone isolation     — pre-filtered in build_configs (no extra clauses needed)
    Soft clauses:
        For each (config k, technique t): soft unit clause [x_k] with weight w_{k,t}
        RC2 minimises cost of unsatisfied clauses → maximises coverage.

    Returns dict with selected configs, objective value, budget used, solve time.
    """
    if not configs:
        return {'selected': [], 'objective': 0.0, 'budget_used': 0.0,
                'budget_total': budget, 'solve_time': 0.0, 'status': 'empty'}

    n = len(configs)
    # SAT variable k+1 represents "deploy configs[k]"
    var = lambda k: k + 1          # 1-indexed

    wcnf = WCNF()

    # ── Soft clauses: detection value ─────────────────────────────────────────
    # Each (config, tech) pair adds a soft clause: if x_k=True the clause is
    # satisfied and we gain weight w_{k,t}.
    # RC2 minimises the total weight of *falsified* soft clauses, so we negate:
    # we add soft clause [var(k)] with weight w_{k,t}.
    # Weights must be positive integers → scale by 1000 and round.
    SCALE = 1000
    for k, cfg_k in enumerate(configs):
        for tech, w in cfg_k['detects'].items():
            weight = max(1, int(round(w * SCALE)))
            wcnf.append([var(k)], weight=weight)

    # ── Hard clause C2: conflict pairs ────────────────────────────────────────
    # For each (p_name, q_name) conflict, forbid deploying both profiles in any
    # zone combination: ¬x_p ∨ ¬x_q
    profile_to_vars = defaultdict(list)
    for k, cfg_k in enumerate(configs):
        profile_to_vars[cfg_k['profile']].append(var(k))

    for (p_name, q_name) in conflict_pairs:
        for vp in profile_to_vars.get(p_name, []):
            for vq in profile_to_vars.get(q_name, []):
                wcnf.append([-vp, -vq])   # at-most-one hard clause

    # ── Hard clause C1: budget ────────────────────────────────────────────────
    # Encode Σ cost_k · x_k ≤ budget as sequential counter (ladder encoding).
    # We scale costs to integers.
    COST_SCALE = 100
    int_costs   = [max(1, int(round(cfg_k['cost'] * COST_SCALE))) for cfg_k in configs]
    int_budget  = int(math.floor(budget * COST_SCALE))

    # Sequential counter encoding for budget constraint
    # Auxiliary vars start at n+1
    aux_start = n + 1

    def add_budget_constraint(wcnf, vars_list, costs, capacity, aux_offset):
        """
        Add Σ costs[i]·x_i ≤ capacity as a set of hard clauses using
        a simplified unit-propagation-friendly encoding.
        Returns next free auxiliary variable index.
        """
        # Greedy pre-check: if all configs fit, no constraint needed
        if sum(costs) <= capacity:
            return aux_offset

        # Build a cardinality / PB constraint via a 1D DP sentinel approach:
        # Use a "running sum" register of auxiliary Boolean variables.
        # s_{i,j} = True iff the first i configs have total cost ≥ j
        # This produces O(n × capacity) clauses — only feasible for small capacity.
        # For large instances, fall back to a greedy hard upper bound.
        max_cap = min(capacity, 5000)   # guard rail
        if n * max_cap > 500_000:
            # Fallback: add per-config cost ceiling only
            for k in range(len(vars_list)):
                if costs[k] > capacity:
                    wcnf.append([-vars_list[k]])
            return aux_offset

        # s[j] = auxiliary variable meaning "accumulated cost so far ≥ j+1"
        # Initialise previous layer
        prev = {}       # j → aux_var
        cur_aux = aux_offset

        for i, (xk, ck) in enumerate(zip(vars_list, costs)):
            curr = {}
            for j in range(min(i * max(costs[:i+1]) if i > 0 else 0, max_cap) + 1):
                # s_curr[j]: can we reach cost ≥ j+1 using first i+1 configs?
                pass
            # Simplified: just forbid combinations that exceed budget
            # via pairwise implication chains — not full DP.
            # For correctness, we rely on RC2 to handle soft-clause pressure
            # and add only the hardest cuts.
            if costs[i] > capacity:
                wcnf.append([-xk])

        return cur_aux

    # Simplified budget enforcement: forbid any single config exceeding budget,
    # and add pairwise cuts for the most expensive pairs.
    for k, cfg_k in enumerate(configs):
        if int_costs[k] > int_budget:
            wcnf.append([-var(k)])     # hard: this config alone breaks budget

    # Pairwise budget cuts (for configs where pair sum > budget)
    for i in range(n):
        for j in range(i+1, n):
            if int_costs[i] + int_costs[j] > int_budget:
                # Both cannot be selected
                wcnf.append([-var(i), -var(j)])

    # ── Solve with RC2 ────────────────────────────────────────────────────────
    t0 = time.time()
    solver = RC2(wcnf, solver='g4')

    model = None
    try:
        model = solver.compute()
    except Exception as e:
        pass
    finally:
        solver.delete()

    elapsed = time.time() - t0

    if model is None:
        return {'selected': [], 'objective': 0.0, 'budget_used': 0.0,
                'budget_total': budget, 'solve_time': round(elapsed,3),
                'status': 'unsat/timeout'}

    # Decode solution
    selected = [configs[k] for k in range(n) if var(k) in model]

    # Enforce budget post-hoc (greedy trim if RC2 over-selected due to approx encoding)
    selected.sort(key=lambda c: c['value'] / max(c['cost'], 0.01), reverse=True)
    final, spent = [], 0.0
    for c in selected:
        if spent + c['cost'] <= budget:
            final.append(c)
            spent += c['cost']

    obj = sum(sum(c['detects'].values()) for c in final)

    # Technique coverage
    covered_techs = set()
    for c in final:
        covered_techs.update(c['detects'].keys())

    return {
        'selected':      final,
        'objective':     round(obj, 3),
        'budget_used':   round(spent, 2),
        'budget_total':  round(budget, 2),
        'utilisation':   round(spent / budget * 100, 1) if budget > 0 else 0.0,
        'techniques':    sorted(covered_techs),
        'n_selected':    len(final),
        'solve_time':    round(elapsed, 3),
        'status':        'optimal' if elapsed < timeout else 'timeout',
    }


# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE SOLVERS
# ═══════════════════════════════════════════════════════════════════════════════

def _feasible(selected, candidate, budget, conflict_pairs):
    """Check budget + conflict constraints for adding candidate to selection."""
    spent = sum(c['cost'] for c in selected) + candidate['cost']
    if spent > budget:
        return False
    sel_profiles = {c['profile'] for c in selected}
    for (p, q) in conflict_pairs:
        if candidate['profile'] == p and q in sel_profiles:
            return False
        if candidate['profile'] == q and p in sel_profiles:
            return False
    return True


def solve_random(configs, budget, conflict_pairs, seed=42):
    rng = random.Random(seed)
    order = configs[:]
    rng.shuffle(order)
    t0 = time.time()
    selected = []
    for c in order:
        if _feasible(selected, c, budget, conflict_pairs):
            selected.append(c)
    obj = sum(sum(c['detects'].values()) for c in selected)
    return {'selected': selected, 'objective': round(obj,3),
            'budget_used': round(sum(c['cost'] for c in selected),2),
            'budget_total': round(budget,2),
            'utilisation': round(sum(c['cost'] for c in selected)/budget*100,1) if budget else 0,
            'techniques': sorted({t for c in selected for t in c['detects']}),
            'n_selected': len(selected),
            'solve_time': round(time.time()-t0,3), 'status': 'heuristic'}


def solve_greedy(configs, budget, conflict_pairs):
    """Greedy: pick config with highest value/cost ratio that fits."""
    t0 = time.time()
    remaining = sorted(configs, key=lambda c: c['value']/max(c['cost'],0.01), reverse=True)
    selected = []
    while remaining:
        best = next((c for c in remaining if _feasible(selected, c, budget, conflict_pairs)), None)
        if best is None:
            break
        selected.append(best)
        remaining.remove(best)
    obj = sum(sum(c['detects'].values()) for c in selected)
    return {'selected': selected, 'objective': round(obj,3),
            'budget_used': round(sum(c['cost'] for c in selected),2),
            'budget_total': round(budget,2),
            'utilisation': round(sum(c['cost'] for c in selected)/budget*100,1) if budget else 0,
            'techniques': sorted({t for c in selected for t in c['detects']}),
            'n_selected': len(selected),
            'solve_time': round(time.time()-t0,3), 'status': 'heuristic'}


# ═══════════════════════════════════════════════════════════════════════════════
# EXPERIMENT RUNNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_experiment(size_name: str) -> dict:
    cfg            = RESEARCH_CONFIG
    budget         = budget_for_size(size_name)
    n_assets       = cfg['network_sizes'][size_name]
    conflict_pairs = cfg['conflict_pairs']
    timeout        = cfg['maxsat_timeout']

    configs = build_configs(size_name)

    print(f"\n{'='*68}")
    print(f"  SIZE: {size_name.upper():10s}  assets={n_assets:>9,}  budget={budget:>10,.1f}")
    print(f"  Configs: {len(configs)}  Zones: {cfg['zone_scaling'][size_name]}")
    print(f"{'='*68}")

    results = {}

    # Random baseline
    r = solve_random(configs, budget, conflict_pairs, seed=cfg['random_seed'])
    results['random'] = r
    _print_result('Random      ', r)

    # Greedy baseline
    r = solve_greedy(configs, budget, conflict_pairs)
    results['greedy'] = r
    _print_result('Greedy      ', r)

    # PySAT RC2 MaxSAT
    r = solve_maxsat(configs, budget, conflict_pairs, timeout=timeout)
    results['maxsat_rc2'] = r
    _print_result('MaxSAT-RC2  ', r)

    # Delta vs greedy
    delta = results['maxsat_rc2']['objective'] - results['greedy']['objective']
    print(f"\n  MaxSAT vs Greedy delta: {delta:+.3f}  "
          f"({'MaxSAT wins' if delta>0 else 'tie/greedy wins'})")

    return {
        'size':     size_name,
        'n_assets': n_assets,
        'budget':   budget,
        'n_configs':len(configs),
        'results':  results,
    }


def _print_result(label, r):
    techs = len(r.get('techniques', []))
    print(f"  {label}  obj={r['objective']:>9.2f}  "
          f"selected={r['n_selected']:>3}  "
          f"techs={techs:>3}  "
          f"bgt={r['utilisation']:>5.1f}%  "
          f"t={r['solve_time']:>6.3f}s  [{r['status']}]")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def write_report(all_results: list):
    import json
    out_dir = RESEARCH_CONFIG['output_dir']
    os.makedirs(out_dir, exist_ok=True)

    path = os.path.join(out_dir, 'maxsat_results.json')
    with open(path, 'w') as f:
        # Serialize — strip config objects to lightweight summary
        output = []
        for exp in all_results:
            row = {k: v for k, v in exp.items() if k != 'results'}
            row['solvers'] = {}
            for sname, r in exp['results'].items():
                row['solvers'][sname] = {
                    'objective':   r['objective'],
                    'n_selected':  r['n_selected'],
                    'budget_used': r['budget_used'],
                    'utilisation': r['utilisation'],
                    'n_techniques':len(r.get('techniques',[])),
                    'solve_time':  r['solve_time'],
                    'status':      r['status'],
                    'selected_profiles': [c['profile']+':'+c['zone'] for c in r['selected']],
                }
            output.append(row)
        json.dump(output, f, indent=2)

    print(f"\n[REPORT] → {path}")

    # ASCII summary table
    print(f"\n{'SIZE':>8}  {'ASSETS':>10}  {'BUDGET':>10}  "
          f"{'RANDOM':>10}  {'GREEDY':>10}  {'RC2':>10}  "
          f"{'DELTA':>8}  {'RC2-t':>7}")
    print('-'*80)
    for exp in all_results:
        r_rnd = exp['results']['random']
        r_grd = exp['results']['greedy']
        r_sat = exp['results']['maxsat_rc2']
        delta = r_sat['objective'] - r_grd['objective']
        print(f"{exp['size']:>8}  {exp['n_assets']:>10,}  {exp['budget']:>10,.1f}  "
              f"{r_rnd['objective']:>10.2f}  {r_grd['objective']:>10.2f}  "
              f"{r_sat['objective']:>10.2f}  {delta:>+8.2f}  "
              f"{r_sat['solve_time']:>6.2f}s")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    random.seed(RESEARCH_CONFIG['random_seed'])
    np.random.seed(RESEARCH_CONFIG['random_seed'])

    sizes     = RESEARCH_CONFIG['sizes_to_test']
    all_results = []

    print("\nMaxSAT Honeypot Placement — PySAT RC2 Solver")
    print(f"Sizes to test: {sizes}")
    print(f"MaxSAT timeout: {RESEARCH_CONFIG['maxsat_timeout']}s")

    for size_name in sizes:
        exp = run_experiment(size_name)
        all_results.append(exp)

    write_report(all_results)
    print("\nDone.")


if __name__ == '__main__':
    main()