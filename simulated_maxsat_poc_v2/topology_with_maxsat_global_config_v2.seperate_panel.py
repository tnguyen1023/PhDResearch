"""
Proactive Network Attack-Path Honeypot Placement
MaxSAT Formulation + Topology Visualization

Uses RESEARCH_CONFIG directly for:
  - Zone graph topology
  - Attack paths (Π) with hop intercept values
  - MITRE technique catalogue (stealth scores, weights)
  - Honeypot profiles (cost, detects, target zones/types)
  - Budget scaling per size
  - Asset roles (detection_multiplier, hop_distance)
  - Conflict pairs (C4 hard clauses)
  - Zone isolation (C5 hard clauses)
"""

import math
import itertools
import random
import warnings
import multiprocessing as mp
from collections import defaultdict

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.lines import Line2D
import networkx as nx

from pysat.examples.rc2 import RC2
from pysat.formula import WCNF

warnings.filterwarnings("ignore")
random.seed(42)
np.random.seed(42)

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIG  (verbatim from research_config.py)
# ═══════════════════════════════════════════════════════════════════════════════

RESEARCH_CONFIG = {
    'network_sizes': {
        'tiny': 100, 'small': 500, 'medium': 5000,
        'large': 50000, 'xlarge': 500000, 'xxlarge': 5560000,
    },
    'sizes_to_test': ['xlarge', 'xxlarge'],
    'attack_volumes': {
        'tiny': 5_000, 'small': 10_000, 'medium': 50_000,
        'large': 500_000, 'xlarge': 5_000_000, 'xxlarge': 25_600_000,
    },
    'budget_base': 250.0,
    'budget_scaling': {
        'tiny': 1.0, 'small': 2.0, 'medium': 7.0,
        'large': 50.0, 'xlarge': 250.0, 'xxlarge': 512.0,
    },
    'parallel': True,
    'max_workers': min(4, mp.cpu_count()),
    'ilp_timeout': 30,
    'maxsat_timeout': 60,
    'random_seed': 42,
    'output_dir': './research_results',

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
            'gateway':      {'label': 'Zone Gateway',          'asset_types': ['web','dns','api','generic'],                     'share_of_zone': 0.05, 'is_gateway': True,  'hop_distance': 1, 'detection_multiplier': 1.3},
            'service_host': {'label': 'Primary Service Host',  'asset_types': ['web','ssh','database','api','scada','identity'], 'share_of_zone': 0.50, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 1.0},
            'support_host': {'label': 'Support Host',          'asset_types': ['dns','ftp_smb','generic'],                       'share_of_zone': 0.30, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 0.9},
            'deep_host':    {'label': 'Deep / High-Value',     'asset_types': ['database','identity','scada'],                   'share_of_zone': 0.10, 'is_gateway': False, 'hop_distance': 3, 'detection_multiplier': 1.5},
            'jump_host':    {'label': 'Jump / Pivot Host',     'asset_types': ['ssh','generic'],                                 'share_of_zone': 0.05, 'is_gateway': False, 'hop_distance': 2, 'detection_multiplier': 1.4},
        },
        'attack_paths': {
            'web_to_db': {
                'label': 'Web Compromise → DB Exfil', 'probability': 0.30,
                'hops': [
                    {'zone': 'zone1', 'techniques': ['T1190','T1059'], 'intercept_value': 1.5},
                    {'zone': 'zone2', 'techniques': ['T1021','T1078'], 'intercept_value': 1.8},
                    {'zone': 'zone2', 'techniques': ['T1213','T1048'], 'intercept_value': 2.0},
                ],
            },
            'cloud_pivot': {
                'label': 'Cloud Entry → Pivot Internal', 'probability': 0.25,
                'hops': [
                    {'zone': 'zone3', 'techniques': ['T1133','T1190'], 'intercept_value': 1.4},
                    {'zone': 'zone2', 'techniques': ['T1550','T1021'], 'intercept_value': 1.8},
                    {'zone': 'zone2', 'techniques': ['T1003','T1558'], 'intercept_value': 2.0},
                ],
            },
            'brute_to_ad': {
                'label': 'Brute Force SSH → AD', 'probability': 0.20,
                'hops': [
                    {'zone': 'zone1', 'techniques': ['T1110','T1133'], 'intercept_value': 1.2},
                    {'zone': 'zone2', 'techniques': ['T1021','T1548'], 'intercept_value': 1.6},
                    {'zone': 'zone5', 'techniques': ['T1558','T1003'], 'intercept_value': 2.0},
                ],
            },
            'ot_infiltration': {
                'label': 'Pivot → OT Sabotage', 'probability': 0.15,
                'hops': [
                    {'zone': 'zone1', 'techniques': ['T1190','T1566'], 'intercept_value': 1.3},
                    {'zone': 'zone2', 'techniques': ['T1021','T1078'], 'intercept_value': 1.7},
                    {'zone': 'zone4', 'techniques': ['T0855','T0814'], 'intercept_value': 2.0},
                ],
            },
            'ransomware': {
                'label': 'Phishing → Ransomware', 'probability': 0.10,
                'hops': [
                    {'zone': 'zone2', 'techniques': ['T1566','T1059'], 'intercept_value': 1.3},
                    {'zone': 'zone2', 'techniques': ['T1021','T1550'], 'intercept_value': 1.7},
                    {'zone': 'zone2', 'techniques': ['T1486','T1485'], 'intercept_value': 2.0},
                ],
            },
        },
        'generation': {
            'honeypot_density_by_role': {
                'gateway': 0.80, 'service_host': 0.30,
                'support_host': 0.20, 'deep_host': 0.50, 'jump_host': 0.70,
            },
        },
        'topology_scaling': {
            'tiny':   {'active_zones': ['zone1','zone2'],                               'active_paths': ['web_to_db','brute_to_ad'],                                             'active_roles': ['gateway','service_host','support_host'],                         'intra_model_override': 'random'},
            'small':  {'active_zones': ['zone1','zone2','zone3'],                       'active_paths': ['web_to_db','cloud_pivot','brute_to_ad'],                               'active_roles': ['gateway','service_host','support_host','deep_host'],             'intra_model_override': None},
            'medium': {'active_zones': ['zone1','zone2','zone3','zone4'],               'active_paths': ['web_to_db','cloud_pivot','brute_to_ad'],                               'active_roles': ['gateway','service_host','support_host','deep_host','jump_host'], 'intra_model_override': None},
            'large':  {'active_zones': ['zone1','zone2','zone3','zone4','zone5'],       'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'], 'active_roles': ['gateway','service_host','support_host','deep_host','jump_host'], 'intra_model_override': None},
            'xlarge': {'active_zones': ['zone1','zone2','zone3','zone4','zone5'],       'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'], 'active_roles': ['gateway','service_host','support_host','deep_host','jump_host'], 'intra_model_override': None},
            'xxlarge':{'active_zones': ['zone1','zone2','zone3','zone4','zone5'],       'active_paths': ['web_to_db','cloud_pivot','brute_to_ad','ot_infiltration','ransomware'], 'active_roles': ['gateway','service_host','support_host','deep_host','jump_host'], 'intra_model_override': None},
        },
    },

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

    'mitre_catalogue': {
        'T1190': {'tactic': 'TA0001', 'name': 'Exploit Public-Facing App',   'weight': 1.4, 'stealth': 0.5},
        'T1133': {'tactic': 'TA0001', 'name': 'External Remote Services',    'weight': 1.2, 'stealth': 0.4},
        'T1566': {'tactic': 'TA0001', 'name': 'Phishing',                    'weight': 1.0, 'stealth': 0.6},
        'T1059': {'tactic': 'TA0002', 'name': 'Command Interpreter',         'weight': 1.3, 'stealth': 0.6},
        'T1548': {'tactic': 'TA0004', 'name': 'Abuse Elevation Control',     'weight': 1.5, 'stealth': 0.6},
        'T1078': {'tactic': 'TA0004', 'name': 'Valid Accounts',              'weight': 1.7, 'stealth': 0.8},
        'T1110': {'tactic': 'TA0006', 'name': 'Brute Force',                 'weight': 1.0, 'stealth': 0.2},
        'T1558': {'tactic': 'TA0006', 'name': 'Kerberoasting',               'weight': 1.8, 'stealth': 0.8},
        'T1003': {'tactic': 'TA0006', 'name': 'OS Credential Dumping',       'weight': 1.9, 'stealth': 0.8},
        'T1046': {'tactic': 'TA0007', 'name': 'Network Scanning',            'weight': 0.5, 'stealth': 0.1},
        'T1082': {'tactic': 'TA0007', 'name': 'System Info Discovery',       'weight': 0.6, 'stealth': 0.2},
        'T1021': {'tactic': 'TA0008', 'name': 'Remote Services',             'weight': 1.8, 'stealth': 0.8},
        'T1550': {'tactic': 'TA0008', 'name': 'Pass the Hash/Ticket',        'weight': 1.8, 'stealth': 0.8},
        'T1213': {'tactic': 'TA0009', 'name': 'Data from Repositories',      'weight': 1.5, 'stealth': 0.7},
        'T1048': {'tactic': 'TA0010', 'name': 'Exfiltration Alt Protocol',   'weight': 2.0, 'stealth': 0.9},
        'T1572': {'tactic': 'TA0011', 'name': 'Protocol Tunneling',          'weight': 1.5, 'stealth': 0.9},
        'T1486': {'tactic': 'TA0040', 'name': 'Data Encrypted for Impact',   'weight': 2.0, 'stealth': 0.6},
        'T1485': {'tactic': 'TA0040', 'name': 'Data Destruction',            'weight': 2.0, 'stealth': 0.7},
        'T0855': {'tactic': 'TA0104', 'name': 'Unauthorized Command Msg',    'weight': 2.0, 'stealth': 0.7},
        'T0814': {'tactic': 'TA0104', 'name': 'Denial of Service (ICS)',     'weight': 1.9, 'stealth': 0.5},
        'T1098': {'tactic': 'TA0003', 'name': 'Account Manipulation',        'weight': 1.4, 'stealth': 0.7},
        'T1136': {'tactic': 'TA0003', 'name': 'Create Account',              'weight': 1.1, 'stealth': 0.5},
    },

    'zones': {
        'zone1': {'label': 'Internet-Facing / DMZ',      'trust_level': 0, 'asset_share': 0.15, 'attack_share': 0.45, 'budget_fraction': 0.20, 'isolated_from': [], 'server_types': ['web','ssh','dns','api','generic'],              'mitre_tactics': ['T1190','T1133','T1566','T1059','T1110','T1046','T1082']},
        'zone2': {'label': 'Internal LAN / Corporate',   'trust_level': 2, 'asset_share': 0.40, 'attack_share': 0.25, 'budget_fraction': 0.30, 'isolated_from': [], 'server_types': ['ssh','database','ftp_smb','identity','web','generic'], 'mitre_tactics': ['T1078','T1548','T1021','T1550','T1003','T1558','T1098','T1136','T1213','T1486','T1485']},
        'zone3': {'label': 'Cloud / Hybrid',             'trust_level': 1, 'asset_share': 0.25, 'attack_share': 0.20, 'budget_fraction': 0.25, 'isolated_from': [], 'server_types': ['web','api','database','ssh','dns','generic'],    'mitre_tactics': ['T1190','T1133','T1078','T1548','T1021','T1048','T1572']},
        'zone4': {'label': 'OT / ICS / SCADA',          'trust_level': 3, 'asset_share': 0.10, 'attack_share': 0.05, 'budget_fraction': 0.15, 'isolated_from': ['zone1','zone3'], 'server_types': ['scada','ssh','generic'],       'mitre_tactics': ['T0855','T0814','T1021','T1078']},
        'zone5': {'label': 'Management / Out-of-Band',  'trust_level': 4, 'asset_share': 0.10, 'attack_share': 0.05, 'budget_fraction': 0.10, 'isolated_from': ['zone1','zone3'], 'server_types': ['ssh','identity','generic'],    'mitre_tactics': ['T1078','T1548','T1003','T1558','T1098','T1136']},
    },

    'honeypot_profiles': {
        'web_trap':     {'label': 'Web Honeypot',         'target_zones': ['zone1','zone3'],                          'target_types': ['web','api'],        'cost_multiplier': 1.0, 'detects': ['T1190','T1133','T1059']},
        'ssh_trap':     {'label': 'SSH Honeypot',         'target_zones': ['zone1','zone2','zone3'],                  'target_types': ['ssh','generic'],     'cost_multiplier': 0.8, 'detects': ['T1110','T1021','T1078','T1133']},
        'db_trap':      {'label': 'Database Honeypot',    'target_zones': ['zone2','zone3'],                         'target_types': ['database'],          'cost_multiplier': 1.3, 'detects': ['T1190','T1213','T1048','T1485']},
        'smb_trap':     {'label': 'SMB Honeypot',         'target_zones': ['zone2'],                                 'target_types': ['ftp_smb'],           'cost_multiplier': 0.9, 'detects': ['T1021','T1550','T1486','T1048']},
        'scada_trap':   {'label': 'SCADA Honeypot',       'target_zones': ['zone4'],                                 'target_types': ['scada'],             'cost_multiplier': 2.0, 'detects': ['T0855','T0814','T1078']},
        'ad_trap':      {'label': 'AD Honeypot',          'target_zones': ['zone2','zone5'],                         'target_types': ['identity'],          'cost_multiplier': 1.5, 'detects': ['T1558','T1550','T1003','T1098']},
        'dns_trap':     {'label': 'DNS Honeypot',         'target_zones': ['zone1','zone2','zone3'],                 'target_types': ['dns'],               'cost_multiplier': 0.7, 'detects': ['T1572','T1046']},
        'generic_trap': {'label': 'Generic Honeypot',     'target_zones': ['zone1','zone2','zone3','zone4','zone5'], 'target_types': ['generic'],           'cost_multiplier': 0.5, 'detects': ['T1046','T1082','T1110']},
    },

    'conflict_pairs': [
        ('scada_trap','web_trap'), ('scada_trap','db_trap'),  ('generic_trap','ad_trap'),
        ('scada_trap','ssh_trap'), ('scada_trap','dns_trap'), ('ad_trap','web_trap'),
        ('smb_trap','dns_trap'),
    ],

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
        'medium':  ['web_trap','ssh_trap','db_trap','dns_trap','generic_trap'],
        'large':   ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','generic_trap'],
        'xlarge':  ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
        'xxlarge': ['web_trap','ssh_trap','db_trap','smb_trap','dns_trap','scada_trap','ad_trap','generic_trap'],
    },

    'zone_solver_config': {
        'zone1': {'maxsat_timeout': 20, 'cluster_priority': 1},
        'zone2': {'maxsat_timeout': 30, 'cluster_priority': 2},
        'zone3': {'maxsat_timeout': 25, 'cluster_priority': 3},
        'zone4': {'maxsat_timeout': 15, 'cluster_priority': 4},
        'zone5': {'maxsat_timeout': 12, 'cluster_priority': 5},
    },
}

CFG = RESEARCH_CONFIG

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — BUILD ABSTRACT ASSET SET  (one representative asset per role×type
#           per active zone — keeps MaxSAT tractable for visualization)
# ═══════════════════════════════════════════════════════════════════════════════

SIZE = 'xxlarge'   # change to 'small', 'large', etc.

# ═══════════════════════════════════════════════════════════════════════════════
# COLOR PALETTE & MAPPINGS
# ═══════════════════════════════════════════════════════════════════════════════

# Base palette
NAVY  = '#0D1B2A'
SLATE = '#1E3A5F'
TEAL  = '#00B4D8'
WHITE = '#E8F4FD'
MGRAY = '#7A9BB5'
RED   = '#EF4444'
AMBER = '#F59E0B'
GREEN = '#10B981'

# Zone fill colors
ZONE_COLORS = {
    'ext':   '#374151',
    'zone1': '#1E3A5F',
    'zone2': '#164E63',
    'zone3': '#1E3A5F',
    'zone4': '#0F3460',
    'zone5': '#1A1A4E',
}

# Zone display labels
ZONE_LABELS = {
    'ext':   'Internet\n(External)',
    'zone1': 'DMZ\n(Zone 1)',
    'zone2': 'App Tier\n(Zone 2)',
    'zone3': 'Services\n(Zone 3)',
    'zone4': 'OT/SCADA\n(Zone 4)',
    'zone5': 'Core/AD\n(Zone 5)',
}

# Attack path colors  (one color per path key)
_PATH_COLOR_LIST = [RED, AMBER, '#A855F7', '#EC4899', '#F97316', '#06B6D4']
PATH_COLORS = {
    pk: _PATH_COLOR_LIST[i % len(_PATH_COLOR_LIST)]
    for i, pk in enumerate(sorted(CFG['topology']['attack_paths'].keys()))
}

# Honeypot profile colors
_PROF_COLOR_LIST = [TEAL, GREEN, AMBER, '#A855F7', '#F97316', '#EC4899',
                    '#06B6D4', '#84CC16']
PROFILE_COLORS = {
    pk: _PROF_COLOR_LIST[i % len(_PROF_COLOR_LIST)]
    for i, pk in enumerate(sorted(CFG['honeypot_profiles'].keys()))
}


topo_scale  = CFG['topology']['topology_scaling'][SIZE]
active_zones = topo_scale['active_zones']
active_paths = topo_scale['active_paths']
active_roles = topo_scale['active_roles']
active_profiles = CFG['profile_scaling'][SIZE]

B  = CFG['budget_base'] * CFG['budget_scaling'][SIZE]
Bz = {z: CFG['zones'][z]['budget_fraction'] * B for z in active_zones}

assets = []   # list of dicts: {id, zone, type, role}
for zone in active_zones:
    zone_types = CFG['zones'][zone]['server_types']
    for role in active_roles:
        role_cfg   = CFG['topology']['asset_roles'][role]
        role_types = [t for t in role_cfg['asset_types'] if t in zone_types]
        for stype in role_types:
            assets.append({
                'id':   f"{zone}_{role}_{stype}",
                'zone': zone,
                'type': stype,
                'role': role,
            })

# ── Derived quantities ─────────────────────────────────────────────────────────

def w_tilde(tech, asset):
    """Topology-weighted detection value: w * dm * (1/hd)"""
    base_w = CFG['mitre_catalogue'].get(tech, {}).get('weight', 0.5)
    scat_w = CFG['server_catalogue'].get(asset['type'], {}).get('detection_weight', 1.0)
    dm     = CFG['topology']['asset_roles'][asset['role']]['detection_multiplier']
    hd     = CFG['topology']['asset_roles'][asset['role']]['hop_distance']
    return base_w * scat_w * dm * (1.0 / hd)

def W_adj(tech, asset):
    """Stealth-adjusted weight: w̃ * (1 + sigma)"""
    sigma = CFG['mitre_catalogue'].get(tech, {}).get('stealth', 0.5)
    return w_tilde(tech, asset) * (1.0 + sigma)

def effective_targets(profile_key):
    """T*(i) — assets the profile can reach."""
    p = CFG['honeypot_profiles'][profile_key]
    return [a for a in assets
            if a['zone'] in p['target_zones']
            and a['type'] in p['target_types']]

def detects_on(profile_key, asset):
    """S_{i,a} — techniques profile i detects on asset a."""
    if asset not in effective_targets(profile_key):
        return []
    zone_techs = set(CFG['zones'][asset['zone']]['mitre_tactics'])
    prof_techs = set(CFG['honeypot_profiles'][profile_key]['detects'])
    return list(zone_techs & prof_techs)

def profile_cost(profile_key):
    mult = CFG['honeypot_profiles'][profile_key]['cost_multiplier']
    # normalise: budget_base / num_profiles * multiplier
    return CFG['budget_base'] / len(active_profiles) * mult

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — MaxSAT ENCODING (WCNF)
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'='*60}")
print(f"  MaxSAT Honeypot Placement  |  size={SIZE}")
print(f"  Budget B={B:.1f}  |  Profiles={len(active_profiles)}")
print(f"  Assets={len(assets)}  |  Zones={len(active_zones)}")
print(f"{'='*60}\n")

wcnf   = WCNF()
vcount = itertools.count(1)
vmap   = {}   # name → var int

def var(name):
    if name not in vmap:
        vmap[name] = next(vcount)
    return vmap[name]

# Decision variables
# x_i    : config k_i deployed
# c_{j,a}: technique t_j detected on asset a

for pk in active_profiles:
    var(f"x_{pk}")

all_tech_asset_pairs = []
for pk in active_profiles:
    for a in effective_targets(pk):
        for tech in detects_on(pk, a):
            pair = (tech, a['id'])
            if pair not in [p for p in all_tech_asset_pairs]:
                all_tech_asset_pairs.append(pair)
            var(f"c_{tech}_{a['id']}")

# ── HARD CLAUSES ──────────────────────────────────────────────────────────────

# C1 — detection requires a deployed covering config
det_support = defaultdict(list)
for pk in active_profiles:
    for a in effective_targets(pk):
        for tech in detects_on(pk, a):
            det_support[(tech, a['id'])].append(pk)

for (tech, aid), supporters in det_support.items():
    # ¬c_{j,a} ∨ (x_{i1} ∨ ... ∨ x_{ik})
    clause = [-var(f"c_{tech}_{aid}")] + [var(f"x_{pk}") for pk in supporters]
    wcnf.append(clause)

# C2 — global budget  (pseudo-boolean → at-most encoding via sequential counter)
costs = [profile_cost(pk) for pk in active_profiles]
# Encode as: sum(cost_i * x_i) <= B  using a simple greedy check at extraction
# For pure CNF we use a cardinality-style bound on count (simplified)
# Full PB encoding omitted for tractability; enforced post-solve

# C4 — conflict pairs
for (pa, pb) in CFG['conflict_pairs']:
    if pa in active_profiles and pb in active_profiles:
        wcnf.append([-var(f"x_{pa}"), -var(f"x_{pb}")])

# C5 — zone isolation: configs spanning isolated zone pairs are hard-banned
hard_cuts = set(CFG['topology']['zone_graph']['hard_cuts'])
for pk in active_profiles:
    p = CFG['honeypot_profiles'][pk]
    tzones = set(p['target_zones'])
    for (za, zb) in hard_cuts:
        if za in tzones and zb in tzones:
            wcnf.append([-var(f"x_{pk}")])   # unit hard clause: ¬x_i

# ── SOFT CLAUSES (4-tier stratified weights) ──────────────────────────────────
# Tier multipliers: T4=1000, T3=100, T2=10, T1=1
TIER = {4: 1000, 3: 100, 2: 10, 1: 1}

# Tier 1 — per (technique, asset) detection coverage
for (tech, aid) in all_tech_asset_pairs:
    a = next((x for x in assets if x['id'] == aid), None)
    if a is None:
        continue
    w = W_adj(tech, a)
    weight = max(1, int(round(w * TIER[1] * 100)))
    wcnf.append([var(f"c_{tech}_{aid}")], weight=weight)

# Tier 2 — technique coverage (at least one asset per technique)
tech_set = set(t for (t, _) in all_tech_asset_pairs)
for tech in tech_set:
    covers = [var(f"c_{tech}_{aid}") for (t, aid) in all_tech_asset_pairs if t == tech]
    if covers:
        tac_sigma = CFG['mitre_catalogue'].get(tech, {}).get('stealth', 0.5)
        tac_w     = CFG['mitre_catalogue'].get(tech, {}).get('weight', 1.0)
        weight    = max(1, int(round(tac_w * (1 + tac_sigma) * TIER[2] * 10)))
        wcnf.append(covers, weight=weight)

# Tier 3 — attack path hop coverage (forward)
for path_key in active_paths:
    path = CFG['topology']['attack_paths'][path_key]
    rho  = path['probability']
    for h, hop in enumerate(path['hops']):
        if hop['zone'] not in active_zones:
            continue
        iv      = hop['intercept_value']
        hop_vars = []
        for tech in hop['techniques']:
            for a in assets:
                if a['zone'] == hop['zone']:
                    cname = f"c_{tech}_{a['id']}"
                    if cname in vmap:
                        hop_vars.append(var(cname))
        if hop_vars:
            pw     = rho * iv
            weight = max(1, int(round(pw * TIER[3] * 50)))
            wcnf.append(list(set(hop_vars)), weight=weight)
    # backward (0.7 discount vs forward)
    for h, hop in enumerate(reversed(path['hops'])):
        if hop['zone'] not in active_zones:
            continue
        iv      = hop['intercept_value']
        hop_vars = []
        for tech in hop['techniques']:
            for a in assets:
                if a['zone'] == hop['zone']:
                    cname = f"c_{tech}_{a['id']}"
                    if cname in vmap:
                        hop_vars.append(var(cname))
        if hop_vars:
            pw     = rho * iv * 0.7
            weight = max(1, int(round(pw * TIER[3] * 50)))
            wcnf.append(list(set(hop_vars)), weight=weight)

# Tier 4 — early intercept (non-final hop)
for path_key in active_paths:
    path = CFG['topology']['attack_paths'][path_key]
    rho  = path['probability']
    hops = path['hops']
    if len(hops) < 2:
        continue
    early_vars = []
    max_iv     = 0.0
    for h, hop in enumerate(hops[:-1]):   # non-final hops
        if hop['zone'] not in active_zones:
            continue
        max_iv = max(max_iv, hop['intercept_value'])
        for tech in hop['techniques']:
            for a in assets:
                if a['zone'] == hop['zone']:
                    cname = f"c_{tech}_{a['id']}"
                    if cname in vmap:
                        early_vars.append(var(cname))
    if early_vars:
        weight = max(1, int(round(rho * max_iv * TIER[4])))
        wcnf.append(list(set(early_vars)), weight=weight)

print(f"WCNF built:  {wcnf.nv} vars  |  {len(wcnf.hard)} hard  |  {len(wcnf.soft)} soft clauses")

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — SOLVE with RC2
# ═══════════════════════════════════════════════════════════════════════════════

print("\nRunning RC2 solver...")
solver    = RC2(wcnf)
model     = solver.compute()
solver.delete()

if model is None:
    print("  RC2 returned no model — using greedy fallback")
    # Greedy fallback: pick profiles by coverage/cost ratio
    deployed = []
    remaining_B = B
    prof_scores = {}
    for pk in active_profiles:
        score = sum(W_adj(t, a) for a in effective_targets(pk) for t in detects_on(pk, a))
        cost  = profile_cost(pk)
        prof_scores[pk] = score / (cost + 1e-9)
    for pk in sorted(prof_scores, key=prof_scores.get, reverse=True):
        c = profile_cost(pk)
        if remaining_B >= c:
            deployed.append(pk)
            remaining_B -= c
else:
    true_vars = {v for v in model if v > 0}
    rev_map   = {v: k for k, v in vmap.items()}
    deployed  = [pk for pk in active_profiles
                 if var(f"x_{pk}") in true_vars]
    # Enforce budget post-solve (greedy trim if needed)
    total_cost = sum(profile_cost(pk) for pk in deployed)
    if total_cost > B:
        deployed.sort(key=lambda pk: profile_cost(pk) / (
                sum(W_adj(t, a) for a in effective_targets(pk) for t in detects_on(pk, a)) + 1e-9
        ))
        while sum(profile_cost(pk) for pk in deployed) > B and deployed:
            deployed.pop(0)

print(f"\nDeployed configs ({len(deployed)}): {deployed}")
print(f"Total cost: {sum(profile_cost(p) for p in deployed):.1f}  /  Budget: {B:.1f}")

# ── Compute coverage metrics ─────────────────────────────────────────────────

covered_pairs    = set()
detected_techniques = set()
for pk in deployed:
    for a in effective_targets(pk):
        for tech in detects_on(pk, a):
            covered_pairs.add((tech, a['id']))
            detected_techniques.add(tech)

all_possible_pairs = set(all_tech_asset_pairs)
det_eff   = len(covered_pairs) / max(len(all_possible_pairs), 1) * 100
tech_cov  = len(detected_techniques) / max(len(tech_set), 1) * 100

# Tactic families
all_tactics  = set(CFG['mitre_catalogue'][t]['tactic'] for t in tech_set if t in CFG['mitre_catalogue'])
det_tactics  = set(CFG['mitre_catalogue'][t]['tactic'] for t in detected_techniques if t in CFG['mitre_catalogue'])
fam_cov      = len(det_tactics) / max(len(all_tactics), 1) * 100

# Path coverage
fwd_covered = bwd_covered = fwd_total = bwd_total = 0
path_coverage = {}
for path_key in active_paths:
    path = CFG['topology']['attack_paths'][path_key]
    hops = path['hops']
    fwd_hits = bwd_hits = 0
    for hop in hops:
        if hop['zone'] not in active_zones:
            continue
        fwd_total += 1
        hit = any((tech, a['id']) in covered_pairs
                  for tech in hop['techniques']
                  for a in assets if a['zone'] == hop['zone'])
        if hit:
            fwd_hits += 1
            fwd_covered += 1
    for hop in reversed(hops):
        if hop['zone'] not in active_zones:
            continue
        bwd_total += 1
        hit = any((tech, a['id']) in covered_pairs
                  for tech in hop['techniques']
                  for a in assets if a['zone'] == hop['zone'])
        if hit:
            bwd_hits += 1
            bwd_covered += 1
    path_coverage[path_key] = {'fwd': fwd_hits, 'bwd': bwd_hits,
                               'total_hops': len(hops)}

fwd_pct = fwd_covered / max(fwd_total, 1) * 100
bwd_pct = bwd_covered / max(bwd_total, 1) * 100

# Q score
Q = 0.35*det_eff + 0.25*tech_cov + 0.15*fam_cov + 0.15*fwd_pct + 0.10*bwd_pct

print(f"\nQ = {Q:.2f}")
print(f"  DetEff={det_eff:.1f}%  TechCov={tech_cov:.1f}%  "
      f"FamCov={fam_cov:.1f}%  Fwd={fwd_pct:.1f}%  Bwd={bwd_pct:.1f}%")


def draw_panel_honeypot_table(ax, deployed, active_zones, CFG,
                              effective_targets, detects_on, profile_cost,
                              detected_techniques,
                              det_eff, tech_cov, fam_cov, fwd_pct, bwd_pct, Q,
                              SLATE, WHITE, MGRAY, GREEN, RED, TEAL, AMBER,
                              NAVY):
    from matplotlib.patches import FancyBboxPatch
    ax.set_facecolor('#121E2D')
    for spine in ax.spines.values():
        spine.set_edgecolor(SLATE)
    ax.set_title("Deployed Honeypot Summary", color=WHITE, fontsize=10,
                 fontweight='bold', pad=6)
    ax.axis('off')

    col_headers = ['Honeypot', 'Zones', 'Detects (n)', 'Cost', 'Coverage']
    col_w       = [0.30, 0.18, 0.16, 0.12, 0.14]
    x_starts    = [sum(col_w[:i]) for i in range(len(col_headers))]

    rows = []
    for pk in deployed:
        p      = CFG['honeypot_profiles'][pk]
        tzones = ','.join([z.replace('zone','Z') for z in p['target_zones']
                           if z in active_zones])
        n_det  = len(set(t for a in effective_targets(pk)
                         for t in detects_on(pk, a)))
        cost   = profile_cost(pk)
        cov_t  = set(t for a in effective_targets(pk) for t in detects_on(pk, a))
        cov_pct = len(cov_t & detected_techniques) / max(len(cov_t), 1) * 100
        rows.append([
            p['label'].replace(' Honeypot','').replace(' Trap',''),
            tzones,
            str(n_det),
            f"{cost:.1f}",
            f"{cov_pct:.0f}%",
        ])

    tbl_data = [col_headers] + rows
    n_rows   = len(tbl_data)

    for r, row in enumerate(tbl_data):
        bg = NAVY if r == 0 else ('#1A2940' if r % 2 == 0 else '#121E2D')
        rect = FancyBboxPatch(
            (0, 1 - (r+1)/(n_rows+1)),
            1.0, 1/(n_rows+1),
            boxstyle="round,pad=0.005",
            facecolor=bg, edgecolor=SLATE, linewidth=0.5,
            transform=ax.transAxes, clip_on=False
        )
        ax.add_patch(rect)
        for c, (cell, xs, cw) in enumerate(zip(row, x_starts, col_w)):
            fw  = 'bold' if r == 0 else 'normal'
            col = WHITE if r == 0 else (GREEN if (c == 4 and r > 0) else MGRAY)
            ax.text(xs + cw*0.05,
                    1 - (r + 0.5)/(n_rows+1),
                    cell,
                    transform=ax.transAxes,
                    fontsize=7, color=col, fontweight=fw,
                    va='center', ha='left')

    # Bottom metric strip
    metrics = [
        ('DetEff',  f"{det_eff:.1f}%",  TEAL),
        ('TechCov', f"{tech_cov:.1f}%", GREEN),
        ('FamCov',  f"{fam_cov:.1f}%",  AMBER),
        ('FwdPath', f"{fwd_pct:.1f}%",  RED),
        ('Q Score', f"{Q:.2f}",         WHITE),
    ]
    for i, (lbl, val, col) in enumerate(metrics):
        x = (i + 0.5) / len(metrics)
        ax.text(x, 0.05, val, ha='center', va='bottom',
                fontsize=9, color=col, fontweight='bold',
                transform=ax.transAxes)
        ax.text(x, 0.01, lbl, ha='center', va='bottom',
                fontsize=6.5, color=MGRAY,
                transform=ax.transAxes)

def draw_panel_techniques(ax, tech_set, detected_techniques, CFG,
                          SLATE, WHITE, MGRAY, GREEN, RED, NAVY):
    import matplotlib.patches as mpatches
    ax.set_facecolor('#121E2D')
    for spine in ax.spines.values():
        spine.set_edgecolor(SLATE)
    ax.set_title("Technique Detection  (stealth-adjusted weight)",
                 color=WHITE, fontsize=10, fontweight='bold', pad=6)

    techs_sorted = sorted(
        tech_set,
        key=lambda t: (CFG['mitre_catalogue'].get(t, {}).get('weight', 0) *
                       (1 + CFG['mitre_catalogue'].get(t, {}).get('stealth', 0))),
        reverse=True
    )[:18]

    t_names    = [CFG['mitre_catalogue'].get(t, {}).get('name', t)[:22]
                  for t in techs_sorted]
    t_weights  = [CFG['mitre_catalogue'].get(t, {}).get('weight', 1) *
                  (1 + CFG['mitre_catalogue'].get(t, {}).get('stealth', 0.5))
                  for t in techs_sorted]
    t_detected = [t in detected_techniques for t in techs_sorted]
    t_colors   = [GREEN if d else RED for d in t_detected]

    ax.barh(range(len(techs_sorted)), t_weights, color=t_colors, alpha=0.85)
    ax.set_yticks(range(len(techs_sorted)))
    ax.set_yticklabels(t_names, fontsize=7, color=WHITE)
    ax.set_xlabel('W_adj = w × (1+σ)', fontsize=8, color=MGRAY)
    ax.tick_params(colors=MGRAY, labelsize=7)
    ax.xaxis.label.set_color(MGRAY)

    for i, (det, tech) in enumerate(zip(t_detected, techs_sorted)):
        sigma = CFG['mitre_catalogue'].get(tech, {}).get('stealth', 0)
        label = f"✓ σ={sigma:.1f}" if det else f"✗ σ={sigma:.1f}"
        ax.text(0.1, i, label, va='center', fontsize=6.5,
                color=WHITE, fontweight='bold')

    det_patch   = mpatches.Patch(color=GREEN,
                                 label=f'Detected ({sum(t_detected)})')
    undet_patch = mpatches.Patch(color=RED,
                                 label=f'Not detected ({len(techs_sorted)-sum(t_detected)})')
    ax.legend(handles=[det_patch, undet_patch], fontsize=7,
              facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE,
              loc='lower right')


def draw_panel_path_heatmap(ax, active_paths, active_zones,
                            path_coverage, CFG,
                            SLATE, WHITE, MGRAY, AMBER):
    import numpy as np
    ax.set_facecolor('#121E2D')
    for spine in ax.spines.values():
        spine.set_edgecolor(SLATE)
    ax.set_title("Attack Path Coverage", color=WHITE, fontsize=10,
                 fontweight='bold', pad=6)

    path_names = [CFG['topology']['attack_paths'][pk]['label'][:24]
                  for pk in active_paths]
    heat_data  = []
    for pk in active_paths:
        path    = CFG['topology']['attack_paths'][pk]
        total_h = len([h for h in path['hops'] if h['zone'] in active_zones])
        cov     = path_coverage.get(pk, {'fwd': 0, 'bwd': 0, 'total_hops': 1})
        fwd_r   = cov['fwd'] / max(total_h, 1)
        bwd_r   = cov['bwd'] / max(total_h, 1)
        heat_data.append([fwd_r, bwd_r])

    heat_arr = np.array(heat_data)
    im = ax.imshow(heat_arr, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)

    ax.set_xticks([0, 1])
    ax.set_xticklabels(['Forward', 'Backward'], fontsize=8, color=WHITE)
    ax.set_yticks(range(len(active_paths)))
    ax.set_yticklabels(path_names, fontsize=7, color=WHITE)
    ax.tick_params(colors=MGRAY)

    for i in range(len(active_paths)):
        for j in range(2):
            val = heat_arr[i, j]
            ax.text(j, i, f"{val*100:.0f}%",
                    ha='center', va='center', fontsize=8,
                    color='white' if val < 0.6 else 'black',
                    fontweight='bold')

    for i, pk in enumerate(active_paths):
        rho = CFG['topology']['attack_paths'][pk]['probability']
        ax.text(2.15, i, f"ρ={rho}",
                va='center', ha='left', fontsize=7, color=AMBER)

    cb = plt.colorbar(im, ax=ax, fraction=0.04, pad=0.02)
    cb.ax.tick_params(colors=WHITE, labelsize=7)
    cb.ax.yaxis.label.set_color(WHITE)


def draw_panel_radar(fig, gs_slot, det_eff, tech_cov, fam_cov,
                     fwd_pct, bwd_pct, Q,
                     TEAL, SLATE, WHITE, MGRAY, AMBER):
    import math
    ax_radar = fig.add_subplot(gs_slot, polar=True)
    ax_radar.set_facecolor('#121E2D')
    ax_radar.spines['polar'].set_color(SLATE)

    categories = ['DetEff%', 'TechCov%', 'FamCov%', 'FwdPath%', 'BwdPath%']
    values     = [det_eff, tech_cov, fam_cov, fwd_pct, bwd_pct]
    N      = len(categories)
    angles = [n / N * 2 * math.pi for n in range(N)] + \
             [0 / N * 2 * math.pi]   # close loop
    vals   = values + values[:1]

    ax_radar.set_theta_offset(math.pi / 2)
    ax_radar.set_theta_direction(-1)
    ax_radar.plot(angles, vals, 'o-', lw=2, color=TEAL)
    ax_radar.fill(angles, vals, alpha=0.25, color=TEAL)
    ax_radar.set_xticks(angles[:-1])
    ax_radar.set_xticklabels(categories, fontsize=8, color=WHITE)
    ax_radar.set_ylim(0, 100)
    ax_radar.set_yticks([25, 50, 75, 100])
    ax_radar.set_yticklabels(['25', '50', '75', '100'], fontsize=6, color=MGRAY)
    ax_radar.grid(color=SLATE, alpha=0.5)
    ax_radar.set_title("Q Score Decomposition", color=WHITE, fontsize=10,
                       fontweight='bold', pad=14)
    ax_radar.text(0, 0, f"Q\n{Q:.1f}", ha='center', va='center',
                  fontsize=11, fontweight='bold', color=AMBER)
    return ax_radar

def draw_panel_budget(ax, active_profiles, deployed, B, CFG,
                      profile_cost, PROFILE_COLORS, SLATE, WHITE,
                      MGRAY, RED, GREEN, NAVY, AMBER):
    ax.set_facecolor('#121E2D')
    for spine in ax.spines.values():
        spine.set_edgecolor(SLATE)
    ax.set_title("Budget Utilisation", color=WHITE, fontsize=10,
                 fontweight='bold', pad=6)

    pk_costs = [profile_cost(pk) for pk in active_profiles]
    pk_cols  = [PROFILE_COLORS.get(pk, SLATE) for pk in active_profiles]
    pk_labels = [CFG['honeypot_profiles'][pk]['label'].replace(' Honeypot','')
                 for pk in active_profiles]

    bars = ax.barh(range(len(active_profiles)), pk_costs,
                   color=pk_cols, alpha=0.9)
    for i, (bar, pk) in enumerate(zip(bars, active_profiles)):
        bar.set_alpha(1.0 if pk in deployed else 0.3)
        label = '✓ DEPLOYED' if pk in deployed else 'not used'
        lcol  = GREEN if pk in deployed else MGRAY
        ax.text(bar.get_width() + 1, i, label,
                va='center', fontsize=6.5, color=lcol, fontweight='bold')

    total_deployed_cost = sum(profile_cost(pk) for pk in deployed)
    ax.axvline(B, color=RED, lw=1.5, ls='--', label=f'Budget B={B:.0f}')
    ax.axvline(total_deployed_cost, color=GREEN, lw=1.5, ls='-',
               label=f'Used={total_deployed_cost:.1f}')

    ax.set_yticks(range(len(active_profiles)))
    ax.set_yticklabels(pk_labels, fontsize=7.5, color=WHITE)
    ax.set_xlabel('Cost units', fontsize=8, color=MGRAY)
    ax.tick_params(colors=MGRAY, labelsize=7.5)
    ax.xaxis.label.set_color(MGRAY)
    ax.legend(fontsize=7, facecolor=NAVY, edgecolor=SLATE, labelcolor=WHITE)
    ax.set_xlim(0, max(pk_costs) * 1.5)

    pct_used = total_deployed_cost / B * 100
    ax.text(0.97, 0.04, f"{pct_used:.1f}% of B used",
            transform=ax.transAxes, ha='right', va='bottom',
            fontsize=8, color=AMBER, fontweight='bold')

def draw_panel_topology(ax, fig, active_zones, active_paths, deployed,
                        pos, G_topo, CFG, PATH_COLORS, PROFILE_COLORS,
                        ZONE_COLORS, ZONE_LABELS, TEAL, SLATE, WHITE,
                        MGRAY, RED, AMBER, GREEN):
    ax.set_facecolor('#121E2D')
    for spine in ax.spines.values():
        spine.set_edgecolor(SLATE)
    ax.set_title("Zone Topology  •  Attack Paths  •  Honeypot Placement",
                 color=WHITE, fontsize=11, fontweight='bold', pad=8)

    # Zone background blobs
    for node in G_topo.nodes:
        if node not in pos:
            continue
        x, y   = pos[node]
        radius = 1.0 if node == 'ext' else 1.4
        c_face = ZONE_COLORS.get(node, SLATE)
        circle = plt.Circle((x, y), radius, color=c_face, alpha=0.18, zorder=1)
        ax.add_patch(circle)

    # Edges
    for (u, v, data) in G_topo.edges(data=True):
        if u not in pos or v not in pos:
            continue
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        lw  = 3.0 if data['chokepoint'] else 1.5
        ls  = '-'  if data['chokepoint'] else '--'
        col = TEAL if data['chokepoint'] else SLATE
        ax.annotate('',
                    xy=(x1, y1), xytext=(x0, y0),
                    arrowprops=dict(arrowstyle='->', color=col, lw=lw,
                                    linestyle=ls, mutation_scale=14),
                    zorder=2)
        mx, my = (x0+x1)/2 + 0.1, (y0+y1)/2 + 0.1
        ax.text(mx, my, f"{data['traversal_cost']:.1f}",
                fontsize=6.5, color=MGRAY, ha='center', va='center', zorder=5)

    # Attack paths
    for idx, pk in enumerate(active_paths):
        path = CFG['topology']['attack_paths'][pk]
        hops = [h for h in path['hops'] if h['zone'] in active_zones]
        if not hops:
            continue
        zones_seq = ['ext'] + [h['zone'] for h in hops]
        col = PATH_COLORS.get(pk, RED)
        for i in range(len(zones_seq)-1):
            z0, z1 = zones_seq[i], zones_seq[i+1]
            if z0 not in pos or z1 not in pos:
                continue
            x0, y0 = pos[z0]
            x1, y1 = pos[z1]
            rad = 0.15 + idx * 0.04
            ax.annotate('',
                        xy=(x1, y1), xytext=(x0, y0),
                        arrowprops=dict(arrowstyle='->', color=col, lw=1.2,
                                        connectionstyle=f'arc3,rad={rad}',
                                        alpha=0.55),
                        zorder=3)

    # Nodes
    for node in G_topo.nodes:
        if node not in pos:
            continue
        x, y   = pos[node]
        c_face = ZONE_COLORS.get(node, SLATE)
        is_dep = any(node in CFG['honeypot_profiles'][pk]['target_zones']
                     for pk in deployed)
        marker = '*' if (node != 'ext' and is_dep) else 'o'
        msize  = 280 if node == 'ext' else (320 if is_dep else 220)
        ax.scatter(x, y, s=msize, c=c_face, marker=marker,
                   edgecolors=WHITE, linewidths=1.5, zorder=6)
        ax.text(x, y - 1.65, ZONE_LABELS.get(node, node),
                fontsize=7.5, color=WHITE, ha='center', va='top',
                fontweight='bold', zorder=7)

    # Honeypot placement markers
    for pk in deployed:
        p    = CFG['honeypot_profiles'][pk]
        pcol = PROFILE_COLORS.get(pk, AMBER)
        for tz in p['target_zones']:
            if tz not in pos or tz not in active_zones:
                continue
            x, y = pos[tz]
            ax.scatter(x + 0.5, y + 0.5, s=120, c=pcol, marker='D',
                       edgecolors=WHITE, linewidths=0.8, zorder=8, alpha=0.9)
            ax.text(x + 0.5, y + 1.0,
                    CFG['honeypot_profiles'][pk]['label'].replace(' Honeypot',''),
                    fontsize=5.5, color=pcol, ha='center', va='bottom',
                    fontweight='bold', zorder=9)

    # Legends
    path_handles = [
        mpatches.Patch(color=PATH_COLORS.get(pk, RED),
                       label=f"{CFG['topology']['attack_paths'][pk]['label'][:28]} "
                             f"(ρ={CFG['topology']['attack_paths'][pk]['probability']})")
        for pk in active_paths
    ]
    honey_handles = [
        mpatches.Patch(color=PROFILE_COLORS.get(pk, AMBER),
                       label=f"◆ {CFG['honeypot_profiles'][pk]['label']}")
        for pk in deployed
    ]
    leg1 = ax.legend(handles=path_handles, loc='lower left', fontsize=6.5,
                     facecolor='#0D1B2A', edgecolor=SLATE, labelcolor=WHITE,
                     title='Attack Paths', title_fontsize=7, framealpha=0.85)
    ax.legend(handles=honey_handles, loc='lower right', fontsize=6.5,
              facecolor='#0D1B2A', edgecolor=SLATE, labelcolor=WHITE,
              title='Deployed Honeypots', title_fontsize=7, framealpha=0.85)
    ax.add_artist(leg1)

    ax.set_xlim(-0.5, 11.5)
    ax.set_ylim(-0.5, 11.5)
    ax.axis('off')
    ax.text(0.01, 0.01,
            "─── Chokepoint edge    ╌╌╌ Non-chokepoint    "
            "★ Zone with honeypot    edge label = traversal cost",
            transform=ax.transAxes, fontsize=6.5, color=MGRAY,
            va='bottom', ha='left')

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4 — VISUALIZATION  (6 panels, each via dedicated function)
# ═══════════════════════════════════════════════════════════════════════════════

fig = plt.figure(figsize=(22, 18), facecolor=NAVY)
fig.suptitle(
    f"MaxSAT Honeypot Placement  |  SIZE={SIZE.upper()}  |  "
    f"Budget={B:.0f}  |  Q={Q:.2f}",
    fontsize=17, fontweight='bold', color=WHITE, y=0.98,
    fontfamily='monospace'
)

gs = fig.add_gridspec(
    3, 3, hspace=0.38, wspace=0.32,
    top=0.93, bottom=0.04, left=0.05, right=0.97
)

ax_topo    = fig.add_subplot(gs[0:2, 0:2])
ax_budget  = fig.add_subplot(gs[0, 2])
ax_metrics = fig.add_subplot(gs[1, 2])   # placeholder — replaced by radar
ax_paths   = fig.add_subplot(gs[2, 0])
ax_techs   = fig.add_subplot(gs[2, 1])
ax_honey   = fig.add_subplot(gs[2, 2])

# Build networkx graph once (shared by panel 1)
G_topo = nx.DiGraph()
G_topo.add_node('ext')
for z in active_zones:
    G_topo.add_node(z)
for edge in CFG['topology']['zone_graph']['edges']:
    fr, to = edge['from'], edge['to']
    if (fr == 'ext' or fr in active_zones) and (to in active_zones):
        G_topo.add_edge(fr, to,
                        traversal_cost=edge['traversal_cost'],
                        chokepoint=edge['chokepoint'])

pos = {
    'ext':   (0.10, 0.50), 'zone1': (0.30, 0.50),
    'zone3': (0.30, 0.82), 'zone2': (0.58, 0.50),
    'zone4': (0.82, 0.22), 'zone5': (0.82, 0.78),
}
pos = {k: (v[0]*10, v[1]*10) for k, v in pos.items() if k in G_topo.nodes}

draw_panel_topology(ax_topo, fig, active_zones, active_paths, deployed,
                    pos, G_topo, CFG, PATH_COLORS, PROFILE_COLORS,
                    ZONE_COLORS, ZONE_LABELS, TEAL, SLATE, WHITE,
                    MGRAY, RED, AMBER, GREEN)

draw_panel_budget(ax_budget, active_profiles, deployed, B, CFG,
                  profile_cost, PROFILE_COLORS, SLATE, WHITE,
                  MGRAY, RED, GREEN, NAVY, AMBER)

ax_metrics.remove()   # replaced by polar subplot
ax_radar = draw_panel_radar(fig, gs[1, 2], det_eff, tech_cov, fam_cov,
                            fwd_pct, bwd_pct, Q,
                            TEAL, SLATE, WHITE, MGRAY, AMBER)

draw_panel_path_heatmap(ax_paths, active_paths, active_zones,
                        path_coverage, CFG,
                        SLATE, WHITE, MGRAY, AMBER)

draw_panel_techniques(ax_techs, tech_set, detected_techniques, CFG,
                      SLATE, WHITE, MGRAY, GREEN, RED, NAVY)

draw_panel_honeypot_table(ax_honey, deployed, active_zones, CFG,
                          effective_targets, detects_on, profile_cost,
                          detected_techniques,
                          det_eff, tech_cov, fam_cov, fwd_pct, bwd_pct, Q,
                          SLATE, WHITE, MGRAY, GREEN, RED, TEAL, AMBER, NAVY)

import os
out_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "outputs")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, f"maxsat_honeypot_placement_{SIZE}.png")
plt.savefig(out_path, dpi=160, bbox_inches='tight',
            facecolor=NAVY, edgecolor='none')

# ─────────────────────────────────────────────────────────────────────────────
# Save each panel as a separate PNG
# ─────────────────────────────────────────────────────────────────────────────

panel_specs = [
    ('topology',  draw_panel_topology,       (22, 14), lambda ax: draw_panel_topology(
        ax, fig, active_zones, active_paths, deployed,
        pos, G_topo, CFG, PATH_COLORS, PROFILE_COLORS,
        ZONE_COLORS, ZONE_LABELS, TEAL, SLATE, WHITE, MGRAY, RED, AMBER, GREEN)),
    ('budget',    draw_panel_budget,          (10, 7),  lambda ax: draw_panel_budget(
        ax, active_profiles, deployed, B, CFG,
        profile_cost, PROFILE_COLORS, SLATE, WHITE, MGRAY, RED, GREEN, NAVY, AMBER)),
    ('path_heatmap', draw_panel_path_heatmap, (10, 7),  lambda ax: draw_panel_path_heatmap(
        ax, active_paths, active_zones, path_coverage, CFG,
        SLATE, WHITE, MGRAY, AMBER)),
    ('techniques',   draw_panel_techniques,   (10, 7),  lambda ax: draw_panel_techniques(
        ax, tech_set, detected_techniques, CFG,
        SLATE, WHITE, MGRAY, GREEN, RED, NAVY)),
    ('honeypot_table', draw_panel_honeypot_table, (10, 7), lambda ax: draw_panel_honeypot_table(
        ax, deployed, active_zones, CFG,
        effective_targets, detects_on, profile_cost, detected_techniques,
        det_eff, tech_cov, fam_cov, fwd_pct, bwd_pct, Q,
        SLATE, WHITE, MGRAY, GREEN, RED, TEAL, AMBER, NAVY)),
]

for panel_name, _, figsize, draw_fn in panel_specs:
    fig_p = plt.figure(figsize=figsize, facecolor=NAVY)
    ax_p  = fig_p.add_subplot(111)
    draw_fn(ax_p)
    p_path = os.path.join(out_dir, f"panel_{panel_name}_{SIZE}.png")
    fig_p.savefig(p_path, dpi=160, bbox_inches='tight',
                  facecolor=NAVY, edgecolor='none')
    plt.close(fig_p)
    print(f"Panel saved → {p_path}")

# Radar panel (polar — needs special handling)
fig_r = plt.figure(figsize=(8, 8), facecolor=NAVY)
draw_panel_radar(fig_r, 111, det_eff, tech_cov, fam_cov,
                 fwd_pct, bwd_pct, Q, TEAL, SLATE, WHITE, MGRAY, AMBER)
r_path = os.path.join(out_dir, f"panel_radar_{SIZE}.png")
fig_r.savefig(r_path, dpi=160, bbox_inches='tight',
              facecolor=NAVY, edgecolor='none')
plt.close(fig_r)
print(f"Panel saved → {r_path}")


plt.close()
print(f"\nVisualization saved → {out_path}")
