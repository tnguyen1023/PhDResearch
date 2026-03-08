"""
MaxSAT Honeypot — Network Topology Visualizer
Generates 5 panels:
  1. Zone graph with edges, chokepoints, bandwidth tiers
  2. Attack paths overlaid on zone graph (one color per path)
  3. Asset-role breakdown + honeypot density per zone
  4. Honeypot profile coverage matrix
  5. MaxSAT solver result — detection coverage & budget allocation
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.lines import Line2D
import numpy as np
import os
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Set, Tuple, Optional
from itertools import combinations

# ── fixed node positions (x, y) ──────────────────────────────────────────────
NODE_POS = {
    'ext':   (-3.2,  0.0),
    'zone1': (-1.2,  0.0),
    'zone3': (-1.2,  2.2),
    'zone2': ( 1.2,  0.0),
    'zone4': ( 3.2, -1.5),
    'zone5': ( 3.2,  1.5),
}

# ── zone styling ──────────────────────────────────────────────────────────────
ZONE_STYLE = {
    'ext':   {'color': '#e74c3c', 'icon': '☠',  'size': 900},
    'zone1': {'color': '#e67e22', 'icon': '🌐', 'size': 1400},
    'zone2': {'color': '#2980b9', 'icon': '🏢', 'size': 1600},
    'zone3': {'color': '#8e44ad', 'icon': '☁',  'size': 1400},
    'zone4': {'color': '#c0392b', 'icon': '⚙',  'size': 1300},
    'zone5': {'color': '#16a085', 'icon': '🔒', 'size': 1300},
}

NODE_LABELS = {
    'ext':   'External\nInternet',
    'zone1': 'Zone 1\nDMZ',
    'zone2': 'Zone 2\nInternal LAN',
    'zone3': 'Zone 3\nCloud/Hybrid',
    'zone4': 'Zone 4\nOT/ICS/SCADA',
    'zone5': 'Zone 5\nManagement',
}

# ── attack path colors ────────────────────────────────────────────────────────
PATH_COLORS = {
    'web_to_db':       '#e74c3c',
    'cloud_pivot':     '#9b59b6',
    'brute_to_ad':     '#f39c12',
    'ot_infiltration': '#e67e22',
    'ransomware':      '#1abc9c',
}

PATH_ZONE_SEQS = {
    'web_to_db':       ['ext', 'zone1', 'zone2', 'zone2'],
    'cloud_pivot':     ['ext', 'zone3', 'zone2', 'zone2'],
    'brute_to_ad':     ['ext', 'zone1', 'zone2', 'zone5'],
    'ot_infiltration': ['ext', 'zone1', 'zone2', 'zone4'],
    'ransomware':      ['ext', 'zone2', 'zone2', 'zone2'],
}

PATH_LABELS = {
    'web_to_db':       'Web → DB Exfil  (30%)',
    'cloud_pivot':     'Cloud Pivot      (25%)',
    'brute_to_ad':     'Brute → AD       (20%)',
    'ot_infiltration': 'OT Infiltration  (15%)',
    'ransomware':      'Ransomware       (10%)',
}

EDGES = [
    {'from': 'ext',   'to': 'zone1', 'traversal_cost': 1.0, 'chokepoint': True,  'bandwidth_tier': 'high'},
    {'from': 'ext',   'to': 'zone3', 'traversal_cost': 1.2, 'chokepoint': True,  'bandwidth_tier': 'high'},
    {'from': 'zone1', 'to': 'zone2', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'medium'},
    {'from': 'zone1', 'to': 'zone3', 'traversal_cost': 1.5, 'chokepoint': False, 'bandwidth_tier': 'high'},
    {'from': 'zone3', 'to': 'zone2', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'medium'},
    {'from': 'zone2', 'to': 'zone4', 'traversal_cost': 3.0, 'chokepoint': True,  'bandwidth_tier': 'low'},
    {'from': 'zone2', 'to': 'zone5', 'traversal_cost': 3.5, 'chokepoint': True,  'bandwidth_tier': 'low'},
    {'from': 'zone5', 'to': 'zone2', 'traversal_cost': 1.0, 'chokepoint': False, 'bandwidth_tier': 'low'},
    {'from': 'zone5', 'to': 'zone4', 'traversal_cost': 2.0, 'chokepoint': True,  'bandwidth_tier': 'low'},
]

HARD_CUTS = [
    ('zone4', 'zone1'), ('zone4', 'zone3'),
    ('zone5', 'zone1'), ('zone5', 'zone3'),
]

BW_STYLE = {
    'high':   {'lw': 3.5, 'ls': '-',  'alpha': 0.85},
    'medium': {'lw': 2.2, 'ls': '-',  'alpha': 0.80},
    'low':    {'lw': 1.4, 'ls': '--', 'alpha': 0.70},
}

ASSET_ROLES = {
    'gateway':      {'share': 0.05, 'hp_density': 0.80, 'color': '#f1c40f', 'hm': 1.3},
    'service_host': {'share': 0.50, 'hp_density': 0.30, 'color': '#3498db', 'hm': 1.0},
    'support_host': {'share': 0.30, 'hp_density': 0.20, 'color': '#95a5a6', 'hm': 0.9},
    'deep_host':    {'share': 0.10, 'hp_density': 0.50, 'color': '#e74c3c', 'hm': 1.5},
    'jump_host':    {'share': 0.05, 'hp_density': 0.70, 'color': '#e67e22', 'hm': 1.4},
}

ZONE_INFO = {
    'zone1': {'label': 'DMZ',        'trust': 0, 'asset_share': 0.15, 'attack_share': 0.45},
    'zone2': {'label': 'Internal',   'trust': 2, 'asset_share': 0.40, 'attack_share': 0.25},
    'zone3': {'label': 'Cloud',      'trust': 1, 'asset_share': 0.25, 'attack_share': 0.20},
    'zone4': {'label': 'OT/ICS',     'trust': 3, 'asset_share': 0.10, 'attack_share': 0.05},
    'zone5': {'label': 'Management', 'trust': 4, 'asset_share': 0.10, 'attack_share': 0.05},
}

HONEYPOT_PROFILES = {
    'web_trap':    {'zones': ['zone1','zone3'],             'color': '#e74c3c'},
    'ssh_trap':    {'zones': ['zone1','zone2','zone3'],     'color': '#e67e22'},
    'db_trap':     {'zones': ['zone2','zone3'],             'color': '#9b59b6'},
    'smb_trap':    {'zones': ['zone2'],                     'color': '#3498db'},
    'scada_trap':  {'zones': ['zone4'],                     'color': '#c0392b'},
    'ad_trap':     {'zones': ['zone2','zone5'],             'color': '#1abc9c'},
    'dns_trap':    {'zones': ['zone1','zone2','zone3'],     'color': '#f39c12'},
    'generic_trap':{'zones': ['zone1','zone2','zone3','zone4','zone5'], 'color': '#7f8c8d'},
}


# =============================================================================
# MaxSAT PROBLEM INSTANCE  —  I = (K, T, A, Z, G, S, w, cost, C, B)
# =============================================================================

# ── Techniques T ─────────────────────────────────────────────────────────────
TECHNIQUES = [
    'SQLi', 'XSS', 'path_traversal', 'RCE_web',          # web techniques
    'ssh_brute', 'key_theft', 'privesc_sudo',              # ssh/auth
    'db_dump', 'schema_enum', 'credential_harvest',        # database
    'smb_relay', 'pass_the_hash', 'lateral_wmi',           # smb/lateral
    'scada_cmd', 'modbus_scan', 'plc_reprogram',           # OT/SCADA
    'kerberoast', 'dcsync', 'ad_enum',                     # AD/management
    'dns_poison', 'dns_exfil',                             # dns
    'arp_spoof', 'port_scan',                              # generic
]

# ── Server types G ────────────────────────────────────────────────────────────
SERVER_TYPES = ['web', 'ssh', 'database', 'smb', 'scada', 'ad', 'dns', 'generic']

# ── Technique sets per server type  S_{i, server_type} ───────────────────────
STYPE_TECHNIQUES: Dict[str, List[str]] = {
    'web':      ['SQLi', 'XSS', 'path_traversal', 'RCE_web'],
    'ssh':      ['ssh_brute', 'key_theft', 'privesc_sudo'],
    'database': ['db_dump', 'schema_enum', 'credential_harvest'],
    'smb':      ['smb_relay', 'pass_the_hash', 'lateral_wmi'],
    'scada':    ['scada_cmd', 'modbus_scan', 'plc_reprogram'],
    'ad':       ['kerberoast', 'dcsync', 'ad_enum'],
    'dns':      ['dns_poison', 'dns_exfil'],
    'generic':  ['arp_spoof', 'port_scan'],
}

# ── Assets A  (name → zone, server_type) ─────────────────────────────────────
ASSETS: Dict[str, Dict] = {
    # zone1 / DMZ
    'web-prod-01':   {'zone': 'zone1', 'type': 'web',      'value': 2.0},
    'web-prod-02':   {'zone': 'zone1', 'type': 'web',      'value': 1.8},
    'dns-ext-01':    {'zone': 'zone1', 'type': 'dns',      'value': 1.5},
    'ssh-jump-dmz':  {'zone': 'zone1', 'type': 'ssh',      'value': 2.5},
    # zone2 / Internal LAN
    'db-main-01':    {'zone': 'zone2', 'type': 'database', 'value': 3.5},
    'db-replica-01': {'zone': 'zone2', 'type': 'database', 'value': 2.8},
    'smb-fs-01':     {'zone': 'zone2', 'type': 'smb',      'value': 2.0},
    'ssh-internal':  {'zone': 'zone2', 'type': 'ssh',      'value': 1.5},
    'web-int-01':    {'zone': 'zone2', 'type': 'web',      'value': 1.2},
    # zone3 / Cloud
    'web-cloud-01':  {'zone': 'zone3', 'type': 'web',      'value': 2.2},
    'db-cloud-01':   {'zone': 'zone3', 'type': 'database', 'value': 2.5},
    'ssh-cloud-01':  {'zone': 'zone3', 'type': 'ssh',      'value': 1.8},
    # zone4 / OT-ICS
    'plc-main-01':   {'zone': 'zone4', 'type': 'scada',    'value': 4.5},
    'plc-backup-01': {'zone': 'zone4', 'type': 'scada',    'value': 3.8},
    'hmi-01':        {'zone': 'zone4', 'type': 'scada',    'value': 3.2},
    # zone5 / Management
    'dc-primary':    {'zone': 'zone5', 'type': 'ad',       'value': 4.0},
    'dc-backup':     {'zone': 'zone5', 'type': 'ad',       'value': 3.5},
    'ssh-mgmt-01':   {'zone': 'zone5', 'type': 'ssh',      'value': 2.0},
    'dns-int-01':    {'zone': 'zone5', 'type': 'dns',      'value': 1.8},
}

# ── Detection value w_{j,a}  (technique × asset weight) ──────────────────────
# Base weight = asset value; high-value techniques get a multiplier
TECHNIQUE_WEIGHT: Dict[str, float] = {
    'SQLi': 1.2, 'XSS': 0.8, 'path_traversal': 1.0, 'RCE_web': 1.5,
    'ssh_brute': 1.0, 'key_theft': 1.4, 'privesc_sudo': 1.3,
    'db_dump': 1.5, 'schema_enum': 0.9, 'credential_harvest': 1.4,
    'smb_relay': 1.3, 'pass_the_hash': 1.5, 'lateral_wmi': 1.2,
    'scada_cmd': 2.0, 'modbus_scan': 1.6, 'plc_reprogram': 2.5,
    'kerberoast': 1.8, 'dcsync': 2.2, 'ad_enum': 1.0,
    'dns_poison': 1.3, 'dns_exfil': 1.1,
    'arp_spoof': 0.8, 'port_scan': 0.6,
}

def detection_weight(technique: str, asset: str) -> float:
    """w_{j,a} = technique_weight * asset_value"""
    return TECHNIQUE_WEIGHT.get(technique, 1.0) * ASSETS[asset]['value']


# ── Honeypot configurations K ─────────────────────────────────────────────────
# Each config maps to HONEYPOT_PROFILES + server type + explicit direct assets
@dataclass
class HoneypotConfig:
    name:       str
    ZK:         List[str]          # zones config may operate in
    GK:         List[str]          # server types config is designed for
    DK:         List[str]          # direct asset overrides
    cost:       float
    color:      str

    def effective_targets(self) -> List[str]:
        """T*(i) = DK ∪ { a ∈ A : type(a) ∈ GK ∧ zone(a) ∈ ZK }"""
        targets = set(self.DK)
        for asset_name, asset_info in ASSETS.items():
            if asset_info['type'] in self.GK and asset_info['zone'] in self.ZK:
                targets.add(asset_name)
        return sorted(targets)

    def detected_techniques(self, asset: str) -> List[str]:
        """
        S*(i, a):
          - if a ∈ DK: use type(a) techniques (explicit placement)
          - else:       use GK ∩ type(a) inherited techniques
        """
        asset_type = ASSETS[asset]['type']
        return STYPE_TECHNIQUES.get(asset_type, [])


CONFIGS: List[HoneypotConfig] = [
    HoneypotConfig('web_trap',    ['zone1','zone3'],         ['web'],            [],              cost=3.0,  color='#e74c3c'),
    HoneypotConfig('ssh_trap',    ['zone1','zone2','zone3'], ['ssh'],            [],              cost=2.5,  color='#e67e22'),
    HoneypotConfig('db_trap',     ['zone2','zone3'],         ['database'],       ['db-main-01'],  cost=4.0,  color='#9b59b6'),
    HoneypotConfig('smb_trap',    ['zone2'],                 ['smb'],            [],              cost=2.0,  color='#3498db'),
    HoneypotConfig('scada_trap',  ['zone4'],                 ['scada'],          ['plc-main-01'], cost=6.0,  color='#c0392b'),
    HoneypotConfig('ad_trap',     ['zone2','zone5'],         ['ad'],             ['dc-primary'],  cost=5.0,  color='#1abc9c'),
    HoneypotConfig('dns_trap',    ['zone1','zone2','zone3'], ['dns'],            [],              cost=2.0,  color='#f39c12'),
    HoneypotConfig('generic_trap',['zone1','zone2','zone3','zone4','zone5'], ['generic'], [],    cost=1.5,  color='#7f8c8d'),
    # Extended configs — multi-role honeypots
    HoneypotConfig('web_ssh_combo',   ['zone1','zone3'],    ['web','ssh'],       [],              cost=4.5,  color='#fd79a8'),
    HoneypotConfig('db_smb_combo',    ['zone2'],            ['database','smb'],  [],              cost=5.5,  color='#6c5ce7'),
    HoneypotConfig('scada_generic',   ['zone4'],            ['scada','generic'], [],              cost=6.5,  color='#d63031'),
    HoneypotConfig('ad_dns_combo',    ['zone5','zone2'],    ['ad','dns'],        ['dc-backup'],   cost=6.0,  color='#00b894'),
]

# ── Conflict pairs C ⊆ K × K ─────────────────────────────────────────────────
# Configs that cannot be deployed simultaneously (resource/port conflicts)
CONFLICTS: List[Tuple[int, int]] = [
    (0, 8),   # web_trap vs web_ssh_combo  (both web in zone1)
    (1, 8),   # ssh_trap vs web_ssh_combo  (both ssh in zone1)
    (2, 9),   # db_trap  vs db_smb_combo   (both db  in zone2)
    (3, 9),   # smb_trap vs db_smb_combo   (both smb in zone2)
    (4, 10),  # scada_trap vs scada_generic (both scada in zone4)
    (5, 11),  # ad_trap  vs ad_dns_combo   (both ad  in zone5)
    (6, 11),  # dns_trap vs ad_dns_combo   (both dns in zone5)
]

# ── Zone-isolated pairs I ⊆ Z × Z ────────────────────────────────────────────
# No single config may span both zones (air-gap enforcement)
ZONE_ISOLATED: List[Tuple[str, str]] = [
    ('zone4', 'zone1'), ('zone4', 'zone3'),
    ('zone5', 'zone1'), ('zone5', 'zone3'),
]

# ── Budget ────────────────────────────────────────────────────────────────────
GLOBAL_BUDGET = 20.0
ZONE_BUDGETS: Dict[str, float] = {
    'zone1': 6.0,
    'zone2': 8.0,
    'zone3': 5.0,
    'zone4': 7.0,
    'zone5': 6.0,
}


# =============================================================================
# MaxSAT GREEDY SOLVER
# Maximise: Σ_{j,a} w_{j,a} * c_{j,a}
# where c_{j,a} = 1 iff ∃ selected k_i with a ∈ T*(i) and t_j ∈ S*(i,a)
# Subject to:
#   Σ cost_i * x_i  ≤  B                           (global budget)
#   Σ_{i: zone(i)=z} cost_i * x_i  ≤  B_z          (zone sub-budgets)
#   x_i + x_j ≤ 1  ∀(i,j) ∈ C                      (conflict free)
#   ¬∃ k_i : ZK_i spans isolated zone pair           (zone isolation)
# =============================================================================

@dataclass
class SolverResult:
    selected_configs:   List[int]
    total_cost:         float
    total_value:        float
    coverage_matrix:    np.ndarray   # shape (|techniques|, |assets|)
    zone_costs:         Dict[str, float]
    zone_coverage:      Dict[str, float]   # fraction of (t,a) pairs covered per zone
    technique_coverage: Dict[str, float]   # fraction of assets each technique covers
    asset_coverage:     Dict[str, int]     # number of techniques covering each asset
    budget_utilisation: float
    num_configs:        int


def solve_maxsat_greedy(
        configs:       List[HoneypotConfig],
        assets:        Dict[str, Dict],
        techniques:    List[str],
        conflicts:     List[Tuple[int, int]],
        zone_isolated: List[Tuple[str, str]],
        global_budget: float,
        zone_budgets:  Dict[str, float],
) -> SolverResult:
    """
    Greedy MaxSAT solver.

    Scoring per config:
        score(k_i) = Σ_{a ∈ T*(i)} Σ_{t_j ∈ S*(i,a)} w_{j,a} * (1 − already_covered_{j,a})
                     ──────────────────────────────────────────────────────────────────────────
                                              cost_i

    This is the marginal gain in weighted detection value per unit cost,
    counting only newly covered (technique, asset) pairs.
    """
    n_tech   = len(techniques)
    n_assets = len(assets)
    asset_ids = {a: i for i, a in enumerate(sorted(assets.keys()))}
    tech_ids  = {t: i for i, t in enumerate(techniques)}

    # covered[j, a] = True if pair (technique_j, asset_a) already detected
    covered = np.zeros((n_tech, n_assets), dtype=bool)

    # Track zone cost usage
    zone_spent: Dict[str, float] = {z: 0.0 for z in zone_budgets}
    total_spent = 0.0
    selected: List[int] = []

    # Pre-validate zone isolation: discard configs that span isolated pairs
    def spans_isolation(cfg: HoneypotConfig) -> bool:
        for (z1, z2) in zone_isolated:
            if z1 in cfg.ZK and z2 in cfg.ZK:
                return True
        return False

    valid_configs = [i for i, cfg in enumerate(configs) if not spans_isolation(cfg)]

    # Conflict set — fast lookup
    conflict_set: Set[Tuple[int, int]] = set()
    for (a, b) in conflicts:
        conflict_set.add((a, b))
        conflict_set.add((b, a))

    def is_feasible(cfg_idx: int) -> bool:
        cfg = configs[cfg_idx]
        # Global budget
        if total_spent + cfg.cost > global_budget + 1e-9:
            return False
        # Zone sub-budgets
        zone_cost_delta: Dict[str, float] = {}
        for z in cfg.ZK:
            zone_cost_delta[z] = zone_cost_delta.get(z, 0) + cfg.cost / len(cfg.ZK)
        for z, delta in zone_cost_delta.items():
            if z in zone_budgets:
                if zone_spent.get(z, 0) + delta > zone_budgets[z] + 1e-9:
                    return False
        # Conflict constraints
        for sel_idx in selected:
            if (cfg_idx, sel_idx) in conflict_set:
                return False
        return True

    def marginal_value(cfg_idx: int) -> float:
        cfg = configs[cfg_idx]
        targets = cfg.effective_targets()
        gain = 0.0
        for asset in targets:
            if asset not in asset_ids:
                continue
            ai = asset_ids[asset]
            techs = cfg.detected_techniques(asset)
            for t in techs:
                if t not in tech_ids:
                    continue
                ti = tech_ids[t]
                if not covered[ti, ai]:
                    gain += detection_weight(t, asset)
        return gain

    def density_score(cfg_idx: int) -> float:
        gain = marginal_value(cfg_idx)
        cost = configs[cfg_idx].cost
        return gain / max(cost, 1e-9)

    # Greedy selection loop
    remaining = set(valid_configs)
    while remaining:
        # Score all remaining feasible configs
        candidates = [(idx, density_score(idx)) for idx in remaining if is_feasible(idx)]
        if not candidates:
            break

        best_idx, best_score = max(candidates, key=lambda x: x[1])
        if best_score <= 0:
            break

        # Select best config
        cfg = configs[best_idx]
        selected.append(best_idx)
        remaining.discard(best_idx)

        # Update budget tracking
        total_spent += cfg.cost
        for z in cfg.ZK:
            zone_spent[z] = zone_spent.get(z, 0) + cfg.cost / len(cfg.ZK)

        # Update covered matrix
        for asset in cfg.effective_targets():
            if asset not in asset_ids:
                continue
            ai = asset_ids[asset]
            for t in cfg.detected_techniques(asset):
                if t not in tech_ids:
                    continue
                ti = tech_ids[t]
                covered[ti, ai] = True

        # Remove conflicting configs
        remaining -= {j for j in remaining if (best_idx, j) in conflict_set}

    # ── Build result metrics ──────────────────────────────────────────────────
    total_value = 0.0
    for ti, t in enumerate(techniques):
        for ai, asset in enumerate(sorted(assets.keys())):
            if covered[ti, ai]:
                total_value += detection_weight(t, asset)

    # Zone coverage: fraction of possible (technique, asset) pairs covered per zone
    zone_coverage: Dict[str, float] = {}
    for zone in ZONE_INFO:
        zone_assets = [a for a, info in assets.items() if info['zone'] == zone]
        if not zone_assets:
            zone_coverage[zone] = 0.0
            continue
        total_pairs   = len(techniques) * len(zone_assets)
        covered_pairs = sum(
            1 for ti in range(n_tech)
            for asset in zone_assets
            if covered[ti, asset_ids[asset]]
        )
        zone_coverage[zone] = covered_pairs / max(total_pairs, 1)

    # Technique coverage: fraction of assets each technique covers
    technique_coverage: Dict[str, float] = {}
    for ti, t in enumerate(techniques):
        covered_assets = int(covered[ti, :].sum())
        technique_coverage[t] = covered_assets / max(n_assets, 1)

    # Asset coverage: number of techniques covering each asset
    asset_coverage: Dict[str, int] = {}
    for asset in sorted(assets.keys()):
        ai = asset_ids[asset]
        asset_coverage[asset] = int(covered[:, ai].sum())

    return SolverResult(
        selected_configs   = selected,
        total_cost         = total_spent,
        total_value        = total_value,
        coverage_matrix    = covered.astype(float),
        zone_costs         = zone_spent,
        zone_coverage      = zone_coverage,
        technique_coverage = technique_coverage,
        asset_coverage     = asset_coverage,
        budget_utilisation = total_spent / max(global_budget, 1e-9),
        num_configs        = len(selected),
    )


# =============================================================================
# HELPERS
# =============================================================================

def draw_arrow(ax, src, dst, color, lw=2.0, alpha=0.9,
               offset=(0, 0), ls='-', head=12, zorder=3,
               rad=0.0):
    x0, y0 = NODE_POS[src][0]+offset[0], NODE_POS[src][1]+offset[1]
    x1, y1 = NODE_POS[dst][0]+offset[0], NODE_POS[dst][1]+offset[1]
    style = f"Arc3,rad={rad}"
    ax.annotate('', xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle=f'-|>,head_width={head/100:.2f},head_length={head/100*1.5:.2f}',
                                color=color, lw=lw, alpha=alpha,
                                linestyle=ls,
                                connectionstyle=style),
                zorder=zorder)


def draw_node(ax, node_id, size_override=None):
    x, y = NODE_POS[node_id]
    style = ZONE_STYLE[node_id]
    sz = size_override or style['size']
    ax.scatter(x+0.04, y-0.04, s=sz*1.1, c='#1a1a2e', alpha=0.25, zorder=4)
    ax.scatter(x, y, s=sz, c=style['color'], edgecolors='white',
               linewidths=2.5, zorder=5, alpha=0.93)


def draw_label(ax, node_id, fontsize=8.5):
    x, y = NODE_POS[node_id]
    style = ZONE_STYLE[node_id]
    sz = style['size']
    offset_y = -np.sqrt(sz) / 130 - 0.30
    ax.text(x, y + offset_y, NODE_LABELS[node_id],
            ha='center', va='top', fontsize=fontsize,
            fontweight='bold', color='white',
            bbox=dict(boxstyle='round,pad=0.2', facecolor=style['color'],
                      alpha=0.85, edgecolor='none'),
            zorder=7)


def ax_base_style(ax):
    ax.set_facecolor('#0d1117')
    ax.set_xlim(-4.5, 4.5)
    ax.set_ylim(-2.8, 3.2)
    ax.axis('off')


# =============================================================================
# PANEL 1 — Zone Graph
# =============================================================================

def draw_zone_graph(ax):
    ax_base_style(ax)
    ax.set_title('Zone Graph — Edges, Chokepoints & Bandwidth',
                 color='white', fontsize=11, fontweight='bold', pad=8)

    zone_hull_colors = {
        'zone1': '#e67e22', 'zone2': '#2980b9',
        'zone3': '#8e44ad', 'zone4': '#c0392b', 'zone5': '#16a085',
    }
    for zid, (x, y) in NODE_POS.items():
        if zid == 'ext': continue
        circle = plt.Circle((x, y), 0.65, color=zone_hull_colors[zid],
                            alpha=0.08, zorder=1)
        ax.add_patch(circle)

    for e in EDGES:
        src, dst = e['from'], e['to']
        bw = e['bandwidth_tier']
        style = BW_STYLE[bw]
        color = '#ff6b6b' if e['chokepoint'] else '#74b9ff'

        rad = 0.18 if (src == 'zone5' and dst == 'zone2') or \
                      (src == 'zone2' and dst == 'zone5') else 0.08

        draw_arrow(ax, src, dst, color=color,
                   lw=style['lw'], alpha=style['alpha'],
                   ls=style['ls'], head=14, zorder=3, rad=rad)

        if e['chokepoint']:
            mx = (NODE_POS[src][0] + NODE_POS[dst][0]) / 2
            my = (NODE_POS[src][1] + NODE_POS[dst][1]) / 2
            ax.text(mx, my + 0.12, '🔥', fontsize=8, ha='center', va='center',
                    zorder=6, alpha=0.85)

        mx = (NODE_POS[src][0] + NODE_POS[dst][0]) / 2
        my = (NODE_POS[src][1] + NODE_POS[dst][1]) / 2
        ax.text(mx - 0.12, my - 0.14, f"c={e['traversal_cost']}",
                fontsize=6.5, color='#aaaaaa', ha='center', zorder=6)

    for (z1, z2) in HARD_CUTS:
        x0, y0 = NODE_POS[z1]
        x1, y1 = NODE_POS[z2]
        mx, my = (x0+x1)/2, (y0+y1)/2
        ax.plot([x0, x1], [y0, y1], color='#ff0000', lw=1.0,
                ls=':', alpha=0.35, zorder=2)
        ax.text(mx, my, '✂ air-gap', fontsize=6, color='#ff6b6b',
                ha='center', va='center', zorder=6,
                bbox=dict(facecolor='#1a1a2e', edgecolor='none', alpha=0.7, pad=1))

    for node_id in NODE_POS:
        draw_node(ax, node_id)
        draw_label(ax, node_id)

    legend_items = [
        Line2D([0],[0], color='#ff6b6b', lw=2.5, label='Chokepoint edge (firewall)'),
        Line2D([0],[0], color='#74b9ff', lw=2.5, label='Open edge'),
        Line2D([0],[0], color='white',   lw=3.0, label='High bandwidth'),
        Line2D([0],[0], color='white',   lw=2.0, label='Medium bandwidth'),
        Line2D([0],[0], color='white',   lw=1.2, ls='--', label='Low bandwidth'),
        Line2D([0],[0], color='#ff0000', lw=1.0, ls=':', label='Air-gap / hard cut'),
    ]
    ax.legend(handles=legend_items, loc='lower left', fontsize=6.5,
              facecolor='#1a1a2e', edgecolor='#444', labelcolor='white',
              framealpha=0.9, handlelength=2.2)


# =============================================================================
# PANEL 2 — Attack Paths
# =============================================================================

def draw_attack_paths(ax):
    ax_base_style(ax)
    ax.set_title('Attack Path Model — Lateral Movement Sequences',
                 color='white', fontsize=11, fontweight='bold', pad=8)

    for e in EDGES:
        src, dst = e['from'], e['to']
        x0, y0 = NODE_POS[src]; x1, y1 = NODE_POS[dst]
        rad = 0.18 if (src=='zone5' and dst=='zone2') or \
                      (src=='zone2' and dst=='zone5') else 0.08
        ax.annotate('', xy=(x1,y1), xytext=(x0,y0),
                    arrowprops=dict(arrowstyle='->', color='#333355',
                                    lw=1.2, alpha=0.4,
                                    connectionstyle=f'Arc3,rad={rad}'),
                    zorder=2)

    offsets = [(-0.06, 0.06), (0.06, 0.06), (-0.06, -0.06),
               (0.06, -0.06), (0.00, 0.12)]
    path_rad = {
        'web_to_db':       0.10,
        'cloud_pivot':     -0.10,
        'brute_to_ad':     0.15,
        'ot_infiltration': -0.15,
        'ransomware':      0.20,
    }

    for i, (path_id, zones) in enumerate(PATH_ZONE_SEQS.items()):
        color = PATH_COLORS[path_id]
        off = offsets[i % len(offsets)]
        rad = path_rad[path_id]
        unique_hops = []
        for j in range(len(zones)-1):
            pair = (zones[j], zones[j+1])
            if pair[0] != pair[1] and pair not in unique_hops:
                unique_hops.append(pair)

        for src, dst in unique_hops:
            draw_arrow(ax, src, dst, color=color, lw=2.8,
                       alpha=0.88, offset=off, head=15,
                       zorder=5, rad=rad)

        if unique_hops:
            src, dst = unique_hops[0]
            x0, y0 = NODE_POS[src][0]+off[0], NODE_POS[src][1]+off[1]
            x1, y1 = NODE_POS[dst][0]+off[0], NODE_POS[dst][1]+off[1]
            mx, my = (x0+x1)/2 + 0.08, (y0+y1)/2 + 0.08
            ax.text(mx, my, f'P={["0.30","0.25","0.20","0.15","0.10"][i]}',
                    fontsize=6, color=color, fontweight='bold',
                    zorder=8, ha='center',
                    bbox=dict(facecolor='#0d1117', edgecolor=color,
                              linewidth=0.8, alpha=0.85, pad=1.5,
                              boxstyle='round,pad=0.2'))

    for node_id in NODE_POS:
        draw_node(ax, node_id)
        draw_label(ax, node_id, fontsize=8)

    legend_items = [
        mpatches.Patch(color=PATH_COLORS[pid], label=PATH_LABELS[pid])
        for pid in PATH_COLORS
    ]
    ax.legend(handles=legend_items, loc='lower left', fontsize=6.5,
              facecolor='#1a1a2e', edgecolor='#444', labelcolor='white',
              framealpha=0.9, title='Attack Paths', title_fontsize=7)


# =============================================================================
# PANEL 3 — Asset Roles & Honeypot Density
# =============================================================================

def draw_asset_roles(ax):
    ax.set_facecolor('#0d1117')
    ax.set_title('Asset Roles × Honeypot Density per Zone',
                 color='white', fontsize=11, fontweight='bold', pad=8)

    zones   = list(ZONE_INFO.keys())
    roles   = list(ASSET_ROLES.keys())
    n_zones = len(zones)
    n_roles = len(roles)
    bar_w   = 0.13
    x_base  = np.arange(n_zones)

    for ri, role in enumerate(roles):
        info  = ASSET_ROLES[role]
        xs    = x_base + (ri - n_roles/2 + 0.5) * bar_w
        heights = [info['share'] * 100] * n_zones
        bars = ax.bar(xs, heights, bar_w, color=info['color'],
                      alpha=0.78, label=role.replace('_',' ').title(),
                      edgecolor='#1a1a2e', linewidth=0.5)

        hp_h = [info['share'] * info['hp_density'] * 100] * n_zones
        ax.bar(xs, hp_h, bar_w, color=info['color'],
               alpha=0.95, hatch='///', edgecolor='white',
               linewidth=0.3)

    ax.set_xticks(x_base)
    ax.set_xticklabels(
        [f"{zid}\n{ZONE_INFO[zid]['label']}\ntrust={ZONE_INFO[zid]['trust']}"
         for zid in zones],
        color='white', fontsize=8
    )
    ax.set_ylabel('Share of Zone (%)', color='white', fontsize=9)
    ax.set_ylim(0, 65)
    ax.tick_params(colors='white')
    ax.spines['bottom'].set_color('#444')
    ax.spines['left'].set_color('#444')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.label.set_color('white')

    for i, (zid, info) in enumerate(ZONE_INFO.items()):
        ax.text(i, 58, f"atk {info['attack_share']*100:.0f}%",
                ha='center', fontsize=7.5, color='#e74c3c', fontweight='bold')
        ax.text(i, 54.5, f"assets {info['asset_share']*100:.0f}%",
                ha='center', fontsize=7, color='#74b9ff')

    legend = ax.legend(fontsize=7, facecolor='#1a1a2e', edgecolor='#444',
                       labelcolor='white', ncol=5, loc='upper right',
                       framealpha=0.9)
    legend.set_title('Role  (/// = honeypot density)', prop={'size':7})
    legend.get_title().set_color('white')

    ax.set_facecolor('#0d1117')
    ax.figure.patch.set_facecolor('#0d1117')
    ax.grid(axis='y', color='#222244', linestyle='--', linewidth=0.6, alpha=0.6)


# =============================================================================
# PANEL 4 — Honeypot Profile Coverage Map
# =============================================================================

def draw_honeypot_map(ax):
    ax.set_facecolor('#0d1117')
    ax.set_title('Honeypot Profile → Zone Coverage Matrix',
                 color='white', fontsize=11, fontweight='bold', pad=8)

    profiles = list(HONEYPOT_PROFILES.keys())
    zones    = ['zone1','zone2','zone3','zone4','zone5']
    matrix   = np.zeros((len(profiles), len(zones)))

    for pi, pname in enumerate(profiles):
        for zi, z in enumerate(zones):
            if z in HONEYPOT_PROFILES[pname]['zones']:
                matrix[pi, zi] = 1.0

    profile_labels = [p.replace('_trap','').replace('_',' ').upper() for p in profiles]
    zone_labels    = ['Zone1\nDMZ','Zone2\nInternal','Zone3\nCloud',
                      'Zone4\nOT/ICS','Zone5\nMgmt']

    im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1,
                   alpha=0.85)

    ax.set_xticks(range(len(zones)));   ax.set_xticklabels(zone_labels, color='white', fontsize=8)
    ax.set_yticks(range(len(profiles))); ax.set_yticklabels(profile_labels, color='white', fontsize=8)
    ax.tick_params(colors='white')

    for pi in range(len(profiles)):
        for zi in range(len(zones)):
            sym = '✓' if matrix[pi, zi] else '·'
            col = '#1a1a2e' if matrix[pi, zi] else '#555'
            ax.text(zi, pi, sym, ha='center', va='center',
                    fontsize=12, color=col, fontweight='bold')

    for pi, pname in enumerate(profiles):
        color = HONEYPOT_PROFILES[pname]['color']
        ax.add_patch(FancyBboxPatch((-0.5, pi-0.48), len(zones), 0.96,
                                    boxstyle='round,pad=0.02',
                                    facecolor=color, alpha=0.08,
                                    edgecolor=color, linewidth=0.6,
                                    zorder=0))

    ax.spines[:].set_color('#444')
    ax.set_facecolor('#0d1117')
    ax.grid(False)


# =============================================================================
# PANEL 5 — MaxSAT Solver Results
# Four sub-panels:
#   5a. Selected configs + budget bar
#   5b. Asset coverage heatmap (technique × asset)
#   5c. Zone coverage bar chart
#   5d. Technique coverage ranked bar
# =============================================================================

def draw_maxsat_results(ax_main, result: SolverResult):
    """
    Renders the MaxSAT solver panel as a composite of 4 sub-axes
    carved from ax_main's bounding box.
    """
    ax_main.set_facecolor('#0d1117')
    ax_main.axis('off')
    ax_main.set_title(
        f'MaxSAT Solver — Greedy Optimal Placement  '
        f'(budget={GLOBAL_BUDGET:.0f}, selected={result.num_configs}, '
        f'value={result.total_value:.1f}, utilisation={result.budget_utilisation*100:.0f}%)',
        color='white', fontsize=10, fontweight='bold', pad=8
    )

    fig = ax_main.figure
    pos = ax_main.get_position()   # Bbox in figure-fraction coords

    # Carve 4 sub-axes from the main panel area
    l, b, w, h = pos.x0, pos.y0, pos.width, pos.height
    pad = 0.01

    # Layout:  [budget bar | zone coverage]  top row
    #          [coverage heatmap full width]  bottom row
    top_h    = h * 0.38
    bot_h    = h * 0.56
    mid_gap  = h * 0.06

    ax_budget = fig.add_axes([l,               b + bot_h + mid_gap, w*0.46 - pad, top_h])
    ax_zone   = fig.add_axes([l + w*0.46 + pad, b + bot_h + mid_gap, w*0.54 - pad, top_h])
    ax_heat   = fig.add_axes([l,               b,                    w*0.65 - pad, bot_h])
    ax_tech   = fig.add_axes([l + w*0.65 + pad, b,                   w*0.35 - pad, bot_h])

    # ── 5a. Budget breakdown bar ──────────────────────────────────────────────
    _draw_budget_bar(ax_budget, result)

    # ── 5b. Zone coverage bars ────────────────────────────────────────────────
    _draw_zone_coverage(ax_zone, result)

    # ── 5c. Detection coverage heatmap (technique × asset) ───────────────────
    _draw_coverage_heatmap(ax_heat, result)

    # ── 5d. Technique coverage ranked bar ────────────────────────────────────
    _draw_technique_coverage(ax_tech, result)


def _draw_budget_bar(ax, result: SolverResult):
    ax.set_facecolor('#0d1117')
    ax.set_title('Budget Allocation per Zone', color='white', fontsize=8, pad=4)

    zone_colors = {
        'zone1': '#e67e22', 'zone2': '#2980b9',
        'zone3': '#8e44ad', 'zone4': '#c0392b', 'zone5': '#16a085',
    }
    zones = list(ZONE_INFO.keys())

    # Stacked bar: spent vs remaining vs over-budget
    spent  = [result.zone_costs.get(z, 0) for z in zones]
    budget = [ZONE_BUDGETS.get(z, 0)      for z in zones]
    remain = [max(budget[i] - spent[i], 0) for i in range(len(zones))]

    x = np.arange(len(zones))
    bars_s = ax.bar(x, spent,  0.55,
                    color=[zone_colors[z] for z in zones],
                    alpha=0.9, label='Spent', edgecolor='white', linewidth=0.5)
    ax.bar(x, remain, 0.55, bottom=spent,
           color=[zone_colors[z] for z in zones],
           alpha=0.25, label='Remaining', edgecolor='none')

    # Budget cap line
    for i, b in enumerate(budget):
        ax.plot([i-0.28, i+0.28], [b, b], color='#f1c40f', lw=1.5, zorder=5)

    # Global budget annotation
    ax.axhline(GLOBAL_BUDGET / len(zones), color='#e74c3c',
               lw=1.0, ls='--', alpha=0.5, label=f'Avg global')

    # Value labels on bars
    for i, (s, b_) in enumerate(zip(spent, budget)):
        ax.text(i, s + 0.1, f'{s:.1f}', ha='center', fontsize=6.5,
                color='white', fontweight='bold')
        ax.text(i, -0.5, f'/{b_:.0f}', ha='center', fontsize=6,
                color='#aaa')

    ax.set_xticks(x)
    ax.set_xticklabels([f"Z{zi+1}" for zi in range(len(zones))],
                       color='white', fontsize=7)
    ax.set_ylabel('Cost', color='white', fontsize=7)
    ax.tick_params(colors='white', labelsize=7)
    ax.spines['bottom'].set_color('#444'); ax.spines['left'].set_color('#444')
    ax.spines['top'].set_visible(False);  ax.spines['right'].set_visible(False)
    ax.set_ylim(-1, max(max(budget), 1) * 1.25)
    ax.yaxis.label.set_color('white')
    ax.legend(fontsize=6, facecolor='#1a1a2e', edgecolor='#444',
              labelcolor='white', loc='upper right')
    ax.set_facecolor('#0d1117')

    # Selected config names inside panel
    sel_names = [CONFIGS[i].name for i in result.selected_configs]
    ax.text(0.02, 0.98,
            'Selected:\n' + '\n'.join(f'  ✓ {n}' for n in sel_names),
            transform=ax.transAxes, fontsize=5.5, color='#74b9ff',
            va='top', ha='left',
            bbox=dict(facecolor='#0d1117', edgecolor='#444',
                      alpha=0.85, pad=2, boxstyle='round,pad=0.3'))


def _draw_zone_coverage(ax, result: SolverResult):
    ax.set_facecolor('#0d1117')
    ax.set_title('Zone Detection Coverage  &  Weighted Value',
                 color='white', fontsize=8, pad=4)

    zone_colors = {
        'zone1': '#e67e22', 'zone2': '#2980b9',
        'zone3': '#8e44ad', 'zone4': '#c0392b', 'zone5': '#16a085',
    }
    zones = list(ZONE_INFO.keys())
    cov   = [result.zone_coverage.get(z, 0) * 100 for z in zones]

    # Weighted value per zone (sum of w_{j,a} for covered pairs in zone)
    asset_ids = {a: i for i, a in enumerate(sorted(ASSETS.keys()))}
    tech_ids  = {t: i for i, t in enumerate(TECHNIQUES)}
    zone_vals = []
    for zone in zones:
        zone_assets = [a for a, info in ASSETS.items() if info['zone'] == zone]
        val = 0.0
        for a in zone_assets:
            ai = asset_ids[a]
            for ti, t in enumerate(TECHNIQUES):
                if result.coverage_matrix[ti, ai]:
                    val += detection_weight(t, a)
        zone_vals.append(val)

    x    = np.arange(len(zones))
    bar_w = 0.35

    ax2 = ax.twinx()
    ax2.bar(x + bar_w/2, zone_vals, bar_w,
            color=[zone_colors[z] for z in zones],
            alpha=0.35, label='Weighted value')
    ax2.set_ylabel('Detection Value', color='#74b9ff', fontsize=7)
    ax2.tick_params(colors='#74b9ff', labelsize=6)
    ax2.spines['right'].set_color('#74b9ff')
    ax2.set_facecolor('#0d1117')
    ax2.yaxis.label.set_color('#74b9ff')

    bars = ax.bar(x - bar_w/2, cov, bar_w,
                  color=[zone_colors[z] for z in zones],
                  alpha=0.9, label='Coverage %', edgecolor='white', linewidth=0.4)
    ax.axhline(100, color='#2ecc71', lw=1.0, ls='--', alpha=0.5)

    for i, c in enumerate(cov):
        ax.text(i - bar_w/2, c + 1.5, f'{c:.0f}%',
                ha='center', fontsize=6.5, color='white', fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(
        [f"{ZONE_INFO[z]['label']}" for z in zones],
        color='white', fontsize=7
    )
    ax.set_ylabel('Coverage (%)', color='white', fontsize=7)
    ax.set_ylim(0, 120)
    ax.tick_params(colors='white', labelsize=7)
    ax.spines['bottom'].set_color('#444'); ax.spines['left'].set_color('#444')
    ax.spines['top'].set_visible(False)
    ax.yaxis.label.set_color('white')
    ax.set_facecolor('#0d1117')

    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2,
              fontsize=6, facecolor='#1a1a2e', edgecolor='#444',
              labelcolor='white', loc='upper right')


def _draw_coverage_heatmap(ax, result: SolverResult):
    """
    Technique × Asset detection coverage heatmap.
    Cell value = w_{j,a}  if covered, 0 otherwise.
    """
    ax.set_facecolor('#0d1117')
    ax.set_title('Detection Coverage Matrix  (w_{j,a} if covered)',
                 color='white', fontsize=8, pad=4)

    assets_sorted = sorted(ASSETS.keys())
    n_tech  = len(TECHNIQUES)
    n_asset = len(assets_sorted)

    # Build weighted coverage matrix
    asset_ids = {a: i for i, a in enumerate(assets_sorted)}
    weight_matrix = np.zeros((n_tech, n_asset))
    for ti, t in enumerate(TECHNIQUES):
        for ai, a in enumerate(assets_sorted):
            if result.coverage_matrix[ti, ai]:
                weight_matrix[ti, ai] = detection_weight(t, a)

    im = ax.imshow(weight_matrix, cmap='YlOrRd', aspect='auto',
                   vmin=0, vmax=weight_matrix.max() or 1, alpha=0.9)

    # Zone-colored column headers
    zone_colors = {
        'zone1': '#e67e22', 'zone2': '#2980b9',
        'zone3': '#8e44ad', 'zone4': '#c0392b', 'zone5': '#16a085',
    }
    ax.set_xticks(range(n_asset))
    ax.set_xticklabels(
        [a.replace('-','‑') for a in assets_sorted],
        rotation=55, ha='right', fontsize=5.5, color='white'
    )
    # Color each x-tick by zone
    for tick, asset in zip(ax.get_xticklabels(), assets_sorted):
        z = ASSETS[asset]['zone']
        tick.set_color(zone_colors.get(z, 'white'))

    ax.set_yticks(range(n_tech))
    ax.set_yticklabels(TECHNIQUES, fontsize=5.5, color='white')

    ax.tick_params(colors='white', labelsize=5.5)
    ax.spines[:].set_color('#444')

    # Colorbar
    cbar = ax.figure.colorbar(im, ax=ax, fraction=0.025, pad=0.01)
    cbar.ax.tick_params(colors='white', labelsize=5)
    cbar.set_label('w_{j,a}', color='white', fontsize=6)

    # Zone separator lines
    zone_order = ['zone1','zone2','zone3','zone4','zone5']
    col = 0
    for z in zone_order:
        zone_assets = [a for a in assets_sorted if ASSETS[a]['zone'] == z]
        col += len(zone_assets)
        if col < n_asset:
            ax.axvline(col - 0.5, color='white', lw=0.8, alpha=0.4)

    ax.set_facecolor('#0d1117')


def _draw_technique_coverage(ax, result: SolverResult):
    """Horizontal bar chart — techniques ranked by fraction of assets covered."""
    ax.set_facecolor('#0d1117')
    ax.set_title('Technique Coverage\n(fraction of assets detected)',
                 color='white', fontsize=8, pad=4)

    # Sort by coverage descending
    tech_cov = sorted(result.technique_coverage.items(),
                      key=lambda x: x[1], reverse=True)
    names  = [t for t, _ in tech_cov]
    values = [v * 100 for _, v in tech_cov]

    # Color by server-type family
    family_colors = {
        'web':      '#e74c3c',
        'ssh':      '#e67e22',
        'database': '#9b59b6',
        'smb':      '#3498db',
        'scada':    '#c0392b',
        'ad':       '#1abc9c',
        'dns':      '#f39c12',
        'generic':  '#7f8c8d',
    }
    def tech_family(t: str) -> str:
        for stype, techs in STYPE_TECHNIQUES.items():
            if t in techs:
                return stype
        return 'generic'

    colors = [family_colors.get(tech_family(t), '#7f8c8d') for t in names]
    y = np.arange(len(names))

    bars = ax.barh(y, values, 0.7, color=colors, alpha=0.85,
                   edgecolor='#1a1a2e', linewidth=0.4)

    for i, v in enumerate(values):
        ax.text(v + 0.5, i, f'{v:.0f}%', va='center', fontsize=5.5,
                color='white')

    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=5.5, color='white')
    ax.set_xlabel('% Assets Covered', color='white', fontsize=7)
    ax.set_xlim(0, 115)
    ax.invert_yaxis()
    ax.tick_params(colors='white', labelsize=6)
    ax.spines['bottom'].set_color('#444'); ax.spines['left'].set_color('#444')
    ax.spines['top'].set_visible(False);  ax.spines['right'].set_visible(False)
    ax.xaxis.label.set_color('white')
    ax.set_facecolor('#0d1117')

    # Family legend
    legend_items = [
        mpatches.Patch(color=c, label=s)
        for s, c in family_colors.items()
    ]
    ax.legend(handles=legend_items, fontsize=4.5, facecolor='#1a1a2e',
              edgecolor='#444', labelcolor='white', loc='lower right',
              ncol=2, framealpha=0.9)


# =============================================================================
# MAIN FIGURE  —  3-row, 2-col grid + full-width panel 5
# =============================================================================

def generate_topology(output_path='./research_results/topology.png'):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # ── Run MaxSAT solver first ───────────────────────────────────────────────
    print("[MaxSAT] Running greedy solver ...")
    result = solve_maxsat_greedy(
        configs       = CONFIGS,
        assets        = ASSETS,
        techniques    = TECHNIQUES,
        conflicts     = CONFLICTS,
        zone_isolated = ZONE_ISOLATED,
        global_budget = GLOBAL_BUDGET,
        zone_budgets  = ZONE_BUDGETS,
    )
    print(f"[MaxSAT] Selected {result.num_configs} configs | "
          f"cost={result.total_cost:.1f}/{GLOBAL_BUDGET} | "
          f"value={result.total_value:.2f} | "
          f"utilisation={result.budget_utilisation*100:.0f}%")
    print(f"[MaxSAT] Configs: {[CONFIGS[i].name for i in result.selected_configs]}")

    # ── Figure layout ─────────────────────────────────────────────────────────
    fig = plt.figure(figsize=(26, 22), facecolor='#0d1117')
    fig.suptitle(
        'MaxSAT Honeypot Placement — Network Topology, Attack Paths & Solver Results',
        color='white', fontsize=14, fontweight='bold', y=0.99
    )

    # Top 4 panels: 2×2 grid (upper 55% of figure)
    # Bottom panel: full width (lower 40%)
    gs_top = fig.add_gridspec(2, 2,
                              left=0.03, right=0.97,
                              top=0.95,  bottom=0.44,
                              hspace=0.28, wspace=0.15)

    gs_bot = fig.add_gridspec(1, 1,
                              left=0.03, right=0.97,
                              top=0.40,  bottom=0.02)

    ax1 = fig.add_subplot(gs_top[0, 0])
    ax2 = fig.add_subplot(gs_top[0, 1])
    ax3 = fig.add_subplot(gs_top[1, 0])
    ax4 = fig.add_subplot(gs_top[1, 1])
    ax5 = fig.add_subplot(gs_bot[0, 0])

    draw_zone_graph(ax1)
    draw_attack_paths(ax2)
    draw_asset_roles(ax3)
    draw_honeypot_map(ax4)
    draw_maxsat_results(ax5, result)

    # Panel labels A–E
    for ax, lbl in zip([ax1, ax2, ax3, ax4, ax5], ['A','B','C','D','E']):
        ax.text(0.01, 0.99, lbl, transform=ax.transAxes,
                fontsize=13, fontweight='bold', color='#f1c40f',
                va='top', ha='left')

    plt.savefig(output_path, dpi=160, bbox_inches='tight',
                facecolor='#0d1117')
    plt.close()
    print(f"[SAVED] → {output_path}")
    return output_path


if __name__ == '__main__':
    generate_topology('./research_results/topology.png')
