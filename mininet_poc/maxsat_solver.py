cat > ~/honeypot-maxsat/src/maxsat_solver.py << 'EOF'
from pysat.examples.rc2 import RC2
from pysat.formula import WCNF
import itertools

NETWORK_CONFIG = {
    'honeypots': ['web_trap','ssh_trap','db_trap','dns_trap','generic_trap'],
    'costs': {
        'web_trap':     250,
        'ssh_trap':     200,
        'db_trap':      325,
        'dns_trap':     175,
        'generic_trap': 125,
    },
    # Tighten budget to force real tradeoffs (can afford ~3 of 5)
    'budget': 600,
    'honeypot_zones': {
        'web_trap':     ['zone1', 'zone3'],
        'ssh_trap':     ['zone1', 'zone2', 'zone3'],
        'db_trap':      ['zone2', 'zone3'],
        'dns_trap':     ['zone1', 'zone2', 'zone3'],
        # FIX: remove zone4 — generic_trap cannot bridge air gap
        'generic_trap': ['zone1', 'zone2', 'zone3', 'zone5'],
    },
    'conflicts': [],
    'air_gaps': [
        ('zone4', 'zone1'), ('zone4', 'zone2'),
        ('zone4', 'zone3'), ('zone5', 'zone1'),
    ],
    'honeypot_detects': {
        'web_trap':     ['T1190', 'T1133', 'T1059'],
        'ssh_trap':     ['T1110', 'T1021', 'T1078'],
        'db_trap':      ['T1213', 'T1048', 'T1485'],
        'dns_trap':     ['T1572', 'T1095', 'T1046'],
        'generic_trap': ['T1046', 'T1082', 'T1110'],
    },
    # Attack technique weights — higher = more valuable to detect
    'technique_weights': {
        'T1190': 3.0, 'T1133': 2.0, 'T1059': 1.5,  # Initial access
        'T1110': 2.0, 'T1021': 3.5, 'T1078': 3.0,  # Lateral movement
        'T1213': 2.5, 'T1048': 4.0, 'T1485': 3.5,  # Exfil/impact
        'T1572': 3.0, 'T1095': 2.0, 'T1046': 1.5,  # C2/discovery
        'T1082': 1.0,                                 # Discovery
    },
    'paths': [
        {
            'id': 'web_to_db', 'prob': 0.30,
            'hops': [
                {'zone': 'zone1', 'attacks': ['T1190','T1059'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1021','T1078'], 'iv': 1.8},
                {'zone': 'zone2', 'attacks': ['T1213','T1048'], 'iv': 2.0},
            ]
        },
        {
            'id': 'cloud_pivot', 'prob': 0.25,
            'hops': [
                {'zone': 'zone3', 'attacks': ['T1190','T1133'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1021','T1078'], 'iv': 1.8},
            ]
        },
        {
            'id': 'brute_to_ad', 'prob': 0.20,
            'hops': [
                {'zone': 'zone1', 'attacks': ['T1110','T1078'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1021','T1078'], 'iv': 1.7},
                {'zone': 'zone5', 'attacks': ['T1110','T1078'], 'iv': 2.0},
            ]
        },
        {
            'id': 'ot_infiltration', 'prob': 0.15,
            'hops': [
                {'zone': 'zone1', 'attacks': ['T1190','T1059'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1021','T1046'], 'iv': 1.7},
            ]
        },
        {
            'id': 'ransomware', 'prob': 0.10,
            'hops': [
                {'zone': 'zone2', 'attacks': ['T1110','T1082'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1046','T1485'], 'iv': 1.8},
            ]
        },
    ],
    'tactic_families': {
        'initial_access':    ['T1190', 'T1133'],
        'execution':         ['T1059'],
        'credential_access': ['T1110', 'T1078', 'T1213'],
        'lateral_movement':  ['T1021'],
        'collection':        ['T1213'],
        'exfiltration':      ['T1048'],
        'impact':            ['T1485'],
        'discovery':         ['T1046', 'T1082'],
        'command_control':   ['T1572', 'T1095'],
    },
}

def _covers(k, hop, cfg):
    return (
            hop['zone'] in cfg['honeypot_zones'][k] and
            any(a in cfg['honeypot_detects'][k] for a in hop['attacks'])
    )

def _tech_weight(k, hop, cfg):
    """Sum of technique weights for honeypot k on this hop"""
    tw = cfg.get('technique_weights', {})
    return sum(
        tw.get(a, 1.0)
        for a in hop['attacks']
        if a in cfg['honeypot_detects'][k]
    )

def solve(config=None):
    cfg     = config or NETWORK_CONFIG
    wcnf    = WCNF()
    var_id  = [1]
    var_map = {}

    def new_var(name):
        v = var_id[0]
        var_id[0] += 1
        var_map[name] = v
        return v

    x     = {k: new_var(f'x_{k}') for k in cfg['honeypots']}
    costs = cfg['costs']
    hps   = cfg['honeypots']
    B     = cfg['budget']

    # ── HARD CLAUSES ──────────────────────────────────────────────

    # C4: conflict pairs
    for (ki, kl) in cfg['conflicts']:
        wcnf.append([-x[ki], -x[kl]])

    # C5: air gap — ban honeypots that span isolated zones
    banned = set()
    for (za, zb) in cfg['air_gaps']:
        for k in hps:
            if (za in cfg['honeypot_zones'][k] and
                    zb in cfg['honeypot_zones'][k]):
                wcnf.append([-x[k]])
                banned.add(k)

    # C2: budget — minimal infeasible subsets only
    infeasible_count = 0
    blocked_sets = []
    for r in range(1, len(hps) + 1):
        for combo in itertools.combinations(hps, r):
            if sum(costs[k] for k in combo) > B:
                already = any(
                    set(prev).issubset(set(combo))
                    for prev in blocked_sets
                )
                if not already:
                    blocked_sets.append(combo)
                    wcnf.append([-x[k] for k in combo])
                    infeasible_count += 1

    total_all = sum(costs[k] for k in hps)
    print(f"  Budget          : {B}")
    print(f"  All-5 cost      : {total_all} "
          f"({'fits' if total_all <= B else 'over — tradeoffs required'})")
    print(f"  Air-gap banned  : {list(banned) if banned else 'none'}")
    print(f"  Budget clauses  : {infeasible_count}")

    # ── SOFT CLAUSES (4-level weighted priority) ──────────────────
    # Weights scaled so L4 >> L3 >> L2 >> L1
    W = {'L4': 100000, 'L3': 10000, 'L2': 1000, 'L1': 100}

    # Level 4 — early interception (non-final hops, prevention value)
    for path in cfg['paths']:
        rho  = path['prob']
        hops = path['hops']
        for hop in hops[:-1]:   # non-final hops only
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tech_weight(k, hop, cfg)
                    w  = max(1, int(W['L4'] * rho * hop['iv'] * tw))
                    wcnf.append([x[k]], weight=w)

    # Level 3 — forward path coverage per hop
    for path in cfg['paths']:
        rho = path['prob']
        for hop in path['hops']:
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tech_weight(k, hop, cfg)
                    w  = max(1, int(W['L3'] * rho * hop['iv'] * tw))
                    wcnf.append([x[k]], weight=w)

    # Level 3 — backward coverage (forensics, 0.7 discount)
    for path in cfg['paths']:
        rho = path['prob']
        for hop in reversed(path['hops']):
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tech_weight(k, hop, cfg)
                    w  = max(1, int(W['L3'] * rho * hop['iv'] * tw * 0.7))
                    wcnf.append([x[k]], weight=w)

    # Level 2 — technique coverage weighted by stealth/importance
    all_attacks = set(
        a for path in cfg['paths']
        for hop  in path['hops']
        for a    in hop['attacks']
    )
    tw_map = cfg.get('technique_weights', {})
    for attack in all_attacks:
        for k in hps:
            if attack in cfg['honeypot_detects'][k]:
                w = max(1, int(W['L2'] * tw_map.get(attack, 1.0)))
                wcnf.append([x[k]], weight=w)

    # Level 2 — tactic family breadth bonus (1.2x)
    for family, techniques in cfg['tactic_families'].items():
        for k in hps:
            if any(t in cfg['honeypot_detects'][k] for t in techniques):
                fam_w = sum(tw_map.get(t, 1.0) for t in techniques
                            if t in cfg['honeypot_detects'][k])
                wcnf.append([x[k]], weight=int(W['L2'] * 1.2 * fam_w))

    # Level 1 — base deployment reward
    for k in hps:
        wcnf.append([x[k]], weight=W['L1'])

    # ── SOLVE ─────────────────────────────────────────────────────
    print(f"\n=== Running RC2 MAXSAT Solver ===")
    print(f"  Clauses — Hard: {len(wcnf.hard)} | Soft: {len(wcnf.soft)}")

    with RC2(wcnf) as solver:
        model = solver.compute()
        cost  = solver.cost

    deployed   = [k for k in hps if model[x[k]-1] > 0]
    total_cost = sum(costs[k] for k in deployed)

    assert total_cost <= B, f"Budget violated: {total_cost} > {B}"

    print(f"  Deployed  : {deployed}")
    print(f"  Cost      : {total_cost} / {B}")
    print(f"  Remaining : {B - total_cost}")
    print(f"  UNSAT wt  : {cost}")
    return deployed, total_cost, var_map

if __name__ == '__main__':
    solve()
EOF