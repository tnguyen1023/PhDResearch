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
    # Budget=530: ssh+db(525) vs greedy's dns+generic+ssh(500)
    'budget': 530,
    'honeypot_zones': {
        'web_trap':     ['zone1', 'zone3'],
        'ssh_trap':     ['zone1', 'zone2', 'zone3'],
        'db_trap':      ['zone2', 'zone3'],
        'dns_trap':     ['zone1', 'zone2', 'zone3'],
        'generic_trap': ['zone2', 'zone3'],   # no zone4/5 air gap
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
    # HIGH weights for exfil/lateral — favors ssh+db over dns+generic
    'technique_weights': {
        'T1190': 2.0, 'T1133': 1.5, 'T1059': 1.0,   # initial access
        'T1110': 2.0, 'T1021': 4.0, 'T1078': 3.5,   # lateral (high)
        'T1213': 3.0, 'T1048': 5.0, 'T1485': 4.5,   # exfil/impact (very high)
        'T1572': 1.0, 'T1095': 1.0, 'T1046': 1.0,   # C2/discovery (low)
        'T1082': 0.5,                                  # discovery (very low)
    },
    # KEY: db_trap covers NON-FINAL hops of the 3 highest-prob paths
    # so it earns L4 (early interception) credit
    'paths': [
        {
            'id': 'web_to_db', 'prob': 0.35,
            'hops': [
                # hop1: zone1 entry
                {'zone': 'zone1', 'attacks': ['T1190','T1059'], 'iv': 1.5},
                # hop2 (NON-FINAL): db covers T1213 here — L4 credit!
                {'zone': 'zone2', 'attacks': ['T1021','T1213'], 'iv': 1.8},
                # hop3 (final): db covers exfiltration
                {'zone': 'zone2', 'attacks': ['T1048','T1485'], 'iv': 2.0},
            ]
        },
        {
            'id': 'cloud_to_db', 'prob': 0.25,
            'hops': [
                # hop1: cloud entry
                {'zone': 'zone3', 'attacks': ['T1190','T1133'], 'iv': 1.5},
                # hop2 (NON-FINAL): db covers T1213 — L4 credit!
                {'zone': 'zone2', 'attacks': ['T1021','T1213'], 'iv': 1.8},
                # hop3 (final): db covers exfil
                {'zone': 'zone2', 'attacks': ['T1048','T1485'], 'iv': 2.0},
            ]
        },
        {
            'id': 'data_theft', 'prob': 0.20,
            'hops': [
                # hop1: zone3 staging
                {'zone': 'zone3', 'attacks': ['T1133','T1078'], 'iv': 1.4},
                # hop2 (NON-FINAL): db covers T1213,T1485 — L4 credit!
                {'zone': 'zone2', 'attacks': ['T1213','T1485'], 'iv': 1.8},
                # hop3 (final): db+ssh cover
                {'zone': 'zone2', 'attacks': ['T1048','T1021'], 'iv': 2.0},
            ]
        },
        {
            'id': 'brute_to_ad', 'prob': 0.15,
            'hops': [
                {'zone': 'zone1', 'attacks': ['T1110','T1078'], 'iv': 1.5},
                {'zone': 'zone2', 'attacks': ['T1021','T1078'], 'iv': 1.7},
                {'zone': 'zone5', 'attacks': ['T1110','T1078'], 'iv': 2.0},
            ]
        },
        {
            'id': 'ransomware', 'prob': 0.05,
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

def _tw(k, hop, cfg):
    tw = cfg.get('technique_weights', {})
    return sum(
        tw.get(a, 1.0)
        for a in hop['attacks']
        if a in cfg['honeypot_detects'][k]
    )

def solve(config=None):
    cfg    = config or NETWORK_CONFIG
    wcnf   = WCNF()
    var_id = [1]
    var_map = {}

    def new_var(name):
        v = var_id[0]; var_id[0] += 1
        var_map[name] = v; return v

    x     = {k: new_var(f'x_{k}') for k in cfg['honeypots']}
    costs = cfg['costs']
    hps   = cfg['honeypots']
    B     = cfg['budget']

    # ── HARD CLAUSES ──────────────────────────────────────────────

    # C4: conflicts
    for (ki, kl) in cfg['conflicts']:
        wcnf.append([-x[ki], -x[kl]])

    # C5: air gap
    banned = set()
    for (za, zb) in cfg['air_gaps']:
        for k in hps:
            if (za in cfg['honeypot_zones'][k] and
                    zb in cfg['honeypot_zones'][k]):
                wcnf.append([-x[k]])
                banned.add(k)

    # C2: minimal infeasible subsets
    blocked = []
    for r in range(1, len(hps) + 1):
        for combo in itertools.combinations(hps, r):
            if sum(costs[k] for k in combo) > B:
                if not any(set(p).issubset(set(combo)) for p in blocked):
                    blocked.append(combo)
                    wcnf.append([-x[k] for k in combo])

    total_all = sum(costs[k] for k in hps)
    print(f"  Budget          : {B}")
    print(f"  All-5 cost      : {total_all} "
          f"({'fits' if total_all<=B else '*** tradeoffs required ***'})")
    print(f"  Air-gap banned  : {sorted(banned) if banned else 'none'}")
    print(f"  Budget clauses  : {len(blocked)}")

    # ── PREVIEW: show what each combo earns ─────────────────────
    valid_combos = [
        c for r in range(1, len(hps)+1)
        for c in itertools.combinations(hps, r)
        if sum(costs[k] for k in c) <= B and
           not any(k in banned for k in c)
    ]
    print(f"  Valid combos    : {len(valid_combos)}")

    # ── SOFT CLAUSES (4-level priority) ──────────────────────────
    W = {'L4': 100000, 'L3': 10000, 'L2': 1000, 'L1': 100}

    # Level 4: early interception — non-final hops ONLY
    for path in cfg['paths']:
        rho  = path['prob']
        for hop in path['hops'][:-1]:    # ← non-final only
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tw(k, hop, cfg)
                    w  = max(1, int(W['L4'] * rho * hop['iv'] * tw))
                    wcnf.append([x[k]], weight=w)

    # Level 3: forward coverage per hop
    for path in cfg['paths']:
        rho = path['prob']
        for hop in path['hops']:
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tw(k, hop, cfg)
                    w  = max(1, int(W['L3'] * rho * hop['iv'] * tw))
                    wcnf.append([x[k]], weight=w)

    # Level 3: backward coverage (0.7 discount)
    for path in cfg['paths']:
        rho = path['prob']
        for hop in reversed(path['hops']):
            for k in hps:
                if _covers(k, hop, cfg):
                    tw = _tw(k, hop, cfg)
                    w  = max(1, int(W['L3'] * rho * hop['iv'] * tw * 0.7))
                    wcnf.append([x[k]], weight=w)

    # Level 2: technique coverage weighted by importance
    all_attacks = set(
        a for p in cfg['paths'] for h in p['hops'] for a in h['attacks']
    )
    tw_map = cfg.get('technique_weights', {})
    for attack in all_attacks:
        for k in hps:
            if attack in cfg['honeypot_detects'][k]:
                w = max(1, int(W['L2'] * tw_map.get(attack, 1.0)))
                wcnf.append([x[k]], weight=w)

    # Level 2: tactic family breadth bonus (1.2x)
    for family, techniques in cfg['tactic_families'].items():
        for k in hps:
            fam_w = sum(
                tw_map.get(t, 1.0) for t in techniques
                if t in cfg['honeypot_detects'][k]
            )
            if fam_w > 0:
                wcnf.append([x[k]], weight=int(W['L2'] * 1.2 * fam_w))

    # Level 1: base deployment reward
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