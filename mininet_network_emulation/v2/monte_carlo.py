cat > ~/honeypot-maxsat/src/monte_carlo.py << 'EOF'
import random

HONEYPOT_ZONES = {
    'web_trap':     ['zone1', 'zone3'],
    'ssh_trap':     ['zone1', 'zone2', 'zone3'],
    'db_trap':      ['zone2', 'zone3'],
    'dns_trap':     ['zone1', 'zone2', 'zone3'],
    'generic_trap': ['zone2', 'zone3'],
}

PATHS = {
    'web_to_db':   {'hops': ['zone1','zone2','zone2'], 'prob': 0.35},
    'cloud_to_db': {'hops': ['zone3','zone2','zone2'], 'prob': 0.25},
    'data_theft':  {'hops': ['zone3','zone2','zone2'], 'prob': 0.20},
    'brute_to_ad': {'hops': ['zone1','zone2','zone5'], 'prob': 0.15},
    'ransomware':  {'hops': ['zone2','zone2'],          'prob': 0.05},
}

def simulate(deployed_honeypots, n_trials=50000, seed=42):
    random.seed(seed)
    early_catches, misses, hops_list = 0, 0, []

    for _ in range(n_trials):
        path_id = random.choices(
            list(PATHS.keys()),
            weights=[PATHS[p]['prob'] for p in PATHS]
        )[0]
        hops      = PATHS[path_id]['hops']
        caught_at = None

        for h_idx, zone in enumerate(hops):
            for hp in deployed_honeypots:
                if zone in HONEYPOT_ZONES.get(hp, []):
                    caught_at = h_idx
                    break
            if caught_at is not None:
                break

        if caught_at is None:
            misses += 1
        else:
            hops_list.append(caught_at)
            if caught_at < len(hops) - 1:
                early_catches += 1

    n = n_trials
    return {
        'early_pct':  early_catches / n * 100,
        'miss_rate':  misses / n * 100,
        'catch_rate': (n - misses) / n * 100,
        'mean_hops':  sum(hops_list) / max(len(hops_list), 1),
    }
EOF