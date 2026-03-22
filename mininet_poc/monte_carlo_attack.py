# monte_carlo.py
import random
import json

PATHS = {
    'web_to_db':    {'hops': ['z1','z2_internal','z2_db'], 'prob': 0.30},
    'cloud_pivot':  {'hops': ['z3','z2_internal'],          'prob': 0.25},
    'brute_to_ad':  {'hops': ['z1','z2_internal','z5'],     'prob': 0.20},
    'ot_infiltrate':{'hops': ['z1','z2_internal','z4'],     'prob': 0.15},
    'ransomware':   {'hops': ['z2_email','z2_spread'],      'prob': 0.10},
}

def simulate(deployed_honeypots, honeypot_coverage,
             n_trials=50_000, seed=42):
    random.seed(seed)
    results = {
        'early_pct':         0,
        'mean_hops_detected': [],
        'miss_rate':         0,
        'path_counts':       {k: 0 for k in PATHS}
    }

    for _ in range(n_trials):
        # Choose path by probability
        path_id = random.choices(
            list(PATHS.keys()),
            weights=[PATHS[p]['prob'] for p in PATHS]
        )[0]
        path = PATHS[path_id]
        hops = path['hops']
        results['path_counts'][path_id] += 1

        caught_at = None
        for h, hop in enumerate(hops):
            # Check if any deployed honeypot covers this hop
            for hp in deployed_honeypots:
                if hop in honeypot_coverage.get(hp, []):
                    caught_at = h
                    break
            if caught_at is not None:
                break

        if caught_at is None:
            results['miss_rate'] += 1
        elif caught_at < len(hops) - 1:
            results['early_pct'] += 1
            results['mean_hops_detected'].append(caught_at)
        else:
            results['mean_hops_detected'].append(caught_at)

    n = n_trials
    return {
        'early_pct':          results['early_pct'] / n * 100,
        'miss_rate':          results['miss_rate'] / n * 100,
        'mean_hops_detected': (sum(results['mean_hops_detected']) /
                               max(len(results['mean_hops_detected']), 1)),
        'path_distribution':  results['path_counts'],
    }