import sys, os, random
sys.path.insert(0, os.path.dirname(__file__))
from maxsat_solver import solve, NETWORK_CONFIG
from monte_carlo   import simulate

def compute_q_score(deployed, cfg):
    hps   = cfg['honeypots']
    paths = cfg['paths']

    # DetEff
    total_det = sum(len(cfg['honeypot_detects'][k]) for k in hps)
    achiev    = sum(len(cfg['honeypot_detects'][k]) for k in deployed)
    det_eff   = achiev / total_det * 100 if total_det else 0

    # TechCov
    all_tech     = set(a for p in paths for h in p['hops'] for a in h['attacks'])
    cov_tech     = set(a for k in deployed for a in cfg['honeypot_detects'][k]
                       if a in all_tech)
    tech_cov     = len(cov_tech) / len(all_tech) * 100 if all_tech else 0

    # FamCov
    total_fam    = len(cfg['tactic_families'])
    cov_fam      = sum(1 for f, ts in cfg['tactic_families'].items()
                       if any(t in cov_tech for t in ts))
    fam_cov      = cov_fam / total_fam * 100 if total_fam else 0

    # FwdPath / BwdPath
    total_pairs  = sum(len(p['hops']) for p in paths)
    covered      = sum(
        1 for p in paths for hop in p['hops']
        if any(hop['zone'] in cfg['honeypot_zones'][k] and
               any(a in cfg['honeypot_detects'][k] for a in hop['attacks'])
               for k in deployed)
    )
    fwd_path     = covered / total_pairs * 100 if total_pairs else 0
    bwd_path     = fwd_path  # same coverage, different direction metric

    Q = (0.35*det_eff + 0.25*tech_cov + 0.15*fam_cov +
         0.15*fwd_path + 0.10*bwd_path)
    return Q, {'DetEff':det_eff,'TechCov':tech_cov,'FamCov':fam_cov,
               'FwdPath':fwd_path,'BwdPath':bwd_path}

def greedy_baseline(cfg):
    """Budget-limited greedy: best coverage-per-dollar"""
    remaining = cfg['budget']
    deployed  = []
    available = sorted(
        cfg['honeypots'],
        key=lambda k: len(cfg['honeypot_detects'][k]) / cfg['costs'][k],
        reverse=True
    )
    for k in available:
        if cfg['costs'][k] <= remaining:
            deployed.append(k)
            remaining -= cfg['costs'][k]
    return deployed

def random_baseline(cfg, seed=42):
    """Budget-limited random"""
    random.seed(seed)
    available = cfg['honeypots'][:]
    random.shuffle(available)
    remaining = cfg['budget']
    deployed  = []
    for k in available:
        if cfg['costs'][k] <= remaining:
            deployed.append(k)
            remaining -= cfg['costs'][k]
    return deployed

def main():
    cfg = NETWORK_CONFIG
    print("=" * 65)
    print("  Kill-Chain Honeypot Placement via MAXSAT")
    print(f"  Budget: {cfg['budget']} | "
          f"All-5 cost: {sum(cfg['costs'].values())}")
    print("=" * 65)

    # Step 1: MAXSAT
    print("\n[1] MAXSAT Solver (RC2)...")
    deployed, cost, _ = solve(cfg)

    # Step 2: Monte Carlo
    print("\n[2] Monte Carlo (50,000 trials)...")
    mc = simulate(deployed, n_trials=50000)
    print(f"  Early catch : {mc['early_pct']:.1f}%")
    print(f"  Catch rate  : {mc['catch_rate']:.1f}%")
    print(f"  Miss rate   : {mc['miss_rate']:.1f}%")
    print(f"  Mean hops   : {mc['mean_hops']:.2f}")

    # Step 3: Q score
    print("\n[3] Quality Score Q (paper Eq.21)...")
    Q, comps = compute_q_score(deployed, cfg)
    W = {'DetEff':0.35,'TechCov':0.25,'FamCov':0.15,
         'FwdPath':0.15,'BwdPath':0.10}
    print(f"\n  {'Metric':10} {'Value':>8}  {'Weight':>7}  {'Contrib':>8}")
    print(f"  {'-'*40}")
    for m, v in comps.items():
        print(f"  {m:10} {v:>7.1f}%  {W[m]:>7.2f}  {v*W[m]:>8.2f}")
    print(f"  {'-'*40}")
    print(f"  {'Q Score':10} {Q:>8.2f}")

    # Step 4: Baselines (budget-limited)
    print("\n[4] Budget-Limited Baseline Comparison...")
    g_hps = greedy_baseline(cfg)
    r_hps = random_baseline(cfg)
    g_Q, _ = compute_q_score(g_hps, cfg)
    r_Q, _ = compute_q_score(r_hps, cfg)
    g_mc   = simulate(g_hps)
    r_mc   = simulate(r_hps)
    g_cost = sum(cfg['costs'][k] for k in g_hps)
    r_cost = sum(cfg['costs'][k] for k in r_hps)

    print(f"\n  {'Method':12} {'Cost':>6}  {'Deployed':45} "
          f"{'Q':>6} {'Early%':>7} {'Miss%':>6}")
    print(f"  {'-'*88}")
    print(f"  {'MAXSAT':12} {cost:>6}  {str(deployed):45} "
          f"{Q:>6.2f} {mc['early_pct']:>7.1f} {mc['miss_rate']:>6.1f}")
    print(f"  {'Greedy':12} {g_cost:>6}  {str(g_hps):45} "
          f"{g_Q:>6.2f} {g_mc['early_pct']:>7.1f} {g_mc['miss_rate']:>6.1f}")
    print(f"  {'Random':12} {r_cost:>6}  {str(r_hps):45} "
          f"{r_Q:>6.2f} {r_mc['early_pct']:>7.1f} {r_mc['miss_rate']:>6.1f}")

    gain = (Q - g_Q) / g_Q * 100 if g_Q else 0
    print(f"\n  MAXSAT vs Greedy: {gain:+.1f}%")
    print("\n✓ Complete")

if __name__ == '__main__':
    main()
                                          