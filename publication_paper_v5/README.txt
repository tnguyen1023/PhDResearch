
cd /Users/tnguye514@cable.comcast.com/t_maxsat_solver_poc/poc/MaxSat_Solver_POC

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd zstp_emu_11_revised
time python3 run_all.py

=====

Every number in the paper now comes from a results file written by one command, python3 reproduce.py. The core results come from run_all.py; the validation, the extra experiments and the tests come from separate scripts that reproduce.py runs alongside it. I ran it once from an empty output folder: all steps passed in 41.8 minutes, and the second run of the main pipeline was identical apart from timing.

What run_all.py produces:

r* and its certificate
the four passes and the CP-SAT cross-checks
the baselines and their repair (Tables 4–5)
the emulation (Table 7)
Algorithm 1
sensitivity, zero-burn and the small-instance enumeration

reproduce.py runs it first, then:

Tables, statistics and figures (Tables 7–8, Figures 1–2), computed from results.json.
Validation of the emulation and the contributions (Table 6 rows).
The extra experiments (Tables 9–10).
The three tests, which now write their results to out/tests.json.
The reproducibility check, which reruns run_all.py in a scratch folder and records the comparison in out/repro.json.

=====

What "L2" means. The paper uses levels of validation fidelity:

L1: score the schedule with the model's equations alone.
L2: run the schedule as real network processes and have a scripted attacker interact with them. This is what the paper does.
L3: real virtual machines in separated network zones, attacked with real tools such as nmap and Metasploit. The paper names this as future work.

How the L2 emulation works (emulation_l2.py):

Honeypots. Every deployment in a schedule becomes a small TCP server on the local machine. When contacted, it returns a banner showing its trap type, zone and identity, and it logs the contact.
Attacker. One attacker walks through the time slots in each episode. In each slot it:
probes each zone with probability ρ_θ;
attacks along each path with probability min(1, ρ_π·ω_θ,π), contacting honeypots that detect each hop's technique;
recognizes a honeypot as burned only from what it has itself observed in earlier slots.
Scoring from logs. The score is computed only from the honeypots' connection logs, never from the model's evaluator. That separation is what makes it a check.
STIX 2.1 bundles. The observed contacts are exported in the standard threat-intelligence format, the same kind of input Algorithm 1 consumes.

Two modes, two purposes:

Deterministic mode (the attacker probes and attacks everything) checks that the model's equations mean what they say when run as real processes. The log-based score equals the model score in 96 of 96 cases.
Stochastic mode (100 random attacker episodes per profile) shows how schedules perform against an attacker who sees only part of the network. With every schedule facing the same episodes, the max–min schedule is significantly better than 20 of 22 others, all feasible baselines included. It is not significantly better than Greedy-Diverse, which breaks hard rules, or the Q-med schedule.

How the emulation itself was validated: an independent simulator written from the stated attacker model reproduces all 9,600 recorded episodes exactly, the attacker's random choices match the stated probabilities, and the STIX output is structurally valid.

What it doesn't show, as the paper states:

The attacker is a scripted probability model on local sockets, not real attacker behaviour.
Rule violations have no attacker-visible effect, which favours the baselines.
Real-world security is not claimed; that is what L3 would test.

In short, contribution 4 is a careful consistency and robustness check of the model through running processes, not a field test.

=====