
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