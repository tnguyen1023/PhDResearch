
cd /Users/tnguye514@cable.comcast.com/t_maxsat_solver_poc/poc/MaxSat_Solver_POC

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd zstp_emu_11_revised
time python3 run_all.py