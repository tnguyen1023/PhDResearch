"""
config.py
Zone-Slot-Time-Persona V6 MaxSAT RC2 Configuration
====================================================
Complete instance tuple I = (K, T, A, Z, P, G, C, I2, ⋄, w, cost, B, B2,
    dm, hd, σ, ρ, iv, GK, τd, τdp, τd0, Δ, Δp, q, ρmax, H, γ, βmax, κ,
    τ_GK, h_min, κ_min, ρ_decay, Δ_N)

Every symbol from equation (1) Section A is defined here and nowhere else.
Import this module; do not hard-code parameters in the solver.

Usage:
    from config import CFG
    K   = CFG["K"]
    qp  = CFG["q"]        # persona priors (updated by Algorithm 1)
    GK  = CFG["GK"]       # role-compatibility admits dict
    ...
"""

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION A ── STRUCTURAL SETS
# ─────────────────────────────────────────────────────────────────────────────

# K  ── honeypot types  (|K| = 8, XLarge configuration)
K = [
    "ssh_trap",
    "db_trap",
    "smb_trap",
    "scada_trap",
    "ad_trap",
    "dns_trap",
    "web_trap",
    "generic_trap",
]

# T  ── ATT&CK techniques covered by this deployment
T = [
    "T1021",   # Remote Services – Lateral Movement
    "T1048",   # Exfiltration over Alt Protocol
    "T1078",   # Valid Accounts
    "T1083",   # File and Directory Discovery
    "T1046",   # Network Service Scanning
    "T1110",   # Brute Force
    "T1566",   # Phishing – Initial Access
    "T1190",   # Exploit Public-Facing Application
    "T1041",   # Exfiltration over C2 Channel
    "T1059",   # Command and Scripting Interpreter
    "T1053",   # Scheduled Task/Job
    "T1055",   # Process Injection
    "T1133",   # External Remote Services
    "T1203",   # Exploitation for Client Execution
    "T1547",   # Boot/Logon Autostart Execution
    "T1572",   # Protocol Tunneling
    "T1213",   # Data from Information Repositories
    "T1068",   # Exploitation for Privilege Escalation
]

# Z  ── network zones
Z = [
    "DMZ",       # perimeter / internet-facing
    "Internal",  # internal LAN
    "Cloud",     # cloud workloads
    "OT",        # OT/SCADA (air-gapped from DMZ, Cloud, Mgmt)
    "Mgmt",      # management / jump-host segment
]

# P  ── persona catalogue  (|P| = 4)
P = [
    "HR_workstation",
    "DevOps_server",
    "Finance_DB",
    "Generic_Linux",
]

# A  ── asset count per zone (large-network XLarge configuration)
#        Total |A| = 500 ; clause-DB scales O(|K|·|A|·|T|·H·|P|)
A_per_zone = {
    "DMZ":      80,
    "Internal": 200,
    "Cloud":    120,
    "OT":       50,
    "Mgmt":     50,
}
A_total = sum(A_per_zone.values())   # 500


# ─────────────────────────────────────────────────────────────────────────────
#  G  ── ATTACK PATHS  π ∈ G
#  Each path: ordered zone sequence, path probability ρπ, intercept values ivπ,h
# ─────────────────────────────────────────────────────────────────────────────

G = [
    {
        "id":    "pi1",
        "name":  "web-to-db",
        "zones": ["DMZ", "Internal", "Internal"],   # hop 0,1,2
        "rho":   0.35,                               # ρπ – path probability
        "iv":    [1.8, 1.4, 1.0],                   # ivπ,h per hop
        "techniques": ["T1566", "T1078", "T1048"],   # ATT&CK per hop (informational)
    },
    {
        "id":    "pi2",
        "name":  "cloud-ad-pivot",
        "zones": ["Cloud", "Internal", "Mgmt"],
        "rho":   0.25,
        "iv":    [1.6, 1.3, 1.0],
        "techniques": ["T1190", "T1021", "T1110"],
    },
    {
        "id":    "pi3",
        "name":  "ot-infiltration",
        "zones": ["DMZ", "OT"],
        "rho":   0.15,
        "iv":    [1.5, 1.2],
        "techniques": ["T1566", "T1059"],
    },
    {
        "id":    "pi4",
        "name":  "mgmt-pivot",
        "zones": ["DMZ", "Mgmt", "Internal"],
        "rho":   0.20,
        "iv":    [1.7, 1.3, 1.0],
        "techniques": ["T1133", "T1078", "T1021"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  C  ── PAIRWISE TYPE CONFLICT SET  C ⊆ K × K  (constraint C4)
#  Pairs that share monitoring infrastructure or produce redundant signals.
# ─────────────────────────────────────────────────────────────────────────────

C_conflicts = [
    ("generic_trap", "dns_trap"),    # both capture T1046 – saturates pipeline
    ("smb_trap",     "generic_trap"),# overlapping SMB/generic coverage
]


# ─────────────────────────────────────────────────────────────────────────────
#  I2  ── AIR-GAPPED ZONE PAIRS  I2 ⊆ Z × Z  (constraint C5)
#  Physical isolation: no routed path exists between these zone pairs.
# ─────────────────────────────────────────────────────────────────────────────

I2 = [
    ("OT", "DMZ"),
    ("OT", "Cloud"),
    ("OT", "Mgmt"),
]


# ─────────────────────────────────────────────────────────────────────────────
#  ⋄  ── ZONE AFFINITY  (constraint C5: xi,z,t,p = 0 unless z ∈ ZKi)
#  Maps each honeypot type to the zones where it can legally be deployed.
# ─────────────────────────────────────────────────────────────────────────────

diamond_affinity = {          # ⋄ — zone affinity per type
    "ssh_trap":     ["DMZ", "Internal", "Cloud", "Mgmt"],
    "db_trap":      ["Internal", "Cloud", "Mgmt"],
    "smb_trap":     ["Internal", "Mgmt"],
    "scada_trap":   ["OT"],                               # OT-only; C5 air-gap enforced separately
    "ad_trap":      ["Internal", "Mgmt"],
    "dns_trap":     ["DMZ", "Internal", "Cloud"],
    "web_trap":     ["DMZ", "Cloud"],
    "generic_trap": ["DMZ", "Internal", "Cloud", "Mgmt"],
}


# ─────────────────────────────────────────────────────────────────────────────
#  w  ── BASE TECHNIQUE WEIGHTS  wj ∈ ℝ+
#  Raw detection value before topology and stealth adjustments (eqs 2–3).
# ─────────────────────────────────────────────────────────────────────────────

w_technique = {
    "T1021": 0.80,
    "T1048": 1.40,
    "T1078": 1.00,
    "T1083": 0.60,
    "T1046": 0.70,
    "T1110": 0.90,
    "T1566": 1.20,
    "T1190": 1.10,
    "T1041": 1.30,
    "T1059": 0.75,
    "T1053": 0.65,
    "T1055": 0.85,
    "T1133": 0.95,
    "T1203": 0.80,
    "T1547": 0.70,
    "T1572": 1.35,
    "T1213": 1.00,
    "T1068": 0.90,
}


# ─────────────────────────────────────────────────────────────────────────────
#  σ  ── STEALTH SCORES  σj ∈ [0,1]
#  Higher σ → harder to catch by other means → higher W after eq 3.
# ─────────────────────────────────────────────────────────────────────────────

sigma = {
    "T1021": 0.40,
    "T1048": 0.90,   # exfil over alt protocol – blends into HTTPS
    "T1078": 0.70,
    "T1083": 0.30,
    "T1046": 0.50,
    "T1110": 0.60,
    "T1566": 0.80,
    "T1190": 0.70,
    "T1041": 0.85,
    "T1059": 0.40,
    "T1053": 0.50,
    "T1055": 0.60,
    "T1133": 0.75,
    "T1203": 0.55,
    "T1547": 0.50,
    "T1572": 0.90,   # protocol tunneling – very stealthy
    "T1213": 0.60,
    "T1068": 0.70,
}


# ─────────────────────────────────────────────────────────────────────────────
#  cost  ── DEPLOYMENT COSTS  costi,z ∈ ℝ+  (per slot, per zone)
#  Used in budget constraints C2 and C3.
# ─────────────────────────────────────────────────────────────────────────────

cost_per_type = {         # base cost units / slot
    "ssh_trap":     0.80,
    "db_trap":      1.20,
    "smb_trap":     0.90,
    "scada_trap":   2.00,  # high – specialist OT sensor
    "ad_trap":      1.50,
    "dns_trap":     0.70,
    "web_trap":     1.00,
    "generic_trap": 0.50,
}

# Zone multiplier applied to base cost (captures zone-specific infra overhead)
cost_zone_multiplier = {
    "DMZ":      1.0,
    "Internal": 1.0,
    "Cloud":    0.9,   # slightly cheaper (cloud elasticity)
    "OT":       1.5,   # specialist OT deployment overhead
    "Mgmt":     1.1,
}


# ─────────────────────────────────────────────────────────────────────────────
#  B, B2  ── BUDGET PARAMETERS  (constraints C2, C3)
# ─────────────────────────────────────────────────────────────────────────────

B_global = 62_500.0          # B  ── global budget per slot

B_zone = {                   # B2 ── per-zone budget per slot
    "DMZ":      15_000.0,
    "Internal": 20_000.0,
    "Cloud":    15_000.0,
    "OT":        8_000.0,
    "Mgmt":      4_500.0,
}


# ─────────────────────────────────────────────────────────────────────────────
#  dm, hd  ── ASSET ROLE MULTIPLIER AND HOP DISTANCE
#  dm,a ∈ ℝ+ ; hd,a ∈ ℤ+
#  Used in eq 2: ẅj,a = wj,a × dm,a / hd,a
#  Provided as zone-level distributions; individual assets sampled at runtime.
# ─────────────────────────────────────────────────────────────────────────────

dm_range = (0.80, 2.50)   # uniform sampling range for dm,a

hd_by_zone = {            # typical hop distance from network entry per zone
    "DMZ":      1,
    "Internal": 2,
    "Cloud":    2,
    "OT":       3,
    "Mgmt":     2,
}


# ─────────────────────────────────────────────────────────────────────────────
#  TACTIC FAMILIES  ── used for L2-fam 1.2× bonus (eq 10)
#  Maps family name → list of technique IDs in that family.
# ─────────────────────────────────────────────────────────────────────────────

tactic_families = {
    "LateralMovement": ["T1021", "T1078"],
    "Exfiltration":    ["T1048", "T1041"],
    "Discovery":       ["T1083", "T1046"],
    "CredentialAccess":["T1110"],
    "InitialAccess":   ["T1566", "T1190", "T1133", "T1203"],
    "Execution":       ["T1059", "T1053", "T1547"],
    "DefenseEvasion":  ["T1055", "T1068"],
    "CmdAndControl":   ["T1572", "T1213"],
}


# ─────────────────────────────────────────────────────────────────────────────
#  TRAP → TECHNIQUES  ── which techniques each trap type can detect
# ─────────────────────────────────────────────────────────────────────────────

trap_techniques = {
    "ssh_trap":     ["T1021", "T1078", "T1059"],
    "db_trap":      ["T1048", "T1213", "T1083"],
    "smb_trap":     ["T1021", "T1046", "T1055"],
    "scada_trap":   ["T1059", "T1053", "T1203"],
    "ad_trap":      ["T1110", "T1078", "T1547"],
    "dns_trap":     ["T1572", "T1041", "T1046"],
    "web_trap":     ["T1190", "T1566", "T1133"],
    "generic_trap": ["T1046", "T1068", "T1213"],
}


# ─────────────────────────────────────────────────────────────────────────────
#  H  ── PLANNING HORIZON  (number of deployment slots)
#  T̄ = {1, …, H}  is the slot index set.
#  Chosen for RC2 tractability with full C1–C15 encoding:
#    primary vars = |K|·|Z|·H·|P| = 8·5·4·4 = 640  (XLarge)
# ─────────────────────────────────────────────────────────────────────────────

H = 4   # planning horizon (4 months in the running example)


# ─────────────────────────────────────────────────────────────────────────────
#  GK  ── ROLE-COMPATIBILITY (C5b, eq 14)
#  GKi,p = 1  iff  M(servertype(trap), persona) ≥ τ_GK
#  Stored as dict: (trap, persona) → compatibility score ∈ [0,1]
#  A pair is ADMITTED when its score ≥ τ_GK (defined below).
# ─────────────────────────────────────────────────────────────────────────────

GK_scores = {
    # ssh_trap (Linux/Windows endpoint service)
    ("ssh_trap",     "HR_workstation"):  0.85,
    ("ssh_trap",     "DevOps_server"):   0.90,
    ("ssh_trap",     "Finance_DB"):      0.40,   # implausible – Finance DB on raw SSH
    ("ssh_trap",     "Generic_Linux"):   0.75,

    # db_trap (database service)
    ("db_trap",      "HR_workstation"):  0.50,
    ("db_trap",      "DevOps_server"):   0.70,
    ("db_trap",      "Finance_DB"):      0.95,   # perfect match
    ("db_trap",      "Generic_Linux"):   0.60,

    # smb_trap (Windows file share)
    ("smb_trap",     "HR_workstation"):  0.80,
    ("smb_trap",     "DevOps_server"):   0.70,
    ("smb_trap",     "Finance_DB"):      0.55,
    ("smb_trap",     "Generic_Linux"):   0.45,   # Linux ↔ SMB implausible

    # scada_trap (OT/ICS device)
    ("scada_trap",   "HR_workstation"):  0.20,   # no HR workstations in OT
    ("scada_trap",   "DevOps_server"):   0.50,
    ("scada_trap",   "Finance_DB"):      0.15,
    ("scada_trap",   "Generic_Linux"):   0.90,   # OT devices run embedded Linux

    # ad_trap (Active Directory domain controller)
    ("ad_trap",      "HR_workstation"):  0.90,   # HR always on AD
    ("ad_trap",      "DevOps_server"):   0.75,
    ("ad_trap",      "Finance_DB"):      0.60,
    ("ad_trap",      "Generic_Linux"):   0.40,   # Linux DCs unusual

    # dns_trap (DNS/DHCP service)
    ("dns_trap",     "HR_workstation"):  0.55,
    ("dns_trap",     "DevOps_server"):   0.80,
    ("dns_trap",     "Finance_DB"):      0.35,
    ("dns_trap",     "Generic_Linux"):   0.85,

    # web_trap (web / application server)
    ("web_trap",     "HR_workstation"):  0.65,
    ("web_trap",     "DevOps_server"):   0.85,
    ("web_trap",     "Finance_DB"):      0.50,
    ("web_trap",     "Generic_Linux"):   0.80,

    # generic_trap (low-interaction catch-all)
    ("generic_trap", "HR_workstation"):  0.75,
    ("generic_trap", "DevOps_server"):   0.70,
    ("generic_trap", "Finance_DB"):      0.50,
    ("generic_trap", "Generic_Linux"):   0.80,
}

# Admission threshold (eq 14): pair admitted iff GK_scores[(trap,persona)] >= tau_GK
tau_GK = 0.65   # τ_GK — defined below in the V4 parameter block; also here for GK admission


def gk_admitted(trap, persona):
    """Return True if (trap, persona) passes the GK plausibility check (eq 14)."""
    return GK_scores.get((trap, persona), 0.0) >= tau_GK


# ─────────────────────────────────────────────────────────────────────────────
#  DISCOVERY THRESHOLDS  ── τd, τdp, τd0  (constraints C9, C13)
# ─────────────────────────────────────────────────────────────────────────────

tau_d0  = 3   # τd0 ── type-discovery baseline (slots before type identified at ρπ=0)
tau_dp0 = 2   # τdp0 ── persona-discovery baseline (slots before persona identified, n=0)
rho_max = 1.0 # ρmax ── normalization ceiling for threat-adaptive τd formula


# ─────────────────────────────────────────────────────────────────────────────
#  CHURN BUDGETS  ── Δ, Δp  (constraint C8)
# ─────────────────────────────────────────────────────────────────────────────

Delta   = 2   # Δ  ── max type-rotation state changes per (trap,zone,persona) across T̄
Delta_p = 2   # Δp ── max persona-rotation changes per (trap,zone) across T̄

# C8/C13 compatibility check (equation 15, V5):
#   Δ ≥ ⌈H / τdp0⌉ − 1   →   2 ≥ ⌈4/2⌉ − 1 = 1  ✓
import math as _math
assert Delta >= _math.ceil(H / tau_dp0) - 1, (
    f"C8/C13 INFEASIBLE: Delta={Delta} < ceil({H}/{tau_dp0})-1="
    f"{_math.ceil(H/tau_dp0)-1}. Raise Delta or tau_dp0."
)


# ─────────────────────────────────────────────────────────────────────────────
#  q  ── PERSONA PRIORS  qp ∈ [0,1],  Σp qp = 1
#  Initial (uniform); updated by Algorithm 1 at each STIX/TAXII event.
#  Algorithm 1 Steps 3a (STIX blend) and 3b (empirical blend) produce q_updated.
# ─────────────────────────────────────────────────────────────────────────────

q_initial = {
    "HR_workstation": 0.25,
    "DevOps_server":  0.25,
    "Finance_DB":     0.25,
    "Generic_Linux":  0.25,
}

# STIX signals used in Algorithm 1 Step 3a (3 concurrent signals, V3 multi-signal)
stix_signals = [
    {
        "confidence": 0.88,
        "threat_class": "financial",
        "deltas": {
            "Finance_DB":     +0.25,
            "HR_workstation": +0.15,
            "DevOps_server":  -0.05,
            "Generic_Linux":  -0.05,
        },
    },
    {
        "confidence": 0.45,
        "threat_class": "espionage",
        "deltas": {
            "DevOps_server":  +0.20,
            "Generic_Linux":  +0.10,
            "Finance_DB":     -0.05,
            "HR_workstation": -0.05,
        },
    },
    {
        "confidence": 0.30,
        "threat_class": "recon",
        "deltas": {
            "Generic_Linux":  +0.15,
            "HR_workstation": +0.05,
            "Finance_DB":     -0.05,
            "DevOps_server":  -0.05,
        },
    },
]

# Empirical interaction counts for Step 3b (trailing observation window)
empirical_interactions = {
    "Finance_DB":     18,
    "HR_workstation": 12,
    "DevOps_server":   7,
    "Generic_Linux":   3,
}   # N_obs = sum = 40


# ─────────────────────────────────────────────────────────────────────────────
#  V4 GAP-RESOLUTION PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────

# γ  ── attacker learning-decay rate (K.1, equations 12/12′)
gamma = 0.80     # γ ∈ (0,1] ; γ=1 disables learning (recovers V3 τd exactly)

# βmax  ── empirical trust ceiling (K.2, Algorithm 1 Step 3b)
beta_max = 0.60  # βmax ∈ [0,1]; STIX prior retains ≥ (1−βmax) weight

# κ  ── half-confidence constant (K.2, Step 3b)
kappa = 30.0     # κ ∈ ℝ+ ; β = min(N_obs/(N_obs+κ), βmax)

# τ_GK  ── GK role-compatibility admission threshold (L.1, eq 14)
# Already defined above to bootstrap GK; repeated here for tuple completeness.
# tau_GK = 0.65  ← see GK block above

# h_min  ── minimum real-time slot duration floor (L.2, constraint C15)
h_min   = 24.0   # hours; one slot must represent at least h_min hours of real time

# κ_min  ── fastest plausible attacker kill-chain duration (L.2, C15)
kappa_min = 12.0 # hours; from threat intelligence

# C15 precondition check:
assert h_min >= kappa_min, (
    f"C15 VIOLATION: h_min={h_min}h < kappa_min={kappa_min}h. "
    "Slot granularity is too fine to bound the fastest known attacker kill chain."
)


# ─────────────────────────────────────────────────────────────────────────────
#  V5 GAP-RESOLUTION PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────

# ρ_decay  ── cooldown decay rate for Ni,p(t) (V5 formal recurrence)
rho_decay = 0.50  # ρ_decay ∈ (0,1); N halved (rounded down) after Δ_N inactive slots

# Δ_N  ── cooldown window before Ni,p(t) begins to decay (V5, independent of Δ and Δp)
Delta_N = 3       # Δ_N ∈ ℤ+; consecutive inactive slots across all zones before decay starts


# ─────────────────────────────────────────────────────────────────────────────
#  V6 SCENARIO SET Θ  (Section L, equations 16–18)
#  Each θk = (ρπ^(k), τd0^(k), threat-class^(k))
#  Operator-specified; used by RC2 to build the robust objective.
# ─────────────────────────────────────────────────────────────────────────────

Theta = [
    {
        "id":           "theta_low",
        "rho":          0.15,
        "tau_d0":       4,
        "threat_class": "recon",
        "label":        "θ_low  ρ=0.15  (cautious, infrequent attacker)",
    },
    {
        "id":           "theta_med",
        "rho":          0.30,
        "tau_d0":       3,
        "threat_class": "financial",
        "label":        "θ_med  ρ=0.30  (baseline throughout Sections D–I)",
    },
    {
        "id":           "theta_high",
        "rho":          0.55,
        "tau_d0":       2,
        "threat_class": "financial",
        "label":        "θ_high ρ=0.55  (elevated threat, C11 worked example)",
    },
    {
        "id":           "theta_burst",
        "rho":          0.85,
        "tau_d0":       1,
        "threat_class": "espionage",
        "label":        "θ_burst ρ=0.85  (near-max threat, motivated V5 τd floor)",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  SOFT-CLAUSE GEOMETRIC WEIGHTS  (Section E, equations 6–11)
#  w4 = 1000w3,  w3 = 100w2,  w2 = 10w1  — unchanged from base paper.
# ─────────────────────────────────────────────────────────────────────────────

w1 = 1        # L1 – basic detection
w2 = 10       # L2-tech – technique coverage
w2_fam = 12   # L2-fam – tactic-family bonus (1.2× w2)
w3 = 100      # L3-fwd – forward path coverage
w3_bwd = 70   # L3-bwd – forensic backward (0.7 × w3)
w4 = 1000     # L4    – early interception (1000 × w3)


# ─────────────────────────────────────────────────────────────────────────────
#  SOLVER RUNTIME PARAMETERS  (RC2 / python-sat)
# ─────────────────────────────────────────────────────────────────────────────

solver_backend = "g4"     # RC2 SAT backend: "g4" (Glucose4) or "mc" (MiniCard)
random_seed    = 42
weight_scale   = 1        # Integer scale factor applied to all soft weights before WCNF export


# ─────────────────────────────────────────────────────────────────────────────
#  MASTER CFG DICT  ── single import point for the solver
# ─────────────────────────────────────────────────────────────────────────────

CFG = {
    # ── Structural sets ──────────────────────────────────────
    "K":                    K,
    "T":                    T,
    "Z":                    Z,
    "P":                    P,
    "A_per_zone":           A_per_zone,
    "A_total":              A_total,

    # ── Attack paths G ───────────────────────────────────────
    "G":                    G,

    # ── Conflict set C, air-gaps I2, affinity ⋄ ─────────────
    "C_conflicts":          C_conflicts,
    "I2":                   I2,
    "diamond_affinity":     diamond_affinity,   # ⋄

    # ── Technique weights w, stealth σ ───────────────────────
    "w":                    w_technique,
    "sigma":                sigma,

    # ── Cost ─────────────────────────────────────────────────
    "cost_per_type":        cost_per_type,
    "cost_zone_multiplier": cost_zone_multiplier,

    # ── Budgets B, B2 ────────────────────────────────────────
    "B":                    B_global,
    "B2":                   B_zone,

    # ── Asset parameters dm, hd ──────────────────────────────
    "dm_range":             dm_range,
    "hd_by_zone":           hd_by_zone,

    # ── Tactic families (for L2-fam) ─────────────────────────
    "tactic_families":      tactic_families,

    # ── Trap → techniques mapping ────────────────────────────
    "trap_techniques":      trap_techniques,

    # ── Planning horizon H ───────────────────────────────────
    "H":                    H,

    # ── GK role-compatibility ────────────────────────────────
    "GK_scores":            GK_scores,
    "gk_admitted":          gk_admitted,    # callable: (trap, persona) → bool

    # ── Discovery thresholds τd, τdp, τd0 ───────────────────
    "tau_d0":               tau_d0,
    "tau_dp0":              tau_dp0,
    "rho_max":              rho_max,

    # ── Churn budgets Δ, Δp ──────────────────────────────────
    "Delta":                Delta,
    "Delta_p":              Delta_p,

    # ── Persona priors q, STIX signals, empirical data ───────
    "q":                    q_initial,
    "stix_signals":         stix_signals,
    "empirical_interactions": empirical_interactions,

    # ── V4 parameters: γ, βmax, κ, τ_GK, h_min, κ_min ───────
    "gamma":                gamma,
    "beta_max":             beta_max,
    "kappa":                kappa,
    "tau_GK":               tau_GK,
    "h_min":                h_min,
    "kappa_min":            kappa_min,

    # ── V5 parameters: ρ_decay, Δ_N ──────────────────────────
    "rho_decay":            rho_decay,
    "Delta_N":              Delta_N,

    # ── V6 scenario set Θ ────────────────────────────────────
    "Theta":                Theta,

    # ── Soft-clause geometric weights ────────────────────────
    "w1":                   w1,
    "w2":                   w2,
    "w2_fam":               w2_fam,
    "w3":                   w3,
    "w3_bwd":               w3_bwd,
    "w4":                   w4,

    # ── Solver runtime ────────────────────────────────────────
    "solver_backend":       solver_backend,
    "random_seed":          random_seed,
    "weight_scale":         weight_scale,
}


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST  ── run  python config.py  to verify parameter consistency
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print("=" * 65)
    print("  Zone-Slot-Time-Persona V6 — Configuration Self-Test")
    print("=" * 65)

    # Structural sizes
    print(f"\n[Sets]")
    print(f"  |K| = {len(K)} types      : {K}")
    print(f"  |T| = {len(T)} techniques")
    print(f"  |Z| = {len(Z)} zones      : {Z}")
    print(f"  |P| = {len(P)} personas   : {P}")
    print(f"  |A| = {A_total} assets    : {A_per_zone}")
    print(f"  |G| = {len(G)} paths      : {[p['name'] for p in G]}")
    print(f"  |Θ| = {len(Theta)} scenarios : {[t['id'] for t in Theta]}")

    # Primary variable count
    pv = len(K) * len(Z) * H * len(P)
    print(f"\n[Complexity]")
    print(f"  Primary vars |K|·|Z|·H·|P| = {pv}  (independent of |A|)")
    print(f"  Soft-clause DB ~ O(|K|·|A|·|T|·H·|P|) = "
          f"{len(K)*A_total*len(T)*H*len(P):,}")

    # Precondition checks
    print(f"\n[Preconditions]")
    print(f"  C15:   h_min={h_min}h ≥ κ_min={kappa_min}h  ✓")
    print(f"  C8/C13: Δ={Delta} ≥ ⌈H/τdp0⌉−1="
          f"{_math.ceil(H/tau_dp0)-1}  ✓")

    # GK admission summary
    admitted = {(tr,p): gk_admitted(tr,p) for tr in K for p in P}
    n_admitted = sum(admitted.values())
    print(f"\n[GK]")
    print(f"  τ_GK = {tau_GK}  →  {n_admitted}/{len(K)*len(P)} "
          f"(trap,persona) pairs admitted")

    # Budget check: single most-expensive deployment per zone
    print(f"\n[Budgets]")
    print(f"  B_global = {B_global:,.0f}")
    for z in Z:
        most_exp = max(
            cost_per_type[tr]*cost_zone_multiplier[z]
            for tr in K if z in diamond_affinity[tr]
        )
        print(f"  B_{z:8s} = {B_zone.get(z,0):>8,.0f}   "
              f"most expensive deployment = {most_exp:.2f} units/slot")

    # Soft-clause weight ratios
    print(f"\n[Soft-clause weights]")
    print(f"  L4={w4}  L3={w3}  L3-bwd={w3_bwd}  "
          f"L2={w2}  L2-fam={w2_fam}  L1={w1}")
    print(f"  Ratios: w4/w3={w4//w3}×  w3/w2={w3//w2}×  "
          f"w2_fam/w2={w2_fam/w2:.1f}×")

    # Scenario summary
    print(f"\n[Θ scenarios]")
    for th in Theta:
        td_eff = max(1.0, th["tau_d0"] * (1 - th["rho"] / rho_max))
        print(f"  {th['id']:12s}  ρ={th['rho']}  τd0={th['tau_d0']}"
              f"  τd_eff≈{td_eff:.2f}  class={th['threat_class']}")

    print("\n[✓] All preconditions satisfied. CFG ready for import.")
    print("=" * 65)
