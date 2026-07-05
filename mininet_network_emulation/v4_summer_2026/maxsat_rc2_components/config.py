"""
config.py
Zone-Slot-Time-Persona V6 MaxSAT RC2 Configuration
====================================================
Complete instance tuple I = (K, T, A, Z, P, G, C, I2, ⋄, w, cost, B, B2,
    dm, hd, σ, ρ, iv, GK, τd, τdp, τd0, Δ, Δp, q, ρmax, H, γ, βmax, κ,
    τ_GK, h_min, κ_min, ρ_decay, Δ_N)

Every symbol from equation (1) Section A is defined here and nowhere else.
Import this module; do not hard-code parameters in the solver.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SCALE SELECTOR  ── set NETWORK_SCALE before every run
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  NETWORK_SCALE = "Small"    →  |K|=5  |Z|=3  H=4  |P|=3  |A|=150   |G|=3  |Θ|=3
  NETWORK_SCALE = "Medium"   →  |K|=8  |Z|=5  H=6  |P|=4  |A|=500   |G|=5  |Θ|=4
  NETWORK_SCALE = "Large"    →  |K|=10 |Z|=6  H=8  |P|=5  |A|=1000  |G|=7  |Θ|=4
  NETWORK_SCALE = "XLarge"   →  |K|=8  |Z|=5  H=4  |P|=4  |A|=500   |G|=4  |Θ|=4  ← dissertation baseline
  NETWORK_SCALE = "XXLarge"  →  |K|=12 |Z|=7  H=8  |P|=6  |A|=2000  |G|=8  |Θ|=5

Complexity (primary vars = |K|·|Z|·H·|P|):
  Small:    180   vars   soft-DB ~    162,000   ← quick sanity tests
  Medium:   960   vars   soft-DB ~  1,728,000   ← development / unit tests
  Large:  2,400   vars   soft-DB ~  7,200,000   ← strong dissertation result
  XLarge:   640   vars   soft-DB ~  1,152,000   ← current dissertation baseline
  XXLarge: 4,032  vars   soft-DB ~ 20,736,000   ← stress / scalability section

Usage:
    from config import CFG, NETWORK_SCALE
    print(CFG["SCALE"])      # confirms active scale
    K = CFG["K"]
    A = CFG["A_total"]
"""

import math as _math
import os as _os

# ─────────────────────────────────────────────────────────────────────────────
#  ★  SCALE SELECTOR  ── change this ONE line to switch configurations
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_SCALE = _os.environ.get("ZSTP_SCALE", "XLarge")
# Override from environment: ZSTP_SCALE=Large python maxsat_rc2_solver.py
# Or change the string literal here directly.
# Valid values: "Small" | "Medium" | "Large" | "XLarge" | "XXLarge"


# ─────────────────────────────────────────────────────────────────────────────
#  SCALE DEFINITIONS  ── each entry fully specifies the instance dimensions
# ─────────────────────────────────────────────────────────────────────────────

_SCALE_DEFS = {

    # ── Small ────────────────────────────────────────────────────────────────
    # 3 zones, 5 trap types, 3 personas, 3 paths, 3 scenarios
    # Use for: rapid sanity checks, unit tests, algorithm debugging
    # Primary vars: 5×3×4×3 = 180   Soft-DB: ~162,000
    "Small": {
        "K": ["ssh_trap", "db_trap", "web_trap", "dns_trap", "generic_trap"],
        "Z": ["DMZ", "Internal", "Cloud"],
        "H": 4,
        "P": ["HR_workstation", "DevOps_server", "Finance_DB"],
        "A_per_zone": {"DMZ": 30, "Internal": 80, "Cloud": 40},
        "G": [
            {"id":"pi1","name":"web-to-db",
             "zones":["DMZ","Internal","Internal"],
             "rho":0.35,"iv":[1.8,1.4,1.0],
             "techniques":["T1566","T1078","T1048"]},
            {"id":"pi2","name":"cloud-pivot",
             "zones":["Cloud","Internal"],
             "rho":0.25,"iv":[1.6,1.0],
             "techniques":["T1190","T1021"]},
            {"id":"pi3","name":"lateral",
             "zones":["DMZ","Internal"],
             "rho":0.20,"iv":[1.5,1.0],
             "techniques":["T1133","T1021"]},
        ],
        "Theta": [
            {"id":"theta_low",  "rho":0.15,"tau_d0":4,"threat_class":"recon",
             "label":"θ_low ρ=0.15"},
            {"id":"theta_med",  "rho":0.30,"tau_d0":3,"threat_class":"financial",
             "label":"θ_med ρ=0.30"},
            {"id":"theta_burst","rho":0.85,"tau_d0":1,"threat_class":"espionage",
             "label":"θ_burst ρ=0.85"},
        ],
        "H_val":      4,
        "tau_d0":     3,
        "tau_dp0":    2,
        "Delta":      2,
        "Delta_p":    2,
        "B_global":   25_000.0,
        "B_zone":     {"DMZ":8_000.0,"Internal":12_000.0,"Cloud":8_000.0},
        "I2":         [],
        "C_conflicts":[("generic_trap","dns_trap")],
        "diamond_affinity": {
            "ssh_trap":     ["DMZ","Internal","Cloud"],
            "db_trap":      ["Internal","Cloud"],
            "web_trap":     ["DMZ","Cloud"],
            "dns_trap":     ["DMZ","Internal","Cloud"],
            "generic_trap": ["DMZ","Internal","Cloud"],
        },
        "GK_scores": {
            ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,("ssh_trap","Finance_DB"):0.40,
            ("db_trap","HR_workstation"):0.50, ("db_trap","DevOps_server"):0.70, ("db_trap","Finance_DB"):0.95,
            ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,("web_trap","Finance_DB"):0.50,
            ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,("dns_trap","Finance_DB"):0.35,
            ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,("generic_trap","Finance_DB"):0.50,
        },
        "stix_signals": [
            {"confidence":0.88,"threat_class":"financial",
             "deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,"DevOps_server":-0.05}},
        ],
        "empirical_interactions": {"Finance_DB":18,"HR_workstation":12,"DevOps_server":7},
    },

    # ── Medium ───────────────────────────────────────────────────────────────
    # 5 zones, 8 trap types, 4 personas, 5 paths, 6-slot horizon
    # Use for: development, parameter sensitivity, comparison-table drafts
    # Primary vars: 8×5×6×4 = 960   Soft-DB: ~1.7M
    "Medium": {
        "K": ["ssh_trap","db_trap","smb_trap","scada_trap","ad_trap",
              "dns_trap","web_trap","generic_trap"],
        "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
        "H": 6,
        "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
        "A_per_zone": {"DMZ":80,"Internal":200,"Cloud":120,"OT":50,"Mgmt":50},
        "G": [
            {"id":"pi1","name":"web-to-db",
             "zones":["DMZ","Internal","Internal"],
             "rho":0.35,"iv":[1.8,1.4,1.0],"techniques":["T1566","T1078","T1048"]},
            {"id":"pi2","name":"cloud-ad-pivot",
             "zones":["Cloud","Internal","Mgmt"],
             "rho":0.25,"iv":[1.6,1.3,1.0],"techniques":["T1190","T1021","T1110"]},
            {"id":"pi3","name":"ot-infiltration",
             "zones":["DMZ","OT"],
             "rho":0.15,"iv":[1.5,1.2],"techniques":["T1566","T1059"]},
            {"id":"pi4","name":"mgmt-pivot",
             "zones":["DMZ","Mgmt","Internal"],
             "rho":0.20,"iv":[1.7,1.3,1.0],"techniques":["T1133","T1078","T1021"]},
            {"id":"pi5","name":"cloud-exfil",
             "zones":["Cloud","Internal"],
             "rho":0.15,"iv":[1.4,1.0],"techniques":["T1048","T1041"]},
        ],
        "Theta": [
            {"id":"theta_low",  "rho":0.15,"tau_d0":4,"threat_class":"recon",
             "label":"θ_low ρ=0.15"},
            {"id":"theta_med",  "rho":0.30,"tau_d0":3,"threat_class":"financial",
             "label":"θ_med ρ=0.30"},
            {"id":"theta_high", "rho":0.55,"tau_d0":2,"threat_class":"financial",
             "label":"θ_high ρ=0.55"},
            {"id":"theta_burst","rho":0.85,"tau_d0":1,"threat_class":"espionage",
             "label":"θ_burst ρ=0.85"},
        ],
        "H_val":3,"tau_d0":3,"tau_dp0":2,"Delta":3,"Delta_p":3,
        "B_global":62_500.0,
        "B_zone":{"DMZ":15_000.0,"Internal":20_000.0,"Cloud":15_000.0,"OT":8_000.0,"Mgmt":4_500.0},
        "I2":[("OT","DMZ"),("OT","Cloud"),("OT","Mgmt")],
        "C_conflicts":[("generic_trap","dns_trap"),("smb_trap","generic_trap")],
        "diamond_affinity": {
            "ssh_trap":["DMZ","Internal","Cloud","Mgmt"],
            "db_trap":["Internal","Cloud","Mgmt"],
            "smb_trap":["Internal","Mgmt"],
            "scada_trap":["OT"],
            "ad_trap":["Internal","Mgmt"],
            "dns_trap":["DMZ","Internal","Cloud"],
            "web_trap":["DMZ","Cloud"],
            "generic_trap":["DMZ","Internal","Cloud","Mgmt"],
        },
        "GK_scores": {
            ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
            ("ssh_trap","Finance_DB"):0.40,("ssh_trap","Generic_Linux"):0.75,
            ("db_trap","HR_workstation"):0.50,("db_trap","DevOps_server"):0.70,
            ("db_trap","Finance_DB"):0.95,("db_trap","Generic_Linux"):0.60,
            ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
            ("smb_trap","Finance_DB"):0.55,("smb_trap","Generic_Linux"):0.45,
            ("scada_trap","HR_workstation"):0.20,("scada_trap","DevOps_server"):0.50,
            ("scada_trap","Finance_DB"):0.15,("scada_trap","Generic_Linux"):0.90,
            ("ad_trap","HR_workstation"):0.90,("ad_trap","DevOps_server"):0.75,
            ("ad_trap","Finance_DB"):0.60,("ad_trap","Generic_Linux"):0.40,
            ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
            ("dns_trap","Finance_DB"):0.35,("dns_trap","Generic_Linux"):0.85,
            ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
            ("web_trap","Finance_DB"):0.50,("web_trap","Generic_Linux"):0.80,
            ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
            ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
        },
        "stix_signals":[
            {"confidence":0.88,"threat_class":"financial",
             "deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,"DevOps_server":-0.05,"Generic_Linux":-0.05}},
            {"confidence":0.45,"threat_class":"espionage",
             "deltas":{"DevOps_server":+0.20,"Generic_Linux":+0.10,"Finance_DB":-0.05,"HR_workstation":-0.05}},
        ],
        "empirical_interactions":{"Finance_DB":18,"HR_workstation":12,"DevOps_server":7,"Generic_Linux":3},
    },

    # ── Large ────────────────────────────────────────────────────────────────
    # 6 zones, 10 trap types, 5 personas, 7 paths, 8-slot horizon
    # Use for: main dissertation result, scalability claims, Chapter 5 tables
    # Primary vars: 10×6×8×5 = 2,400   Soft-DB: ~7.2M
    "Large": {
        "K": ["ssh_trap","db_trap","smb_trap","scada_trap","ad_trap",
              "dns_trap","web_trap","generic_trap","ftp_trap","rdp_trap"],
        "Z": ["DMZ","Internal","Cloud","OT","Mgmt","Dev"],
        "H": 8,
        "P": ["HR_workstation","DevOps_server","Finance_DB",
              "Generic_Linux","Executive_Host"],
        "A_per_zone": {"DMZ":120,"Internal":350,"Cloud":200,"OT":80,"Mgmt":100,"Dev":150},
        "G": [
            {"id":"pi1","name":"web-to-db",
             "zones":["DMZ","Internal","Internal"],
             "rho":0.35,"iv":[1.8,1.4,1.0],"techniques":["T1566","T1078","T1048"]},
            {"id":"pi2","name":"cloud-ad-pivot",
             "zones":["Cloud","Internal","Mgmt"],
             "rho":0.25,"iv":[1.6,1.3,1.0],"techniques":["T1190","T1021","T1110"]},
            {"id":"pi3","name":"ot-infiltration",
             "zones":["DMZ","OT"],
             "rho":0.15,"iv":[1.5,1.2],"techniques":["T1566","T1059"]},
            {"id":"pi4","name":"mgmt-pivot",
             "zones":["DMZ","Mgmt","Internal"],
             "rho":0.20,"iv":[1.7,1.3,1.0],"techniques":["T1133","T1078","T1021"]},
            {"id":"pi5","name":"dev-exfil",
             "zones":["Dev","Internal","Cloud"],
             "rho":0.18,"iv":[1.5,1.2,1.0],"techniques":["T1048","T1041","T1213"]},
            {"id":"pi6","name":"exec-spear",
             "zones":["DMZ","Mgmt"],
             "rho":0.12,"iv":[1.6,1.0],"techniques":["T1566","T1078"]},
            {"id":"pi7","name":"cloud-ot-bridge",
             "zones":["Cloud","Internal","OT"],
             "rho":0.10,"iv":[1.4,1.2,1.0],"techniques":["T1190","T1021","T1059"]},
        ],
        "Theta": [
            {"id":"theta_low",  "rho":0.15,"tau_d0":4,"threat_class":"recon",
             "label":"θ_low ρ=0.15"},
            {"id":"theta_med",  "rho":0.30,"tau_d0":3,"threat_class":"financial",
             "label":"θ_med ρ=0.30"},
            {"id":"theta_high", "rho":0.55,"tau_d0":2,"threat_class":"financial",
             "label":"θ_high ρ=0.55"},
            {"id":"theta_burst","rho":0.85,"tau_d0":1,"threat_class":"espionage",
             "label":"θ_burst ρ=0.85"},
        ],
        "H_val":4,"tau_d0":4,"tau_dp0":3,"Delta":3,"Delta_p":3,
        "B_global":120_000.0,
        "B_zone":{"DMZ":25_000.0,"Internal":35_000.0,"Cloud":25_000.0,
                  "OT":15_000.0,"Mgmt":12_000.0,"Dev":18_000.0},
        "I2":[("OT","DMZ"),("OT","Cloud"),("OT","Mgmt"),("OT","Dev")],
        "C_conflicts":[("generic_trap","dns_trap"),("smb_trap","generic_trap"),
                       ("ftp_trap","smb_trap")],
        "diamond_affinity": {
            "ssh_trap":    ["DMZ","Internal","Cloud","Mgmt","Dev"],
            "db_trap":     ["Internal","Cloud","Mgmt","Dev"],
            "smb_trap":    ["Internal","Mgmt","Dev"],
            "scada_trap":  ["OT"],
            "ad_trap":     ["Internal","Mgmt"],
            "dns_trap":    ["DMZ","Internal","Cloud"],
            "web_trap":    ["DMZ","Cloud","Dev"],
            "generic_trap":["DMZ","Internal","Cloud","Mgmt","Dev"],
            "ftp_trap":    ["DMZ","Internal","Dev"],
            "rdp_trap":    ["Internal","Mgmt","Dev"],
        },
        "GK_scores": {
            ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
            ("ssh_trap","Finance_DB"):0.40,("ssh_trap","Generic_Linux"):0.75,
            ("ssh_trap","Executive_Host"):0.70,
            ("db_trap","HR_workstation"):0.50,("db_trap","DevOps_server"):0.70,
            ("db_trap","Finance_DB"):0.95,("db_trap","Generic_Linux"):0.60,
            ("db_trap","Executive_Host"):0.45,
            ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
            ("smb_trap","Finance_DB"):0.55,("smb_trap","Generic_Linux"):0.45,
            ("smb_trap","Executive_Host"):0.85,
            ("scada_trap","HR_workstation"):0.20,("scada_trap","DevOps_server"):0.50,
            ("scada_trap","Finance_DB"):0.15,("scada_trap","Generic_Linux"):0.90,
            ("scada_trap","Executive_Host"):0.10,
            ("ad_trap","HR_workstation"):0.90,("ad_trap","DevOps_server"):0.75,
            ("ad_trap","Finance_DB"):0.60,("ad_trap","Generic_Linux"):0.40,
            ("ad_trap","Executive_Host"):0.95,
            ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
            ("dns_trap","Finance_DB"):0.35,("dns_trap","Generic_Linux"):0.85,
            ("dns_trap","Executive_Host"):0.50,
            ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
            ("web_trap","Finance_DB"):0.50,("web_trap","Generic_Linux"):0.80,
            ("web_trap","Executive_Host"):0.75,
            ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
            ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
            ("generic_trap","Executive_Host"):0.70,
            ("ftp_trap","HR_workstation"):0.60,("ftp_trap","DevOps_server"):0.75,
            ("ftp_trap","Finance_DB"):0.55,("ftp_trap","Generic_Linux"):0.80,
            ("ftp_trap","Executive_Host"):0.40,
            ("rdp_trap","HR_workstation"):0.90,("rdp_trap","DevOps_server"):0.80,
            ("rdp_trap","Finance_DB"):0.65,("rdp_trap","Generic_Linux"):0.55,
            ("rdp_trap","Executive_Host"):0.95,
        },
        "stix_signals":[
            {"confidence":0.88,"threat_class":"financial",
             "deltas":{"Finance_DB":+0.20,"HR_workstation":+0.12,"Executive_Host":+0.08,
                       "DevOps_server":-0.05,"Generic_Linux":-0.05}},
            {"confidence":0.45,"threat_class":"espionage",
             "deltas":{"DevOps_server":+0.18,"Generic_Linux":+0.10,"Executive_Host":+0.05,
                       "Finance_DB":-0.05,"HR_workstation":-0.05}},
            {"confidence":0.30,"threat_class":"recon",
             "deltas":{"Generic_Linux":+0.12,"HR_workstation":+0.05,
                       "Finance_DB":-0.03,"DevOps_server":-0.03,"Executive_Host":-0.02}},
        ],
        "empirical_interactions":{"Finance_DB":22,"HR_workstation":15,
                                   "Executive_Host":10,"DevOps_server":8,"Generic_Linux":4},
    },

    # ── XLarge ───────────────────────────────────────────────────────────────
    # DISSERTATION BASELINE — unchanged from original config.py
    # 5 zones, 8 trap types, 4 personas, 4 paths, 4-slot horizon
    # Primary vars: 8×5×4×4 = 640   Soft-DB: ~1.15M
    "XLarge": {
        "K": ["ssh_trap","db_trap","smb_trap","scada_trap","ad_trap",
              "dns_trap","web_trap","generic_trap"],
        "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
        "H": 4,
        "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
        "A_per_zone": {"DMZ":80,"Internal":200,"Cloud":120,"OT":50,"Mgmt":50},
        "G": [
            {"id":"pi1","name":"web-to-db",
             "zones":["DMZ","Internal","Internal"],
             "rho":0.35,"iv":[1.8,1.4,1.0],"techniques":["T1566","T1078","T1048"]},
            {"id":"pi2","name":"cloud-ad-pivot",
             "zones":["Cloud","Internal","Mgmt"],
             "rho":0.25,"iv":[1.6,1.3,1.0],"techniques":["T1190","T1021","T1110"]},
            {"id":"pi3","name":"ot-infiltration",
             "zones":["DMZ","OT"],
             "rho":0.15,"iv":[1.5,1.2],"techniques":["T1566","T1059"]},
            {"id":"pi4","name":"mgmt-pivot",
             "zones":["DMZ","Mgmt","Internal"],
             "rho":0.20,"iv":[1.7,1.3,1.0],"techniques":["T1133","T1078","T1021"]},
        ],
        "Theta": [
            {"id":"theta_low",  "rho":0.15,"tau_d0":4,"threat_class":"recon",
             "label":"θ_low  ρ=0.15  (cautious, infrequent attacker)"},
            {"id":"theta_med",  "rho":0.30,"tau_d0":3,"threat_class":"financial",
             "label":"θ_med  ρ=0.30  (baseline throughout Sections D–I)"},
            {"id":"theta_high", "rho":0.55,"tau_d0":2,"threat_class":"financial",
             "label":"θ_high ρ=0.55  (elevated threat, C11 worked example)"},
            {"id":"theta_burst","rho":0.85,"tau_d0":1,"threat_class":"espionage",
             "label":"θ_burst ρ=0.85  (near-max threat, motivated V5 τd floor)"},
        ],
        "H_val":3,"tau_d0":3,"tau_dp0":2,"Delta":2,"Delta_p":2,
        "B_global":62_500.0,
        "B_zone":{"DMZ":15_000.0,"Internal":20_000.0,"Cloud":15_000.0,
                  "OT":8_000.0,"Mgmt":4_500.0},
        "I2":[("OT","DMZ"),("OT","Cloud"),("OT","Mgmt")],
        "C_conflicts":[("generic_trap","dns_trap"),("smb_trap","generic_trap")],
        "diamond_affinity": {
            "ssh_trap":    ["DMZ","Internal","Cloud","Mgmt"],
            "db_trap":     ["Internal","Cloud","Mgmt"],
            "smb_trap":    ["Internal","Mgmt"],
            "scada_trap":  ["OT"],
            "ad_trap":     ["Internal","Mgmt"],
            "dns_trap":    ["DMZ","Internal","Cloud"],
            "web_trap":    ["DMZ","Cloud"],
            "generic_trap":["DMZ","Internal","Cloud","Mgmt"],
        },
        "GK_scores": {
            ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
            ("ssh_trap","Finance_DB"):0.40,("ssh_trap","Generic_Linux"):0.75,
            ("db_trap","HR_workstation"):0.50,("db_trap","DevOps_server"):0.70,
            ("db_trap","Finance_DB"):0.95,("db_trap","Generic_Linux"):0.60,
            ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
            ("smb_trap","Finance_DB"):0.55,("smb_trap","Generic_Linux"):0.45,
            ("scada_trap","HR_workstation"):0.20,("scada_trap","DevOps_server"):0.50,
            ("scada_trap","Finance_DB"):0.15,("scada_trap","Generic_Linux"):0.90,
            ("ad_trap","HR_workstation"):0.90,("ad_trap","DevOps_server"):0.75,
            ("ad_trap","Finance_DB"):0.60,("ad_trap","Generic_Linux"):0.40,
            ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
            ("dns_trap","Finance_DB"):0.35,("dns_trap","Generic_Linux"):0.85,
            ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
            ("web_trap","Finance_DB"):0.50,("web_trap","Generic_Linux"):0.80,
            ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
            ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
        },
        "stix_signals":[
            {"confidence":0.88,"threat_class":"financial",
             "deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,
                       "DevOps_server":-0.05,"Generic_Linux":-0.05}},
            {"confidence":0.45,"threat_class":"espionage",
             "deltas":{"DevOps_server":+0.20,"Generic_Linux":+0.10,
                       "Finance_DB":-0.05,"HR_workstation":-0.05}},
            {"confidence":0.30,"threat_class":"recon",
             "deltas":{"Generic_Linux":+0.15,"HR_workstation":+0.05,
                       "Finance_DB":-0.05,"DevOps_server":-0.05}},
        ],
        "empirical_interactions":{"Finance_DB":18,"HR_workstation":12,
                                   "DevOps_server":7,"Generic_Linux":3},
    },

    # ── XXLarge ──────────────────────────────────────────────────────────────
    # 7 zones, 12 trap types, 6 personas, 8 paths, 8-slot horizon
    # Use for: scalability section, stress test, future-work comparison
    # Primary vars: 12×7×8×6 = 4,032   Soft-DB: ~20.7M
    "XXLarge": {
        "K": ["ssh_trap","db_trap","smb_trap","scada_trap","ad_trap",
              "dns_trap","web_trap","generic_trap","ftp_trap","rdp_trap",
              "mail_trap","api_trap"],
        "Z": ["DMZ","Internal","Cloud","OT","Mgmt","Dev","Partner"],
        "H": 8,
        "P": ["HR_workstation","DevOps_server","Finance_DB",
              "Generic_Linux","Executive_Host","Partner_Gateway"],
        "A_per_zone": {"DMZ":150,"Internal":500,"Cloud":300,
                       "OT":100,"Mgmt":120,"Dev":200,"Partner":80},
        "G": [
            {"id":"pi1","name":"web-to-db",
             "zones":["DMZ","Internal","Internal"],
             "rho":0.35,"iv":[1.8,1.4,1.0],"techniques":["T1566","T1078","T1048"]},
            {"id":"pi2","name":"cloud-ad-pivot",
             "zones":["Cloud","Internal","Mgmt"],
             "rho":0.25,"iv":[1.6,1.3,1.0],"techniques":["T1190","T1021","T1110"]},
            {"id":"pi3","name":"ot-infiltration",
             "zones":["DMZ","OT"],
             "rho":0.15,"iv":[1.5,1.2],"techniques":["T1566","T1059"]},
            {"id":"pi4","name":"mgmt-pivot",
             "zones":["DMZ","Mgmt","Internal"],
             "rho":0.20,"iv":[1.7,1.3,1.0],"techniques":["T1133","T1078","T1021"]},
            {"id":"pi5","name":"dev-exfil",
             "zones":["Dev","Internal","Cloud"],
             "rho":0.18,"iv":[1.5,1.2,1.0],"techniques":["T1048","T1041","T1213"]},
            {"id":"pi6","name":"exec-spear",
             "zones":["DMZ","Mgmt"],
             "rho":0.12,"iv":[1.6,1.0],"techniques":["T1566","T1078"]},
            {"id":"pi7","name":"partner-pivot",
             "zones":["Partner","Internal","Cloud"],
             "rho":0.10,"iv":[1.4,1.2,1.0],"techniques":["T1190","T1021","T1048"]},
            {"id":"pi8","name":"cloud-ot-bridge",
             "zones":["Cloud","Internal","OT"],
             "rho":0.08,"iv":[1.4,1.2,1.0],"techniques":["T1190","T1021","T1059"]},
        ],
        "Theta": [
            {"id":"theta_low",   "rho":0.10,"tau_d0":5,"threat_class":"recon",
             "label":"θ_low ρ=0.10"},
            {"id":"theta_med",   "rho":0.30,"tau_d0":3,"threat_class":"financial",
             "label":"θ_med ρ=0.30"},
            {"id":"theta_high",  "rho":0.55,"tau_d0":2,"threat_class":"financial",
             "label":"θ_high ρ=0.55"},
            {"id":"theta_burst", "rho":0.85,"tau_d0":1,"threat_class":"espionage",
             "label":"θ_burst ρ=0.85"},
            {"id":"theta_apt",   "rho":0.70,"tau_d0":1,"threat_class":"nation-state",
             "label":"θ_apt ρ=0.70"},
        ],
        "H_val":4,"tau_d0":4,"tau_dp0":3,"Delta":3,"Delta_p":3,
        "B_global":200_000.0,
        "B_zone":{"DMZ":40_000.0,"Internal":60_000.0,"Cloud":40_000.0,
                  "OT":25_000.0,"Mgmt":20_000.0,"Dev":30_000.0,"Partner":15_000.0},
        "I2":[("OT","DMZ"),("OT","Cloud"),("OT","Mgmt"),
              ("OT","Dev"),("OT","Partner"),("Partner","Internal")],
        "C_conflicts":[("generic_trap","dns_trap"),("smb_trap","generic_trap"),
                       ("ftp_trap","smb_trap"),("mail_trap","api_trap")],
        "diamond_affinity": {
            "ssh_trap":     ["DMZ","Internal","Cloud","Mgmt","Dev","Partner"],
            "db_trap":      ["Internal","Cloud","Mgmt","Dev"],
            "smb_trap":     ["Internal","Mgmt","Dev"],
            "scada_trap":   ["OT"],
            "ad_trap":      ["Internal","Mgmt"],
            "dns_trap":     ["DMZ","Internal","Cloud","Partner"],
            "web_trap":     ["DMZ","Cloud","Dev","Partner"],
            "generic_trap": ["DMZ","Internal","Cloud","Mgmt","Dev"],
            "ftp_trap":     ["DMZ","Internal","Dev","Partner"],
            "rdp_trap":     ["Internal","Mgmt","Dev"],
            "mail_trap":    ["DMZ","Internal","Partner"],
            "api_trap":     ["Cloud","Dev","Partner"],
        },
        "GK_scores": {
            # ssh_trap
            ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
            ("ssh_trap","Finance_DB"):0.40,("ssh_trap","Generic_Linux"):0.75,
            ("ssh_trap","Executive_Host"):0.70,("ssh_trap","Partner_Gateway"):0.65,
            # db_trap
            ("db_trap","HR_workstation"):0.50,("db_trap","DevOps_server"):0.70,
            ("db_trap","Finance_DB"):0.95,("db_trap","Generic_Linux"):0.60,
            ("db_trap","Executive_Host"):0.45,("db_trap","Partner_Gateway"):0.40,
            # smb_trap
            ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
            ("smb_trap","Finance_DB"):0.55,("smb_trap","Generic_Linux"):0.45,
            ("smb_trap","Executive_Host"):0.85,("smb_trap","Partner_Gateway"):0.50,
            # scada_trap
            ("scada_trap","HR_workstation"):0.20,("scada_trap","DevOps_server"):0.50,
            ("scada_trap","Finance_DB"):0.15,("scada_trap","Generic_Linux"):0.90,
            ("scada_trap","Executive_Host"):0.10,("scada_trap","Partner_Gateway"):0.20,
            # ad_trap
            ("ad_trap","HR_workstation"):0.90,("ad_trap","DevOps_server"):0.75,
            ("ad_trap","Finance_DB"):0.60,("ad_trap","Generic_Linux"):0.40,
            ("ad_trap","Executive_Host"):0.95,("ad_trap","Partner_Gateway"):0.55,
            # dns_trap
            ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
            ("dns_trap","Finance_DB"):0.35,("dns_trap","Generic_Linux"):0.85,
            ("dns_trap","Executive_Host"):0.50,("dns_trap","Partner_Gateway"):0.75,
            # web_trap
            ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
            ("web_trap","Finance_DB"):0.50,("web_trap","Generic_Linux"):0.80,
            ("web_trap","Executive_Host"):0.75,("web_trap","Partner_Gateway"):0.70,
            # generic_trap
            ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
            ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
            ("generic_trap","Executive_Host"):0.70,("generic_trap","Partner_Gateway"):0.65,
            # ftp_trap
            ("ftp_trap","HR_workstation"):0.60,("ftp_trap","DevOps_server"):0.75,
            ("ftp_trap","Finance_DB"):0.55,("ftp_trap","Generic_Linux"):0.80,
            ("ftp_trap","Executive_Host"):0.40,("ftp_trap","Partner_Gateway"):0.85,
            # rdp_trap
            ("rdp_trap","HR_workstation"):0.90,("rdp_trap","DevOps_server"):0.80,
            ("rdp_trap","Finance_DB"):0.65,("rdp_trap","Generic_Linux"):0.55,
            ("rdp_trap","Executive_Host"):0.95,("rdp_trap","Partner_Gateway"):0.60,
            # mail_trap
            ("mail_trap","HR_workstation"):0.95,("mail_trap","DevOps_server"):0.65,
            ("mail_trap","Finance_DB"):0.70,("mail_trap","Generic_Linux"):0.50,
            ("mail_trap","Executive_Host"):0.90,("mail_trap","Partner_Gateway"):0.80,
            # api_trap
            ("api_trap","HR_workstation"):0.50,("api_trap","DevOps_server"):0.95,
            ("api_trap","Finance_DB"):0.70,("api_trap","Generic_Linux"):0.75,
            ("api_trap","Executive_Host"):0.55,("api_trap","Partner_Gateway"):0.85,
        },
        "stix_signals":[
            {"confidence":0.88,"threat_class":"financial",
             "deltas":{"Finance_DB":+0.20,"HR_workstation":+0.12,"Executive_Host":+0.08,
                       "DevOps_server":-0.04,"Generic_Linux":-0.04,"Partner_Gateway":-0.02}},
            {"confidence":0.45,"threat_class":"espionage",
             "deltas":{"DevOps_server":+0.15,"Generic_Linux":+0.10,"Partner_Gateway":+0.05,
                       "Finance_DB":-0.04,"HR_workstation":-0.03,"Executive_Host":-0.02}},
            {"confidence":0.30,"threat_class":"recon",
             "deltas":{"Generic_Linux":+0.10,"Partner_Gateway":+0.08,"HR_workstation":+0.04,
                       "Finance_DB":-0.03,"DevOps_server":-0.03,"Executive_Host":-0.02}},
        ],
        "empirical_interactions":{"Finance_DB":25,"HR_workstation":18,"Executive_Host":12,
                                   "DevOps_server":10,"Partner_Gateway":7,"Generic_Linux":4},
    },
}


# ─────────────────────────────────────────────────────────────────────────────
#  VALIDATE SCALE SELECTION
# ─────────────────────────────────────────────────────────────────────────────

assert NETWORK_SCALE in _SCALE_DEFS, (
    f"Unknown NETWORK_SCALE={NETWORK_SCALE!r}. "
    f"Valid: {list(_SCALE_DEFS.keys())}"
)
_S = _SCALE_DEFS[NETWORK_SCALE]


# ─────────────────────────────────────────────────────────────────────────────
#  ACTIVE INSTANCE  ── extracted from selected scale
# ─────────────────────────────────────────────────────────────────────────────

K = _S["K"]
Z = _S["Z"]
H = _S["H"]
P = _S["P"]
G = _S["G"]
Theta = _S["Theta"]

A_per_zone = _S["A_per_zone"]
A_total    = sum(A_per_zone.values())

I2             = _S["I2"]
C_conflicts    = _S["C_conflicts"]
diamond_affinity = _S["diamond_affinity"]

tau_d0  = _S["tau_d0"]
tau_dp0 = _S["tau_dp0"]
Delta   = _S["Delta"]
Delta_p = _S["Delta_p"]

B_global = _S["B_global"]
B_zone   = _S["B_zone"]

stix_signals           = _S["stix_signals"]
empirical_interactions = _S["empirical_interactions"]

GK_scores = _S["GK_scores"]

# ─────────────────────────────────────────────────────────────────────────────
#  SHARED PARAMETERS  ── identical across all scales (physics of the model)
# ─────────────────────────────────────────────────────────────────────────────

# ATT&CK techniques (full set; traps use subsets)
T = [
    "T1021","T1048","T1078","T1083","T1046","T1110","T1566","T1190",
    "T1041","T1059","T1053","T1055","T1133","T1203","T1547","T1572",
    "T1213","T1068",
]

w_technique = {
    "T1021":0.80,"T1048":1.40,"T1078":1.00,"T1083":0.60,"T1046":0.70,
    "T1110":0.90,"T1566":1.20,"T1190":1.10,"T1041":1.30,"T1059":0.75,
    "T1053":0.65,"T1055":0.85,"T1133":0.95,"T1203":0.80,"T1547":0.70,
    "T1572":1.35,"T1213":1.00,"T1068":0.90,
}

sigma = {
    "T1021":0.40,"T1048":0.90,"T1078":0.70,"T1083":0.30,"T1046":0.50,
    "T1110":0.60,"T1566":0.80,"T1190":0.70,"T1041":0.85,"T1059":0.40,
    "T1053":0.50,"T1055":0.60,"T1133":0.75,"T1203":0.55,"T1547":0.50,
    "T1572":0.90,"T1213":0.60,"T1068":0.70,
}

cost_per_type = {
    "ssh_trap":0.80,"db_trap":1.20,"smb_trap":0.90,"scada_trap":2.00,
    "ad_trap":1.50,"dns_trap":0.70,"web_trap":1.00,"generic_trap":0.50,
    "ftp_trap":0.60,"rdp_trap":0.85,"mail_trap":0.65,"api_trap":0.75,
}

cost_zone_multiplier = {
    "DMZ":1.0,"Internal":1.0,"Cloud":0.9,"OT":1.5,
    "Mgmt":1.1,"Dev":0.95,"Partner":1.2,
}

dm_range   = (0.80, 2.50)
hd_by_zone = {"DMZ":1,"Internal":2,"Cloud":2,"OT":3,"Mgmt":2,"Dev":2,"Partner":2}

tactic_families = {
    "LateralMovement": ["T1021","T1078"],
    "Exfiltration":    ["T1048","T1041"],
    "Discovery":       ["T1083","T1046"],
    "CredentialAccess":["T1110"],
    "InitialAccess":   ["T1566","T1190","T1133","T1203"],
    "Execution":       ["T1059","T1053","T1547"],
    "DefenseEvasion":  ["T1055","T1068"],
    "CmdAndControl":   ["T1572","T1213"],
}

# Trap → techniques mapping (superset; subsets apply per scale)
trap_techniques = {
    "ssh_trap":     ["T1021","T1078","T1059"],
    "db_trap":      ["T1048","T1213","T1083"],
    "smb_trap":     ["T1021","T1046","T1055"],
    "scada_trap":   ["T1059","T1053","T1203"],
    "ad_trap":      ["T1110","T1078","T1547"],
    "dns_trap":     ["T1572","T1041","T1046"],
    "web_trap":     ["T1190","T1566","T1133"],
    "generic_trap": ["T1046","T1068","T1213"],
    "ftp_trap":     ["T1048","T1059","T1041"],
    "rdp_trap":     ["T1021","T1078","T1055"],
    "mail_trap":    ["T1566","T1078","T1133"],
    "api_trap":     ["T1190","T1572","T1213"],
}

q_initial = {p: 1.0/len(P) for p in P}   # uniform prior, always normalised to |P|

rho_max = 1.0
tau_GK  = 0.65

# V4 gap-resolution
gamma     = 0.80
beta_max  = 0.60
kappa     = 30.0
h_min     = 24.0
kappa_min = 12.0

# V5 gap-resolution
rho_decay = 0.50
Delta_N   = 3

# Soft-clause geometric weights (Section E, eqs 6–11)
w1     = 1
w2     = 10
w2_fam = 12
w3     = 100
w3_bwd = 70
w4     = 1000

# Solver runtime
solver_backend = "g4"
random_seed    = 42
weight_scale   = 1

# ─────────────────────────────────────────────────────────────────────────────
#  PRECONDITION CHECKS  (run at import time for every scale)
# ─────────────────────────────────────────────────────────────────────────────

tau_GK = 0.65

def gk_admitted(trap, persona):
    """Return True if (trap, persona) passes GK plausibility check (eq 14)."""
    return GK_scores.get((trap, persona), 0.0) >= tau_GK

# C8/C13: Delta >= ceil(H / tau_dp0) - 1
_c813_req = _math.ceil(H / tau_dp0) - 1
assert Delta >= _c813_req, (
    f"[{NETWORK_SCALE}] C8/C13 INFEASIBLE: Delta={Delta} < "
    f"ceil({H}/{tau_dp0})-1={_c813_req}. Raise Delta or tau_dp0."
)

# C15: h_min >= kappa_min
assert h_min >= kappa_min, (
    f"C15 VIOLATION: h_min={h_min}h < kappa_min={kappa_min}h."
)

# ─────────────────────────────────────────────────────────────────────────────
#  MASTER CFG DICT
# ─────────────────────────────────────────────────────────────────────────────

CFG = {
    # ── Scale identifier ──────────────────────────────────────────────────
    "SCALE":                NETWORK_SCALE,

    # ── Structural sets ───────────────────────────────────────────────────
    "K":                    K,
    "T":                    T,
    "Z":                    Z,
    "P":                    P,
    "A_per_zone":           A_per_zone,
    "A_total":              A_total,

    # ── Attack paths ─────────────────────────────────────────────────────
    "G":                    G,

    # ── Conflict / affinity / air-gaps ───────────────────────────────────
    "C_conflicts":          C_conflicts,
    "I2":                   I2,
    "diamond_affinity":     diamond_affinity,

    # ── Technique weights and stealth ─────────────────────────────────────
    "w":                    w_technique,
    "sigma":                sigma,

    # ── Costs and budgets ────────────────────────────────────────────────
    "cost_per_type":        cost_per_type,
    "cost_zone_multiplier": cost_zone_multiplier,
    "B":                    B_global,
    "B2":                   B_zone,

    # ── Asset parameters ─────────────────────────────────────────────────
    "dm_range":             dm_range,
    "hd_by_zone":           hd_by_zone,

    # ── Tactic families and trap→technique map ───────────────────────────
    "tactic_families":      tactic_families,
    "trap_techniques":      trap_techniques,

    # ── Planning horizon ──────────────────────────────────────────────────
    "H":                    H,

    # ── GK role-compatibility ─────────────────────────────────────────────
    "GK_scores":            GK_scores,
    "gk_admitted":          gk_admitted,
    "tau_GK":               tau_GK,

    # ── Discovery thresholds ──────────────────────────────────────────────
    "tau_d0":               tau_d0,
    "tau_dp0":              tau_dp0,
    "rho_max":              rho_max,

    # ── Churn budgets ─────────────────────────────────────────────────────
    "Delta":                Delta,
    "Delta_p":              Delta_p,

    # ── Persona priors and STIX/empirical data ───────────────────────────
    "q":                    q_initial,
    "stix_signals":         stix_signals,
    "empirical_interactions": empirical_interactions,

    # ── V4 parameters ────────────────────────────────────────────────────
    "gamma":                gamma,
    "beta_max":             beta_max,
    "kappa":                kappa,
    "h_min":                h_min,
    "kappa_min":            kappa_min,

    # ── V5 parameters ────────────────────────────────────────────────────
    "rho_decay":            rho_decay,
    "Delta_N":              Delta_N,

    # ── V6 scenario set ───────────────────────────────────────────────────
    "Theta":                Theta,

    # ── Soft-clause weights ───────────────────────────────────────────────
    "w1":                   w1,
    "w2":                   w2,
    "w2_fam":               w2_fam,
    "w3":                   w3,
    "w3_bwd":               w3_bwd,
    "w4":                   w4,

    # ── Solver runtime ────────────────────────────────────────────────────
    "solver_backend":       solver_backend,
    "random_seed":          random_seed,
    "weight_scale":         weight_scale,
}


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST  ── python config.py   or   ZSTP_SCALE=Large python config.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pv   = len(K)*len(Z)*H*len(P)
    soft = len(K)*A_total*len(T)*H*len(P)

    print("=" * 68)
    print(f"  ZSTP-V6 Config Self-Test  ──  Scale = {NETWORK_SCALE}")
    print("=" * 68)
    print(f"\n  Dimensions:")
    print(f"    |K| = {len(K):3d}  trap types   : {K}")
    print(f"    |Z| = {len(Z):3d}  zones        : {Z}")
    print(f"    H   = {H:3d}  slots")
    print(f"    |P| = {len(P):3d}  personas     : {P}")
    print(f"    |A| = {A_total:4d}  assets       : {dict(A_per_zone)}")
    print(f"    |G| = {len(G):3d}  attack paths : {[p['name'] for p in G]}")
    print(f"    |Θ| = {len(Theta):3d}  scenarios    : {[t['id'] for t in Theta]}")
    print(f"\n  Complexity:")
    print(f"    Primary vars  |K|·|Z|·H·|P| = {pv:,}")
    print(f"    Soft-clause DB ~ O(|K|·|A|·|T|·H·|P|) = {soft:,}")
    print(f"\n  Feasibility:")
    print(f"    C8/C13: Δ={Delta} ≥ ⌈H/τdp0⌉−1 = {_c813_req}  ✓")
    print(f"    C15:    h_min={h_min}h ≥ κ_min={kappa_min}h  ✓")
    print(f"\n  GK admitted pairs: "
          f"{sum(gk_admitted(tr,p) for tr in K for p in P)}/{len(K)*len(P)}"
          f"  (τ_GK={tau_GK})")
    print(f"\n  Weights: w4={w4} w3={w3} w3b={w3_bwd} "
          f"w2={w2} w2f={w2_fam} w1={w1}")
    print(f"\n  [✓] Scale '{NETWORK_SCALE}' — CFG ready for import.")
    print("=" * 68)
    print()
    print("  Quick-switch commands:")
    for s in ["Small","Medium","Large","XLarge","XXLarge"]:
        d = _SCALE_DEFS[s]
        pv2 = len(d['K'])*len(d['Z'])*d['H']*len(d['P'])
        marker = " ← active" if s == NETWORK_SCALE else ""
        print(f"    ZSTP_SCALE={s:<9s} python config.py   "
              f"|K|={len(d['K']):2d} |Z|={len(d['Z'])} H={d['H']:2d} "
              f"|P|={len(d['P'])} |A|={sum(d['A_per_zone'].values()):5d} "
              f"pv={pv2:,}{marker}")
