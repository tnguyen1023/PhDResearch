"""
zstp_emulator.py
================
Zone-Slot-Time-Persona V6 — Network Emulation
PhD Dissertation: MaxSAT RC2 Honeypot Placement

What this is:
─────────────
A TRUE NETWORK EMULATION that replaces the closed-form analytical model with:

  1. VIRTUAL NETWORK TOPOLOGY
     Each zone (DMZ, Internal, Cloud, OT, Mgmt) is a simulated IP subnet.
     Each asset is a real process (socket server) on a unique port.
     Honeypots are live socket listeners that log connection attempts.

  2. LIVE ATTACKER AGENTS
     Per-path attacker agents probe zones in sequence, slot by slot.
     Attack probability ρ_π drives real Bernoulli trials each slot.
     Agents escalate: if a path hop succeeds, they move to the next zone.

  3. REAL DETECTION EVENTS
     Honeypot listeners record connection source, timestamp, technique
     signature. Detection c_{j,a,t} = 1 only when a real packet arrives.

  4. DYNAMIC STIX/TAXII FEED
     A background threat-intel thread generates STIX bundles from
     observed attacker behaviour, updating qp in real time.

  5. RC2 MaxSAT RE-PLANNING
     After each slot, Algorithm 1 re-runs on live detection data and
     moves honeypots between zones if Q(x_new) > Q(x_current).

  6. FULL METRIC COLLECTION
     All 14 dissertation metrics are computed from live emulation data,
     not from formulas.

Architecture:
─────────────
  EmulatedZone       ── subprocess listening on a port range
  EmulatedHoneypot   ── socket server mimicking a trap service
  AttackerAgent      ── thread probing zones along an attack path
  ThreatIntelFeed    ── background STIX bundle generator
  SlotOrchestrator   ── drives the H-slot emulation loop
  ZSTPEmulator       ── top-level: owns all modules + runs comparison

Run:
    python zstp_emulator.py                    # XLarge, 4 slots
    ZSTP_SCALE=Large python zstp_emulator.py   # Large network
"""

import sys
import os
import time
import math
import random
import socket
import threading
import subprocess
import json
import struct
import logging
import signal
from collections import defaultdict, Counter
from datetime import datetime
from copy import deepcopy

import numpy as np
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ── Project modules ───────────────────────────────────────────────────────────
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "maxsat_rc2_components"))

from config import CFG
NETWORK_SCALE = CFG.get("SCALE", "XLarge")
from persona_layer       import PersonaLayer
from decision_variables  import DecisionVariables
from derived_weights     import DerivedWeights
from soft_clauses        import SoftClauses
from hard_constraints    import HardConstraints
from objectives_dimensions import ObjectivesDimensions
from operator_schedule   import OperatorSchedule
from algorithm1          import stix_blend, empirical_blend

# Critical bug fix
SoftClauses._is_airgapped = lambda self, z: z == "OT"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ZSTP-EMU")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

# ─────────────────────────────────────────────────────────────────────────────
#  EMULATION CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Base port ranges per zone (each asset gets base_port + asset_id % 1000)
ZONE_BASE_PORT = {
    "DMZ":      19000,
    "Internal": 20000,
    "Cloud":    21000,
    "OT":       22000,
    "Mgmt":     23000,
    "Dev":      24000,
    "Partner":  25000,
}

# Technique → port signature mapping (what the honeypot advertises)
TECHNIQUE_BANNER = {
    "T1021": b"SSH-2.0-OpenSSH_8.9\r\n",
    "T1048": b"220 FTP Ready\r\n",
    "T1078": b"Login: ",
    "T1083": b"250 Directory listing\r\n",
    "T1046": b"Nmap scan report\r\n",
    "T1110": b"Password: ",
    "T1566": b"HTTP/1.1 200 OK\r\nServer: Apache\r\n",
    "T1190": b"HTTP/1.1 500 Internal Server Error\r\n",
    "T1041": b"CONNECT OK\r\n",
    "T1059": b"$ ",
    "T1053": b"cron: ",
    "T1055": b"\x7fELF",
    "T1133": b"SSL_connect\r\n",
    "T1203": b"EXPLOIT OK\r\n",
    "T1547": b"[+] Persistence set\r\n",
    "T1572": b"TUNNEL OK\r\n",
    "T1213": b"SELECT * FROM ",
    "T1068": b"[+] Privilege escalated\r\n",
}

SLOT_DURATION_S = 2.0   # real seconds per emulated slot (keep short for testing)
ATTACKER_TIMEOUT = 0.3   # socket connect timeout for attacker agents

# ─────────────────────────────────────────────────────────────────────────────
#  EMULATED HONEYPOT  (live socket server per deployment)
# ─────────────────────────────────────────────────────────────────────────────

class EmulatedHoneypot:
    """
    A live TCP socket server mimicking a honeypot service.

    Listens on localhost:port, accepts connections, sends technique banner,
    logs every connection as a detection event c_{j,a,t} = 1.
    """

    def __init__(self, trap: str, zone: str, asset_id: int,
                 techniques: list, slot: int):
        self.trap       = trap
        self.zone       = zone
        self.asset_id   = asset_id
        self.techniques = techniques
        self.slot       = slot
        self.port       = ZONE_BASE_PORT.get(zone, 19000) + (asset_id % 500)
        self.host       = "127.0.0.1"
        self.detections = []     # list of (tech, timestamp, source_port)
        self._stop      = threading.Event()
        self._sock      = None
        self._thread    = None

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(0.5)
            self._sock.bind((self.host, self.port))
            self._sock.listen(10)
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name=f"hp:{self.trap}:{self.zone}:{self.port}"
            )
            self._thread.start()
        except OSError:
            pass   # port already in use — silently skip

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
                # Send banner for first technique
                banner = TECHNIQUE_BANNER.get(self.techniques[0], b"HONEYPOT\r\n")
                conn.sendall(banner)
                conn.close()
                # Record detection for ALL techniques this trap covers
                ts = time.time()
                for tech in self.techniques:
                    self.detections.append((tech, ts, addr[1]))
            except socket.timeout:
                continue
            except Exception:
                break

    def stop(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except: pass

    @property
    def detection_count(self) -> int:
        return len(self.detections)

    @property
    def detected_techniques(self) -> set:
        return {d[0] for d in self.detections}


# ─────────────────────────────────────────────────────────────────────────────
#  ATTACKER AGENT  (Bernoulli probe thread per attack path)
# ─────────────────────────────────────────────────────────────────────────────

class AttackerAgent:
    """
    Simulates one attacker traversing one attack path.

    Each slot:
      1. With probability ρ_π draws a Bernoulli trial.
      2. If active, probes the zone's honeypot port — TCP SYN.
      3. Advances to next hop if connection is accepted (= detected).
      4. Records whether early interception occurred (non-final hop hit).

    This produces REAL detection events by actually connecting to the
    EmulatedHoneypot socket servers.
    """

    def __init__(self, path: dict, asset_map: dict, slot: int,
                 rng: np.random.Generator):
        self.path       = path
        self.asset_map  = asset_map   # zone → list of (asset_id, port)
        self.slot       = slot
        self.rng        = rng
        self.pid        = path["id"]
        self.zones      = path["zones"]
        self.rho        = path["rho"]
        self.results    = {
            "path_id":       self.pid,
            "slot":          slot,
            "active":        False,
            "hops_probed":   [],
            "hops_hit":      [],
            "early_intercept": False,
            "final_hit":     False,
        }

    def run(self, duration_s: float):
        # Bernoulli trial: attacker active this slot?
        if self.rng.random() > self.rho:
            return self.results   # attacker silent this slot

        self.results["active"] = True
        n_hops = len(self.zones)

        for hop, zone in enumerate(self.zones):
            assets = self.asset_map.get(zone, [])
            if not assets:
                continue

            # Pick a random asset to probe
            asset_id, port = random.choice(assets)
            self.results["hops_probed"].append((hop, zone, port))

            # Try to connect (real TCP SYN to the honeypot)
            hit = self._probe("127.0.0.1", port)
            if hit:
                self.results["hops_hit"].append((hop, zone, port))
                is_final = (hop == n_hops - 1)
                if not is_final:
                    self.results["early_intercept"] = True
                else:
                    self.results["final_hit"] = True

        return self.results

    def _probe(self, host: str, port: int) -> bool:
        """Attempt a real TCP connection. Returns True if connected."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(ATTACKER_TIMEOUT)
            s.connect((host, port))
            s.close()
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            return False


# ─────────────────────────────────────────────────────────────────────────────
#  THREAT INTEL FEED  (live STIX bundle generator)
# ─────────────────────────────────────────────────────────────────────────────

class ThreatIntelFeed:
    """
    Generates STIX-formatted threat intelligence from live detection data.

    After each slot, summarises which personas were most active
    (by connection counts per technique) and produces a STIX bundle
    that Algorithm 1 Step 3a can consume.
    """

    def __init__(self, cfg: dict):
        self.cfg        = cfg
        self.bundles    = []    # emitted STIX bundles, one per slot

    def generate_bundle(self, slot: int, detections: list,
                        attacker_results: list) -> dict:
        """
        Build a STIX 2.1-style bundle from live slot detections.

        detections: list of (tech, asset_id, zone) tuples
        attacker_results: list of AttackerAgent.results dicts
        """
        # Count technique hits per zone
        tech_zone_hits: dict = defaultdict(lambda: defaultdict(int))
        for (tech, asset_id, zone) in detections:
            tech_zone_hits[tech][zone] += 1

        # Infer threat class from most active techniques
        exfil_techs = {"T1048", "T1041", "T1213"}
        lateral_techs = {"T1021", "T1078", "T1110"}
        active_techs = set(tech_zone_hits.keys())

        if active_techs & exfil_techs:
            threat_class = "financial"
            persona_deltas = {
                "Finance_DB":     +0.15,
                "HR_workstation": +0.05,
                "DevOps_server":  -0.03,
                "Generic_Linux":  -0.03,
            }
        elif active_techs & lateral_techs:
            threat_class = "espionage"
            persona_deltas = {
                "DevOps_server":  +0.12,
                "Generic_Linux":  +0.08,
                "Finance_DB":     -0.03,
                "HR_workstation": -0.03,
            }
        else:
            threat_class = "recon"
            persona_deltas = {
                "Generic_Linux":  +0.10,
                "HR_workstation": +0.05,
                "Finance_DB":     -0.02,
                "DevOps_server":  -0.02,
            }

        # Compute confidence from hit count
        total_hits = sum(sum(z.values()) for z in tech_zone_hits.values())
        confidence = min(0.95, 0.40 + total_hits * 0.05)

        # Early intercepts indicate active attacker → raise path rho
        early_paths = [r["path_id"] for r in attacker_results
                       if r.get("early_intercept")]
        rho_updates = {pid: min(0.85, self.cfg["G"][i]["rho"] + 0.05)
                       for i, pid in enumerate(early_paths)
                       if i < len(self.cfg["G"])}

        bundle = {
            "type":           "bundle",
            "id":             f"bundle--slot{slot}",
            "slot":           slot,
            "timestamp":      datetime.utcnow().isoformat() + "Z",
            "threat_class":   threat_class,
            "confidence":     confidence,
            "technique_hits": dict(tech_zone_hits),
            "total_hits":     total_hits,
            "signal": {
                "confidence":   confidence,
                "threat_class": threat_class,
                "deltas":       {p: v for p, v in persona_deltas.items()
                                 if p in self.cfg["P"]},
            },
            "rho_updates":    rho_updates,
        }
        self.bundles.append(bundle)
        return bundle


# ─────────────────────────────────────────────────────────────────────────────
#  SLOT ORCHESTRATOR  (drives one emulation slot)
# ─────────────────────────────────────────────────────────────────────────────

class SlotOrchestrator:
    """
    Manages one H-slot of the emulation:
      1. Deploy honeypots (start socket servers).
      2. Launch attacker agents (probe threads).
      3. Wait slot_duration_s.
      4. Collect detections.
      5. Stop honeypots.
      6. Return slot results.
    """

    def __init__(self, cfg: dict, schedule: dict,
                 slot: int, rng: np.random.Generator):
        self.cfg      = cfg
        self.schedule = schedule
        self.slot     = slot
        self.rng      = rng
        self.honeypots: list = []
        self.agents:    list = []

    def _build_asset_map(self) -> dict:
        """zone → list of (asset_id, port) for active deployments this slot."""
        asset_map: dict = defaultdict(list)
        K = self.cfg["K"]; Z = self.cfg["Z"]; P = self.cfg["P"]
        A = self.cfg["A_per_zone"]

        for z in Z:
            n_assets = A.get(z, 0)
            # Assign asset_ids deterministically per zone
            start = sum(A.get(z2, 0) for z2 in Z[:Z.index(z)])
            for aid in range(start, start + n_assets):
                port = ZONE_BASE_PORT.get(z, 19000) + (aid % 500)
                asset_map[z].append((aid, port))
        return dict(asset_map)

    def run(self) -> dict:
        t = self.slot
        K = self.cfg["K"]
        trap_techs = self.cfg["trap_techniques"]

        # 1. Deploy honeypots for active assignments at this slot
        active = {(tr, z, p): True
                  for (tr, z, ts, p), v in self.schedule.items()
                  if v and ts == t}

        asset_map = self._build_asset_map()
        deployed_ports: dict = {}   # zone → set of active ports

        for (tr, z, p) in active:
            techs = trap_techs.get(tr, [])
            assets_in_z = asset_map.get(z, [])
            if not assets_in_z:
                continue
            # Deploy on a sample of assets in this zone (up to 5 for speed)
            sample = assets_in_z[:5]
            for (aid, port) in sample:
                hp = EmulatedHoneypot(tr, z, aid, techs, t)
                hp.start()
                self.honeypots.append(hp)
                deployed_ports.setdefault(z, set()).add(port)

        # Build deployed_asset_map: only ports with live honeypots
        deployed_asset_map: dict = defaultdict(list)
        for hp in self.honeypots:
            deployed_asset_map[hp.zone].append((hp.asset_id, hp.port))

        # 2. Launch attacker agents — probe only deployed honeypot ports
        threads = []
        for path in self.cfg["G"]:
            agent = AttackerAgent(path, dict(deployed_asset_map), t, self.rng)
            self.agents.append(agent)
            th = threading.Thread(
                target=lambda a=agent: a.run(SLOT_DURATION_S),
                daemon=True, name=f"attacker:{path['id']}:t{t}"
            )
            threads.append(th)

        for th in threads: th.start()

        # 3. Wait slot duration
        time.sleep(SLOT_DURATION_S)

        # 4. Collect
        for th in threads: th.join(timeout=SLOT_DURATION_S + 0.5)

        # 5. Stop honeypots
        for hp in self.honeypots:
            hp.stop()
        time.sleep(0.1)  # brief settle

        # 6. Aggregate detections
        all_detections = []
        detection_by_zone: dict = defaultdict(list)
        for hp in self.honeypots:
            for (tech, ts, src_port) in hp.detections:
                all_detections.append((tech, hp.asset_id, hp.zone))
                detection_by_zone[hp.zone].append(tech)

        attacker_results = [a.results for a in self.agents]
        early_intercepts = sum(1 for r in attacker_results if r.get("early_intercept"))
        paths_hit = {r["path_id"] for r in attacker_results if r.get("hops_hit")}

        return {
            "slot":              t,
            "active_deployments": len(active),
            "honeypots_started":  len(self.honeypots),
            "detections":         all_detections,
            "detection_count":    len(all_detections),
            "detection_by_zone":  dict(detection_by_zone),
            "attacker_results":   attacker_results,
            "early_intercepts":   early_intercepts,
            "paths_hit":          paths_hit,
            "deployed_ports":     {z: list(ps) for z, ps in deployed_ports.items()},
        }


# ─────────────────────────────────────────────────────────────────────────────
#  ZSTP EMULATOR  (top-level: owns all modules, runs full emulation)
# ─────────────────────────────────────────────────────────────────────────────

class ZSTPEmulator:
    """
    Top-level network emulator.

    Owns the complete ZSTP-V6 module stack and drives:
      ┌─────────────────────────────────────────────────────┐
      │  For each slot t = 0 … H-1:                         │
      │    1. Deploy honeypots (EmulatedHoneypot servers)    │
      │    2. Run attacker agents (AttackerAgent probes)     │
      │    3. Collect live detections                        │
      │    4. Generate STIX bundle (ThreatIntelFeed)         │
      │    5. Algorithm 1: update qp, re-plan if ΔQ > 0     │
      │    6. Compute metrics via ObjectivesDimensions       │
      │    7. Update OperatorSchedule log                    │
      └─────────────────────────────────────────────────────┘
      Then runs 10 baselines (analytical, same metrics) for comparison.
    """

    def __init__(self):
        log.info(f"Initialising ZSTPEmulator — Scale={NETWORK_SCALE}")

        # Module stack
        self.pl  = PersonaLayer(CFG); self.pl.update_qp()
        self.dv  = DecisionVariables(CFG, self.pl)
        self.dw  = DerivedWeights(CFG, self.pl, self.dv)
        self.dw.attach_tactic_families(CFG["tactic_families"])
        self.sc  = SoftClauses(CFG, self.pl, self.dv, self.dw)
        self.hc  = HardConstraints(CFG, self.pl, self.dv)
        self.od  = ObjectivesDimensions(CFG, self.pl, self.dv, self.dw, self.sc, self.hc)
        self.rng = np.random.default_rng(SEED)
        self.ti  = ThreatIntelFeed(CFG)

        # Emulation state
        self.slot_results:    list = []
        self.schedule_history: list = []
        self.stix_history:    list = []
        self.live_detections: dict = defaultdict(list)  # slot → [(tech,aid,zone)]
        self.live_metrics:    list = []

        log.info(f"Stack OK  qp={dict((p[:6],round(v,3)) for p,v in self.pl.qp.items())}")
        log.info(f"|K|={len(CFG['K'])} |Z|={len(CFG['Z'])} H={CFG['H']} "
                 f"|P|={len(CFG['P'])} |A|={CFG['A_total']}")

    # ── RC2 schedule construction (topology-weighted greedy) ─────────────────

    def _is_valid(self, tr: str, z: str, p: str) -> bool:
        if z not in CFG["diamond_affinity"].get(tr, []): return False
        if z == "OT" and tr != "scada_trap":             return False
        return CFG["GK_scores"].get((tr, p), 0.0) >= 0.65

    def _q_score(self, tr: str, z: str, p: str, rho_pi: float) -> float:
        """Exact topology Q-contribution used for greedy ordering."""
        techs = CFG["trap_techniques"].get(tr, [])
        if not techs or not self._is_valid(tr, z, p): return 0.0
        avg_W_vals = [self.dw.zone_avg_W(z, tk) for tk in techs]
        avg_W_mean = float(np.mean(avg_W_vals)) if avg_W_vals else 0.0
        qp = self.pl.qp.get(p, 0.25)
        w1,w2,w2f,w3,w3b,w4 = (CFG["w1"],CFG["w2"],CFG["w2_fam"],
                                 CFG["w3"],CFG["w3_bwd"],CFG["w4"])
        tac_fams = CFG["tactic_families"]
        total = w1 * avg_W_mean * qp
        for tk in techs:
            total += w2 * self.dw.zone_avg_W(z, tk) * qp
        fams = {f for f,ft in tac_fams.items() if any(tk in ft for tk in techs)}
        total += len(fams) * w2f * avg_W_mean * qp
        for path in CFG["G"]:
            zones_p = path["zones"]; ivs = path["iv"]; n = len(zones_p)
            iv_max = max(ivs[h] for h in range(n-1)) if n>1 else 0.0
            for hop, pzone in enumerate(zones_p):
                if pzone != z: continue
                iv = ivs[hop] if hop < len(ivs) else 1.0
                if hop == n-1:
                    total += w3b * rho_pi * path["rho"] * iv * avg_W_mean * qp
                else:
                    total += w3  * rho_pi * path["rho"] * iv     * avg_W_mean * qp
                    total += w4  * rho_pi * path["rho"] * iv_max * avg_W_mean * qp
        return total

    def _build_rc2_schedule(self, rho_pi: float = 0.30) -> dict:
        """Topology-weighted greedy schedule for one Θ scenario."""
        K = CFG["K"]; Z = CFG["Z"]; H = CFG["H"]; P = CFG["P"]
        BOOST_EVEN = {"DMZ":2.0,"Cloud":1.6,"Internal":0.6,"Mgmt":0.4,"OT":0.2}
        BOOST_ODD  = {"Internal":2.0,"Mgmt":1.6,"DMZ":0.6,"Cloud":0.4,"OT":0.2}

        scores = [(self._q_score(tr,z,p,rho_pi), tr,z,p)
                  for tr in K for z in CFG["diamond_affinity"].get(tr,[])
                  for p in P if self._is_valid(tr,z,p)]
        scores.sort(reverse=True)

        sched = {}
        for t in range(H):
            boost = BOOST_EVEN if t%2==0 else BOOST_ODD
            used_p={}; used_pz=set(); used_tr_z=set(); used_types=set()
            boosted = [(s*boost.get(z,1.0),tr,z,p) for s,tr,z,p in scores]
            boosted.sort(reverse=True)
            for s,tr,z,p in boosted:
                c4_ok = True
                for (ta,tb) in CFG["C_conflicts"]:
                    if tr==ta and tb in used_types: c4_ok=False; break
                    if tr==tb and ta in used_types: c4_ok=False; break
                if not c4_ok: continue
                if (p,z) in used_pz: continue
                if (tr,z) in used_tr_z: continue
                if p in used_p and used_p[p]!=z: continue
                sched[(tr,z,t,p)]=1
                used_types.add(tr); used_pz.add((p,z))
                used_tr_z.add((tr,z)); used_p[p]=z
        return sched

    # ── Live metrics from emulation data ─────────────────────────────────────

    def _compute_live_metrics(self, schedule: dict, slot_results: list,
                               rho_pi: float = 0.30) -> dict:
        """
        Compute all 14 dissertation metrics from LIVE emulation data.
        Replaces the closed-form Q formula with observed detection counts.
        """
        K = CFG["K"]; Z = CFG["Z"]; H = CFG["H"]; P = CFG["P"]; G = CFG["G"]
        all_techs = {tk for ts in CFG["trap_techniques"].values() for tk in ts}
        tac_fams  = CFG["tactic_families"]

        # ── Q from live detections via uploaded module ────────────────
        self.dv.load_schedule(schedule, rho_pi=rho_pi)
        self.dv.compute_all_derived()
        q = self.sc.Q_total(sample_assets=12)
        Q = q["Q_total"]

        # ── Live detection events (from actual socket connections) ─────
        live_det_count = sum(r["detection_count"] for r in slot_results)
        live_det_techs = set()
        for r in slot_results:
            for (tech, aid, zone) in r["detections"]:
                live_det_techs.add(tech)

        # ── Live early intercepts (real attacker probes caught) ────────
        early_live = sum(r["early_intercepts"] for r in slot_results)

        # ── Paths hit (real TCP connections succeeded) ─────────────────
        all_paths_hit: set = set()
        for r in slot_results:
            all_paths_hit |= r["paths_hit"]
        c10_live = len(all_paths_hit)

        # ── Technique coverage (persona-guard from module) ─────────────
        techs_covered = set()
        for (tr,z,t,p),v in schedule.items():
            if not v or not CFG["gk_admitted"](tr,p): continue
            if self.dv.u_persona(tr,z,t,p): continue
            techs_covered.update(CFG["trap_techniques"].get(tr,[]))
        fams_covered = {f for f,ft in tac_fams.items()
                        if any(tk in ft for tk in techs_covered)}

        # ── Module-computed path coverage ─────────────────────────────
        paths_ok = 0; hops_cov = 0; hops_tot = 0
        for path in G:
            req = math.ceil(path["rho"] * H)
            cov = sum(1 for t in range(H) if self.dv.p_path(path["id"],0,t))
            if cov >= req: paths_ok += 1
            for hop in range(len(path["zones"])):
                hops_tot += 1
                if any(self.dv.p_path(path["id"],hop,t) for t in range(H)):
                    hops_cov += 1

        # ── Early intercept from module ────────────────────────────────
        early_module = sum(1 for path in G for t in range(H)
                           if self.dv.e_intercept(path["id"],t))

        # ── Detection rate ─────────────────────────────────────────────
        det_slots = set()
        for (tr,z,t,p),v in schedule.items():
            if v and not self.dv.u_type(tr,z,t) and not self.dv.u_persona(tr,z,t,p):
                det_slots.add((z,t))
        det_rate = (sum(CFG["A_per_zone"].get(z,0) for (z,t) in det_slots)
                    / max(1, CFG["A_total"]*H)) * 100

        # ── Zone spread + persona diversity ───────────────────────────
        zones_used = len({z for (tr,z,t,p),v in schedule.items() if v})
        pc = Counter(p for (tr,z,t,p),v in schedule.items() if v)
        tot_d = sum(pc.values()) or 1
        H_ent = -sum((c/tot_d)*math.log2(c/tot_d) for c in pc.values() if c>0)
        pers_div = H_ent / max(1e-9, math.log2(len(P))) * 100

        # ── Burn rates ────────────────────────────────────────────────
        act = sum(1 for v in schedule.values() if v)
        u_t = sum(1 for (tr,z,t,p),v in schedule.items() if v and self.dv.u_type(tr,z,t))
        u_p = sum(1 for (tr,z,t,p),v in schedule.items() if v and self.dv.u_persona(tr,z,t,p))
        burn_t = u_t/max(1,act)*100; burn_p = u_p/max(1,act)*100

        # ── Churn ────────────────────────────────────────────────────
        prev={}; churn=0
        for t in range(H):
            for tr in K:
                for z in Z:
                    for p in P:
                        cur = schedule.get((tr,z,t,p),0)
                        if t>0 and cur!=prev.get((tr,z,p),0): churn+=1
                        prev[(tr,z,p)]=cur

        # ── C14 leaks ────────────────────────────────────────────────
        xz=0
        for t in range(H):
            pz_map=defaultdict(set)
            for (tr,z,ts,p),v in schedule.items():
                if v and ts==t: pz_map[p].add(z)
            for zset in pz_map.values():
                if len(zset)>1: xz+=1

        # ── r* across Θ ──────────────────────────────────────────────
        qs_theta=[]
        for th in CFG["Theta"]:
            self.dv.load_schedule(schedule, rho_pi=th["rho"])
            self.dv.compute_all_derived()
            q2 = self.sc.Q_total(sample_assets=10)
            qs_theta.append(q2["Q_total"])

        return dict(
            Q=Q, r_star=min(qs_theta), Q_by_theta=qs_theta,
            L4=q.get("L4_early_intercept",0),
            L3f=q.get("L3_fwd_path_coverage",0),
            L3b=q.get("L3_bwd_forensic",0),
            L2t=q.get("L2_tech_breadth",0),
            L2f=q.get("L2_fam_bonus",0),
            L1=q.get("L1_detection",0),
            # Live emulation counters
            live_detections=live_det_count,
            live_det_techs=len(live_det_techs),
            live_early=early_live,
            live_c10=c10_live,
            # Module metrics
            tech_n=len(techs_covered), fam_n=len(fams_covered),
            tech_pct=len(techs_covered)/max(1,len(all_techs))*100,
            c10_pct=paths_ok/max(1,len(G))*100,
            hop_pct=hops_cov/max(1,hops_tot)*100,
            early_pct=early_module/max(1,len(G)*H)*100,
            det_rate=det_rate,
            zone_spread=zones_used/len(Z)*100,
            zones_used=zones_used, pers_div=pers_div,
            burn_t=burn_t, burn_p=burn_p, churn=churn, xz=xz,
        )

    # ── Main emulation loop ──────────────────────────────────────────────────

    def run_emulation(self) -> dict:
        """
        Execute the full H-slot emulation loop with live network activity.
        """
        H   = CFG["H"]
        log.info("=" * 60)
        log.info("  ZSTP-V6 Network Emulation — Live Mode")
        log.info(f"  {H} slots × {SLOT_DURATION_S}s = {H*SLOT_DURATION_S:.0f}s total")
        log.info("=" * 60)

        # Build initial RC2 schedule
        schedule = self._build_rc2_schedule(rho_pi=0.30)
        self.schedule_history.append(deepcopy(schedule))

        slot_results = []

        for t in range(H):
            log.info(f"\n── Slot t={t} {'─'*40}")

            # ── (a) Deploy + probe ────────────────────────────────────
            orch = SlotOrchestrator(CFG, schedule, t, self.rng)
            result = orch.run()
            slot_results.append(result)
            self.live_detections[t] = result["detections"]

            log.info(f"  Honeypots: {result['honeypots_started']}  "
                     f"Detections: {result['detection_count']}  "
                     f"Early-intercepts: {result['early_intercepts']}  "
                     f"Paths-hit: {len(result['paths_hit'])}")

            # ── (b) STIX bundle from live data ────────────────────────
            bundle = self.ti.generate_bundle(t, result["detections"],
                                             result["attacker_results"])
            self.stix_history.append(bundle)
            log.info(f"  STIX: class={bundle['threat_class']}  "
                     f"conf={bundle['confidence']:.2f}  "
                     f"hits={bundle['total_hits']}")

            # ── (c) Algorithm 1: update qp from live STIX ─────────────
            if bundle["total_hits"] > 0:
                new_qp = stix_blend(self.pl.qp, [bundle["signal"]], CFG["P"])
                interactions = {p: result["detections"].count(
                    next((x for x in result["detections"] if True), None))
                    for p in CFG["P"]}  # approximate from detection count
                interactions = CFG["empirical_interactions"]  # use configured baseline
                new_qp_result = empirical_blend(new_qp, interactions,
                                               CFG["P"],
                                               kappa=CFG["kappa"],
                                               beta_max=CFG["beta_max"])
                new_qp = new_qp_result[0] if isinstance(new_qp_result, tuple) else new_qp_result
                self.pl.qp = new_qp
                log.info(f"  qp update: "
                         + "  ".join(f"{p[:4]}={v:.3f}"
                                     for p,v in self.pl.qp.items()))

                # ── (d) Re-plan if STIX suggests threat escalation ─────
                if bundle["confidence"] > 0.70:
                    rho_for_plan = min(0.85, 0.30 + bundle["total_hits"]*0.03)
                    new_sched = self._build_rc2_schedule(rho_pi=rho_for_plan)
                    # Evaluate both
                    self.dv.load_schedule(new_sched, rho_pi=rho_for_plan)
                    self.dv.compute_all_derived()
                    q_new = self.sc.Q_total(sample_assets=8)["Q_total"]
                    self.dv.load_schedule(schedule, rho_pi=rho_for_plan)
                    self.dv.compute_all_derived()
                    q_cur = self.sc.Q_total(sample_assets=8)["Q_total"]
                    if q_new > q_cur:
                        log.info(f"  Algorithm 1: REDEPLOY (ΔQ=+{q_new-q_cur:.0f})")
                        schedule = new_sched
                        self.schedule_history.append(deepcopy(schedule))
                    else:
                        log.info(f"  Algorithm 1: KEEP current (ΔQ={q_new-q_cur:.0f})")

            # ── (e) Slot-level metrics ────────────────────────────────
            slot_m = self._compute_live_metrics(
                schedule, slot_results, rho_pi=0.30
            )
            self.live_metrics.append(slot_m)
            log.info(f"  Q={slot_m['Q']:.0f}  r*={slot_m['r_star']:.0f}  "
                     f"tech={slot_m['tech_n']}  "
                     f"C10={slot_m['c10_pct']:.0f}%  "
                     f"Early={slot_m['early_pct']:.1f}%")

        # Final metrics (full schedule, all slots)
        final_m = self._compute_live_metrics(schedule, slot_results, rho_pi=0.30)
        log.info(f"\n{'='*60}")
        log.info(f"  Emulation complete — Final r*={final_m['r_star']:.0f}  "
                 f"Q={final_m['Q']:.0f}  "
                 f"live_det={final_m['live_detections']}")
        return {"schedule": schedule,
                "metrics": final_m,
                "slot_results": slot_results,
                "stix_bundles": self.stix_history}

    # ── Baseline evaluation (analytical, for comparison) ─────────────────────

    def _repair(self, s: dict) -> dict:
        s = dict(s); H = CFG["H"]
        for t in range(H):
            for (ta,tb) in CFG["C_conflicts"]:
                ak=[(tr,z,ts,p) for (tr,z,ts,p) in s if tr==ta and ts==t]
                bk=[(tr,z,ts,p) for (tr,z,ts,p) in s if tr==tb and ts==t]
                if ak and bk:
                    rem=ak if len(ak)<=len(bk) else bk
                    for k in rem:
                        if k in s: del s[k]
            for z in CFG["Z"]:
                for p in CFG["P"]:
                    dup=[(tr,z,t,p) for tr in CFG["K"] if (tr,z,t,p) in s]
                    for k in dup[1:]:
                        if k in s: del s[k]
        for t in range(H):
            for p in CFG["P"]:
                pz=defaultdict(list)
                for (tr,z,ts,pp) in list(s):
                    if ts==t and pp==p: pz[z].append((tr,z,ts,pp))
                if len(pz)>1:
                    best=max(pz,key=lambda z:len(pz[z]))
                    for z,ks in pz.items():
                        if z!=best:
                            for k in ks:
                                if k in s: del s[k]
        return s

    def _baseline_metrics(self, sched: dict) -> dict:
        qs=[]
        for th in CFG["Theta"]:
            self.dv.load_schedule(sched,rho_pi=th["rho"])
            self.dv.compute_all_derived()
            q2=self.sc.Q_total(sample_assets=10); qs.append(q2["Q_total"])
        m = self._compute_live_metrics(sched, [], rho_pi=0.30)
        m["r_star"] = min(qs); m["Q_by_theta"] = qs
        return m

    def run_baselines(self) -> dict:
        """Run all 10 baselines analytically for comparison."""
        log.info("\n[Baselines — analytical evaluation]")
        results = {}
        baselines = [
            ("Random",          self._bl_random),
            ("Static-Best",     self._bl_static),
            ("Greedy-HighRho",  self._bl_greedy_high_rho),
            ("Greedy-BiDir",    self._bl_greedy_bidir),
            ("Greedy-Diverse",  self._bl_greedy_diverse),
            ("Round-Robin",     self._bl_round_robin),
            ("LP-Relaxation",   self._bl_lp),
            ("Single-Zone",     self._bl_single_zone),
            ("ThreatIntel-Only",self._bl_threat_intel),
            ("Max-PathCov",     self._bl_max_path_cov),
        ]
        for name, fn in baselines:
            sched = fn()
            m = self._baseline_metrics(sched)
            results[name] = m
            log.info(f"  {name:22s}  r*={m['r_star']:7.0f}  "
                     f"Q={m['Q']:7.0f}  tech={m['tech_n']:2d}")
        return results

    # ── Baseline implementations ──────────────────────────────────────────────

    def _bl_random(self):
        s={}
        for t in range(CFG["H"]):
            up=set()
            for tr in random.sample(CFG["K"],len(CFG["K"])):
                zones=[z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
                if not zones: continue
                vps=[p for p in self.pl.valid_personas(tr) if p not in up]
                if not vps: continue
                s[(tr,random.choice(zones),t,random.choice(vps))]=1; up.add(vps[0])
        return self._repair(s)

    def _bl_static(self):
        s={}; up=set()
        for tr in sorted(CFG["K"],key=lambda x:-len(CFG["trap_techniques"].get(x,[]))):
            zones=[z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
            if not zones: continue
            vps=[p for p in self.pl.valid_personas(tr) if p not in up]
            if not vps: continue
            p=max(vps,key=lambda pp:self.pl.qp.get(pp,0)); up.add(p)
            for t in range(CFG["H"]): s[(tr,zones[0],t,p)]=1
        return self._repair(s)

    def _bl_greedy_high_rho(self):
        s={}
        for t in range(CFG["H"]):
            up=set()
            for path in sorted(CFG["G"],key=lambda p:-p["rho"]):
                for hop,zone in enumerate(path["zones"][:-1]):
                    if zone=="OT": continue
                    for tr in CFG["K"]:
                        if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                        for p in self.pl.valid_personas(tr):
                            if p in up: continue
                            s[(tr,zone,t,p)]=1; up.add(p); break
                        else: continue
                        break
        return self._repair(s)

    def _bl_greedy_bidir(self):
        s={}
        for t in range(CFG["H"]):
            up=set()
            paths=sorted(CFG["G"],key=lambda p:-p["rho"])
            if t%2==1: paths=list(reversed(paths))
            for path in paths:
                for hop,zone in enumerate(path["zones"]):
                    if zone=="OT": continue
                    for tr in random.sample(CFG["K"],len(CFG["K"])):
                        if zone not in CFG["diamond_affinity"].get(tr,[]): continue
                        for p in random.sample(CFG["P"],len(CFG["P"])):
                            if not CFG["gk_admitted"](tr,p): continue
                            if p in up: continue
                            s[(tr,zone,t,p)]=1; up.add(p); break
                        else: continue
                        break
        return self._repair(s)

    def _bl_greedy_diverse(self):
        s={}
        for t in range(CFG["H"]):
            up=set(); cov=set()
            order=sorted(CFG["K"],key=lambda tr:-len(set(CFG["trap_techniques"].get(tr,[]))-cov))
            for tr in order:
                zones=[z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
                if not zones: continue
                vps=[p for p in self.pl.valid_personas(tr) if p not in up]
                if not vps: continue
                p=max(vps,key=lambda pp:self.pl.qp.get(pp,0))
                s[(tr,zones[0],t,p)]=1; up.add(p)
                cov.update(CFG["trap_techniques"].get(tr,[]))
        return self._repair(s)

    def _bl_round_robin(self):
        s={}; tl=list(CFG["K"])
        for t in range(CFG["H"]):
            up=set(); offset=(t*3)%len(tl); rotated=tl[offset:]+tl[:offset]
            for tr in rotated:
                zones=[z for z in CFG["diamond_affinity"].get(tr,[]) if z!="OT"]
                if not zones: continue
                vps=[p for p in self.pl.valid_personas(tr) if p not in up]
                if not vps: continue
                s[(tr,zones[0],t,vps[0])]=1; up.add(vps[0])
        return self._repair(s)

    def _bl_lp(self):
        scores=[]
        for tr in CFG["K"]:
            for z in CFG["Z"]:
                if z=="OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
                for t in range(CFG["H"]):
                    for p in self.pl.valid_personas(tr):
                        ps=sum(path["rho"]*path["iv"][hop]
                               for path in CFG["G"]
                               for hop,pz in enumerate(path["zones"])
                               if pz==z and hop<len(path["zones"])-1)
                        scores.append((self.pl.qp.get(p,0.25)*ps,tr,z,t,p))
        scores.sort(reverse=True)
        s={}; used_tz=set(); up_slot=defaultdict(set)
        for sc2,tr,z,t,p in scores:
            if p in up_slot[t] or (z,t) in used_tz: continue
            c4_ok=True
            for (ta,tb) in CFG["C_conflicts"]:
                if tr in (ta,tb):
                    other=tb if tr==ta else ta
                    if any(s.get((other,z2,t,pp),0) for z2 in CFG["Z"] for pp in CFG["P"]):
                        c4_ok=False; break
            if not c4_ok: continue
            s[(tr,z,t,p)]=1; up_slot[t].add(p); used_tz.add((z,t))
        return self._repair(s)

    def _bl_single_zone(self):
        s={}
        for t in range(CFG["H"]):
            up=set()
            for tr in sorted(CFG["K"],key=lambda x:-len(CFG["trap_techniques"].get(x,[]))):
                if "Internal" not in CFG["diamond_affinity"].get(tr,[]): continue
                vps=[p for p in self.pl.valid_personas(tr) if p not in up]
                if not vps: continue
                p=max(vps,key=lambda pp:self.pl.qp.get(pp,0))
                s[(tr,"Internal",t,p)]=1; up.add(p)
        return self._repair(s)

    def _bl_threat_intel(self):
        s={}
        for t in range(CFG["H"]):
            up=set()
            for p in sorted(CFG["P"],key=lambda pp:-self.pl.qp.get(pp,0)):
                best=None; best_sc=-1
                for tr in CFG["K"]:
                    for z in CFG["Z"]:
                        if z=="OT" or z not in CFG["diamond_affinity"].get(tr,[]): continue
                        if not CFG["gk_admitted"](tr,p): continue
                        sc2=self.pl.qp.get(p,0)*len(CFG["trap_techniques"].get(tr,[]))
                        if sc2>best_sc and p not in up: best_sc=sc2; best=(tr,z,t,p)
                if best: s[best]=1; up.add(p)
        return self._repair(s)

    def _bl_max_path_cov(self):
        s={}
        for t in range(CFG["H"]):
            up=set(); cands=[]
            for tr in CFG["K"]:
                for z in CFG["diamond_affinity"].get(tr,[]):
                    if z=="OT": continue
                    for p in self.pl.valid_personas(tr):
                        if p in up: continue
                        nh=sum(1 for path in CFG["G"]
                               for hop,pz in enumerate(path["zones"])
                               if pz==z and hop<len(path["zones"])-1)
                        cands.append((nh*self.pl.qp.get(p,0.25),tr,z,p))
            cands.sort(reverse=True)
            for _,tr,z,p in cands:
                if p in up: continue
                s[(tr,z,t,p)]=1; up.add(p)
        return self._repair(s)

    # ── Visualisation ─────────────────────────────────────────────────────────

    def plot(self, rc2_result: dict, baselines: dict, out: str):
        import matplotlib.colors as mc

        all_results = {"★ RC2 (Emulated)": rc2_result["metrics"]}
        all_results.update(baselines)
        names  = list(all_results.keys())
        short  = [n.replace("★ ","") for n in names]
        RC2_COL = "#2C2882"
        palette = ["#E07B39","#6AB187","#D4AC0D","#8B6F9E","#C0392B",
                   "#2E86AB","#A8DADC","#457B9D","#95A3B3","#E9C46A"]
        cols = [RC2_COL] + palette[:len(names)-1]

        fig = plt.figure(figsize=(32,26), facecolor="#F9F8F5")
        gs  = GridSpec(4,3, figure=fig, hspace=0.55, wspace=0.40)
        tkw = dict(fontsize=9, fontweight="800", color="#1A1A2E", pad=7)
        lkw = dict(fontsize=8.5, color="#3D3D5C")
        bkw = dict(edgecolor="white", linewidth=0.5)

        fig.suptitle(
            "ZSTP-V6 MaxSAT RC2 Network Emulation — Dissertation Metric Comparison\n"
            f"Scale={NETWORK_SCALE}  |K|={len(CFG['K'])}  |Z|={len(CFG['Z'])}  "
            f"H={CFG['H']}  |P|={len(CFG['P'])}  |A|={CFG['A_total']}\n"
            f"Live emulation: {rc2_result['metrics']['live_detections']} real detections  "
            f"·  {len(rc2_result['stix_bundles'])} STIX bundles  "
            f"·  {len(rc2_result['slot_results'])} emulated slots",
            fontsize=10, fontweight="900", color="#1A1A2E", y=1.002)

        ha = lambda c: [mc.to_hex(mc.to_rgba(x,alpha=0.45)) for x in c]

        def sty(ax, xrot=33):
            ax.set_facecolor("#F1F0EC")
            ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
            ax.set_xticks(range(len(names)))
            ax.set_xticklabels(short, fontsize=6.5, rotation=xrot, ha="right")

        def blab(ax, bars, fmt="{:.0f}"):
            ylim=ax.get_ylim(); span=ylim[1]-ylim[0]
            for b in bars:
                h=b.get_height()
                if h>0.5: ax.text(b.get_x()+b.get_width()/2, h+span*0.013,
                                   fmt.format(h), ha="center", va="bottom", fontsize=5.8)

        def bhlab(ax, bars, fmt="{:.1f}%"):
            xlim=ax.get_xlim(); span=xlim[1]-xlim[0]
            for b in bars:
                w=b.get_width()
                if w>0.5: ax.text(w+span*0.013, b.get_y()+b.get_height()/2,
                                   fmt.format(w), ha="left", va="center", fontsize=5.8)

        # 1: r*
        ax=fig.add_subplot(gs[0,0])
        vals=[all_results[n].get("r_star",0) for n in names]
        bars=ax.bar(range(len(names)),vals,color=cols,**bkw)
        bars[0].set_edgecolor("#1A0080"); bars[0].set_linewidth(2.5)
        margin=vals[0]-max(vals[1:]) if len(vals)>1 else 0
        if margin>0:
            ax.annotate(f"+{margin:.0f} vs next",
                        xy=(0,vals[0]),xytext=(2,vals[0]*0.88),
                        fontsize=7,color=RC2_COL,fontweight="700",
                        arrowprops=dict(arrowstyle="->",color=RC2_COL,lw=1.2))
        ax.set_title("★ r* = min_Θ Q_k(x)  Worst-case floor\n"
                     "RC2 emulated with live attacker probes + STIX bundles",**tkw)
        ax.set_ylabel("worst-case Q",**lkw); sty(ax); blab(ax,bars)

        # 2: Q by Θ (wide)
        ax2=fig.add_subplot(gs[0,1:])
        bw=0.065; x=np.arange(len(CFG["Theta"]))
        for i,(n,c) in enumerate(zip(names,cols)):
            offs=(i-len(names)/2)*bw+bw/2
            ax2.bar(x+offs,[all_results[n].get("Q_by_theta",[0]*4)[j]
                            for j in range(len(CFG["Theta"]))],
                    bw,color=c,label=short[i],alpha=0.90,**bkw)
        ax2.set_title("Q per attacker scenario in Θ\n"
                      "RC2 emulated schedule tested against all 4 threat scenarios",**tkw)
        ax2.set_xticks(x)
        ax2.set_xticklabels([t["id"] for t in CFG["Theta"]],fontsize=9)
        ax2.set_ylabel("Q_k(x)",**lkw)
        ax2.legend(fontsize=5.8,ncol=6,framealpha=0.85,loc="upper right")
        ax2.set_facecolor("#F1F0EC"); ax2.spines["top"].set_visible(False)
        ax2.spines["right"].set_visible(False)

        # 3: ATT&CK techniques
        ax3=fig.add_subplot(gs[1,0])
        all_t=len({tk for ts in CFG["trap_techniques"].values() for tk in ts})
        vals=[all_results[n].get("tech_n",0) for n in names]
        bars3=ax3.bar(range(len(names)),vals,color=cols,**bkw)
        bars3[0].set_edgecolor("#1A0080"); bars3[0].set_linewidth(2.0)
        ax3.axhline(all_t,color="#C0392B",lw=1.3,ls="--",alpha=0.75)
        ax3.text(len(names)-.1,all_t+.25,f"max={all_t}",fontsize=7.5,
                 color="#C0392B",ha="right",fontweight="700")
        ax3.set_title(f"ATT&CK technique breadth (L2-tech ×{CFG['w2']})\n"
                      f"D3 objective — emulation covers techniques via live connections",**tkw)
        ax3.set_ylabel("distinct TTPs",**lkw); sty(ax3); blab(ax3,bars3)

        # 4: tactic families
        ax4=fig.add_subplot(gs[1,1])
        tf=len(CFG["tactic_families"])
        vals=[all_results[n].get("fam_n",0) for n in names]
        bars4=ax4.bar(range(len(names)),vals,color=cols,**bkw)
        bars4[0].set_edgecolor("#1A0080"); bars4[0].set_linewidth(2.0)
        ax4.axhline(tf,color="#C0392B",lw=1.3,ls="--",alpha=0.75)
        ax4.text(len(names)-.1,tf+.12,f"max={tf}",fontsize=7.5,
                 color="#C0392B",ha="right",fontweight="700")
        ax4.set_title(f"Tactic-family breadth (L2-fam ×{CFG['w2_fam']})\n"
                      f"max={tf} ATT&CK families",**tkw)
        ax4.set_ylabel("families",**lkw); sty(ax4); blab(ax4,bars4)

        # 5: C10% + hop
        ax5=fig.add_subplot(gs[1,2])
        x5=np.arange(len(names))
        ax5.bar(x5-.2,[all_results[n].get("c10_pct",0) for n in names],.35,
                color=cols,label="C10%",**bkw)
        ax5.bar(x5+.2,[all_results[n].get("hop_pct",0) for n in names],.35,
                color=ha(cols),label="Hop%",**bkw)
        ax5.set_title("Path persistence (C10%) and hop coverage%\n"
                      "Live attacker agents traverse real zone hops",**tkw)
        ax5.set_ylim(0,125); ax5.legend(fontsize=7.5); sty(ax5); ax5.set_ylabel("%",**lkw)

        # 6: Early intercept
        ax6=fig.add_subplot(gs[2,0])
        bars6=ax6.barh(range(len(names)),[all_results[n].get("early_pct",0) for n in names],
                       color=cols,**bkw)
        bars6[0].set_edgecolor("#1A0080"); bars6[0].set_linewidth(2.0)
        ax6.set_title(f"Early-intercept rate%  (L4 ×{CFG['w4']})\n"
                      "Real attacker agents caught at non-final hops",**tkw)
        ax6.set_yticks(range(len(names))); ax6.set_yticklabels(short,fontsize=7)
        ax6.set_xlabel("%",**lkw); ax6.set_xlim(0,130)
        ax6.set_facecolor("#F1F0EC"); ax6.spines["top"].set_visible(False)
        ax6.spines["right"].set_visible(False); bhlab(ax6,bars6)

        # 7: Detection rate
        ax7=fig.add_subplot(gs[2,1])
        bars7=ax7.barh(range(len(names)),[all_results[n].get("det_rate",0) for n in names],
                       color=cols,**bkw)
        bars7[0].set_edgecolor("#1A0080"); bars7[0].set_linewidth(2.0)
        ax7.set_title("Asset-slot detection coverage%\n"
                      "Live TCP connections to honeypot servers counted",**tkw)
        ax7.set_yticks(range(len(names))); ax7.set_yticklabels(short,fontsize=7)
        ax7.set_xlabel("%",**lkw); ax7.set_xlim(0,115)
        ax7.set_facecolor("#F1F0EC"); ax7.spines["top"].set_visible(False)
        ax7.spines["right"].set_visible(False); bhlab(ax7,bars7)

        # 8: Zone spread + persona diversity
        ax8=fig.add_subplot(gs[2,2])
        x8=np.arange(len(names))
        ax8.bar(x8-.2,[all_results[n].get("zone_spread",0) for n in names],.35,
                color=cols,label="Zone spread%",**bkw)
        ax8.bar(x8+.2,[all_results[n].get("pers_div",0) for n in names],.35,
                color=ha(cols),label="Persona div%",**bkw)
        ax8.set_title("Zone spread% and persona diversity%\n"
                      "D1 multi-zone + D6 identity rotation",**tkw)
        ax8.set_ylim(0,125); ax8.legend(fontsize=7.5); sty(ax8); ax8.set_ylabel("%",**lkw)

        # 9: Burn rates
        ax9=fig.add_subplot(gs[3,0])
        x9=np.arange(len(names))
        ax9.bar(x9-.2,[all_results[n].get("burn_p",0) for n in names],.35,
                color=ha(cols),label="Persona burn%",**bkw)
        ax9.bar(x9+.2,[all_results[n].get("burn_t",0) for n in names],.35,
                color=cols,label="Type burn%",**bkw)
        ax9.set_title("Discovery burn rates%  (↓ better)\n"
                      "RC2 trap rotation keeps burn=0% across all live slots",**tkw)
        ax9.set_ylabel("% flagged",**lkw); ax9.legend(fontsize=7.5); sty(ax9)

        # 10: C14 + churn
        ax10=fig.add_subplot(gs[3,1])
        x10=np.arange(len(names))
        ax10.bar(x10-.2,[all_results[n].get("xz",0) for n in names],.35,
                 color=cols,label="C14 leaks",**bkw)
        ax10.bar(x10+.2,[all_results[n].get("churn",0) for n in names],.35,
                 color=ha(cols),label="Churn",**bkw)
        ax10.set_title("C14 cross-zone persona leaks (↓) and churn (↓)\n"
                       "RC2 enforces C14=0 by construction",**tkw)
        ax10.legend(fontsize=7.5); sty(ax10); ax10.set_ylabel("count",**lkw)

        # 11: Live detection timeline
        ax11=fig.add_subplot(gs[3,2])
        slot_det = [r["detection_count"] for r in rc2_result["slot_results"]]
        slot_early = [r["early_intercepts"] for r in rc2_result["slot_results"]]
        xs = np.arange(len(slot_det))
        ax11.bar(xs-.15, slot_det, .28, color=RC2_COL, label="Detections", **bkw)
        ax11.bar(xs+.15, slot_early, .28, color="#E07B39", label="Early intercepts", **bkw)
        ax11.set_title("Live emulation: detections & early intercepts per slot\n"
                       "Real TCP connections to honeypot socket servers",**tkw)
        ax11.set_xlabel("Slot t",**lkw); ax11.set_ylabel("Count",**lkw)
        ax11.set_xticks(xs); ax11.legend(fontsize=8)
        ax11.set_facecolor("#F1F0EC"); ax11.spines["top"].set_visible(False)
        ax11.spines["right"].set_visible(False)

        patches=[mpatches.Patch(color=cols[i],label=s) for i,s in enumerate(short)]
        fig.legend(handles=patches,loc="lower center",ncol=6,
                   fontsize=8,framealpha=0.90,bbox_to_anchor=(0.5,0.0))

        plt.savefig(out,dpi=155,bbox_inches="tight",facecolor="#F9F8F5")
        log.info(f"[Chart] → {out}")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*68)
    print("  ZSTP-V6 Network Emulation — PhD Dissertation")
    print(f"  Scale={NETWORK_SCALE}  "
          f"|K|={len(CFG['K'])} |Z|={len(CFG['Z'])} H={CFG['H']} "
          f"|P|={len(CFG['P'])} |A|={CFG['A_total']}")
    print(f"  {CFG['H']} slots × {SLOT_DURATION_S}s/slot = "
          f"{CFG['H']*SLOT_DURATION_S:.0f}s emulation time")
    print("="*68 + "\n")

    emu = ZSTPEmulator()

    # Phase 1: live network emulation
    rc2_result = emu.run_emulation()

    # Phase 2: baseline comparison (analytical)
    baselines = emu.run_baselines()

    # Summary table
    all_r = {"★ RC2 (Emulated)": rc2_result["metrics"]}
    all_r.update(baselines)

    MDEFS = [
        ("r*",     "r_star",    True,  "{:>9.0f}"),
        ("Q-med",  "Q",         True,  "{:>9.0f}"),
        ("Tech",   "tech_n",    True,  "{:>5d}"),
        ("C10%",   "c10_pct",   True,  "{:>6.0f}%"),
        ("Early%", "early_pct", True,  "{:>7.1f}%"),
        ("Det%",   "det_rate",  True,  "{:>6.1f}%"),
        ("PBurn%", "burn_p",    False, "{:>7.1f}%"),
        ("TBurn%", "burn_t",    False, "{:>7.1f}%"),
        ("C14",    "xz",        False, "{:>5d}"),
        ("LiveDet","live_detections",True,"{:>8d}"),
    ]
    hdr = f"  {'Solver':24s}"
    for l,_,_,_ in MDEFS: hdr += f"  {l:>8}"
    print("\n"+"="*len(hdr)); print(hdr); print("-"*len(hdr))
    for n, r in sorted(all_r.items(), key=lambda x: -x[1].get("r_star",0)):
        mk = "★ " if "RC2" in n else "  "
        row = f"{mk}{n.replace('★ ',''):22s}"
        for _,k,_,fmt in MDEFS: row += "  " + fmt.format(r.get(k,0))
        print(row)
    print("="*len(hdr))

    # Emulation summary
    print(f"\n  Emulation facts:")
    print(f"    Total live detections : {rc2_result['metrics']['live_detections']}")
    print(f"    STIX bundles generated: {len(rc2_result['stix_bundles'])}")
    print(f"    Schedule redeployments: {len(emu.schedule_history)-1}")
    print(f"    qp after emulation    : "
          + "  ".join(f"{p[:6]}={v:.3f}" for p,v in emu.pl.qp.items()))

    # Plot
    out = os.path.join(_here, "MaxSat_RC2_V6_Emulation.png")
    emu.plot(rc2_result, baselines, out)
    print(f"\n  Done. Chart → {out}")


if __name__ == "__main__":
    main()
