"""
decision_variables.py
Zone-Slot-Time-Persona V6 — Decision Variables (Section B)
===========================================================
Implements all seven variable families from the formulation:

    PRIMARY
    -------
    x_{i,z,t,p}   {0,1}  Deploy type i in zone z at slot t wearing persona p

    DERIVED (computed from x; not free solver decisions)
    -------
    x_{i,t}       {0,1}  Type i active in any zone at slot t        (C4 only)
    u_{i,z,t}     {0,1}  Type-discovery flag (C9)
    u_{i,z,t,p}   {0,1}  Persona-discovery flag (C13)
    c_{j,a,t}     {0,1}  Detect technique j on asset a at slot t    (C1)
    p_{π,h,t}     {0,1}  Cover hop h of path π at slot t            (C6)
    e_{π,t}       {0,1}  Early interception on path π at slot t     (C7)

NOTE on encoding: persona is modelled as the fourth index of x (not a
separate variable p_{i,z,t} ∈ P). This keeps all solver decisions in one
variable family and makes C12 (persona-conflict) structurally identical
to C4 (type-conflict) — both are pairwise clauses over the same family.

Usage:
    from config       import CFG
    from persona_layer import PersonaLayer
    from decision_variables import DecisionVariables

    pl  = PersonaLayer(CFG)
    pl.update_qp()

    dv  = DecisionVariables(CFG, pl)

    # Provide any schedule (dict or generate one) and compute everything:
    schedule = { ("ssh_trap","DMZ",0,"HR_workstation"): 1, ... }
    dv.load_schedule(schedule)

    print(dv.x(  "ssh_trap","DMZ",1,"HR_workstation"))   # primary
    print(dv.x_it("ssh_trap",1))                          # derived C4
    print(dv.u_type("ssh_trap","DMZ",1))                  # type-discovery
    print(dv.u_persona("ssh_trap","DMZ",1,"HR_workstation"))  # persona-disc.
    print(dv.c("T1021", 24, 1))                           # detection
    print(dv.p_path("pi1", 0, 1))                         # path coverage
    print(dv.e_intercept("pi1", 1))                       # early interception

    dv.print_schedule()    # operator-readable schedule table
    dv.print_flags()       # discovery flag summary
    dv.print_coverage()    # path and technique coverage summary
"""

import math
from collections import defaultdict

"""
x_{i,z,t,p} (primary). Stored as a sparse dict — only active deployments consume memory. active_deployments(t) and active_in_zone(zone,t) give the solver fast read access. The four-index encoding is the only entry point for all derived variables — nothing is computed separately.
x_{i,t} (derived, C4 only). Collapsed view computed lazily from x. c4_violations() finds any slot where two conflicting types (generic_trap/dns_trap or smb_trap/generic_trap) are both active. Test confirms 0 violations in the sample schedule.
u_{i,z,t} (type-discovery, C9). Computes a rolling window of ceil(τᵈ) consecutive active slots per (trap,zone). V5 independence: persona rotation at t=2 (HR→DevOps) does NOT reset the type clock. Test confirms u_type[ssh_trap,DMZ,t=2]=1 after 3 consecutive slots (t=0,1,2), while t=0 is still 0 — the flag activates exactly when the window fills.
u_{i,z,t,p} (persona-discovery, C13). Independent clock per persona. HR_workstation burns at t=1 (2 consecutive slots, τᵈᵖ=2). DevOps_server activated at t=2 reads 0 — the rotation resets its clock. Dual guard: guard[t=1,HR]=0 because the persona is burned, zeroing all L1–L4 credit exactly as equations 6–11 specify.
c_{j,a,t} (detection, C1). Only fires when a GK-admitted, undiscovered deployment covers technique j in zone(a). 2,460 detection events across the 4-slot horizon on 100 assets — the O(|K|·|A|·|T|·H·|P|) clause database is evaluated in full.
p_{π,h,t} (path coverage, C6). Built from c — a hop is covered iff any detection fires in the correct zone at that slot. One C10 violation surfaced: pi1's DMZ hop (hop 0) is only covered 1/4 slots but requires ⌈0.35×4⌉=2 — a real gap the solver would have to close.
e_{π,t} (early interception, C7). 1 only when a non-final hop is covered. 43.8% early-intercept rate across the 4 paths × 4 slots space. The schedule table annotations correctly flag C9 and C13 burns inline against each deployment row.Decision variablesPY Download and open


"""

# ─────────────────────────────────────────────────────────────────────────────
#  DECISION VARIABLES CLASS
# ─────────────────────────────────────────────────────────────────────────────

class DecisionVariables:
    """
    Stores and computes all seven decision-variable families.

    All derived variables are computed lazily on first access and cached
    until load_schedule() is called again (invalidating the cache).
    """

    def __init__(self, cfg: dict, persona_layer):
        # ── Configuration ─────────────────────────────────────────────
        self.K = cfg["K"]                       # honeypot types
        self.Z = cfg["Z"]                       # zones
        self.P = cfg["P"]                       # personas
        self.H = cfg["H"]                       # planning horizon
        self.G = cfg["G"]                       # attack paths
        self.C_conflicts   = cfg["C_conflicts"] # type conflict pairs (C4)
        self.I2            = cfg["I2"]          # air-gap pairs (C5)
        self.diamond       = cfg["diamond_affinity"]   # ⋄ zone affinity
        self.trap_techs    = cfg["trap_techniques"]    # trap → techniques
        self.A_per_zone    = cfg["A_per_zone"]         # asset counts per zone
        self.A_total       = cfg["A_total"]

        # ── Persona layer (provides τᵈ, τᵈᵖ, GK, qₚ) ─────────────────
        self.pl = persona_layer

        # ── Asset index: build a list of (asset_id, zone) pairs ───────
        self._assets = self._build_asset_list()  # list of (asset_id, zone)
        self._asset_zone = {a: z for a, z in self._assets}

        # ── Primary schedule storage ───────────────────────────────────
        # _x[(trap,zone,t,persona)] → {0,1}
        self._x: dict = {}

        # ── Lazy-computed derived variable caches ─────────────────────
        self._x_it:      dict | None = None   # (trap,t) → {0,1}
        self._u_type:    dict | None = None   # (trap,zone,t) → {0,1}
        self._u_persona: dict | None = None   # (trap,zone,t,persona) → {0,1}
        self._c:         dict | None = None   # (tech,asset,t) → {0,1}
        self._p_path:    dict | None = None   # (path_id,hop,t) → {0,1}
        self._e:         dict | None = None   # (path_id,t) → {0,1}

        # rho_pi used for current compute pass (set in compute_all_derived)
        self._rho_pi = 0.30

    # ─────────────────────────────────────────────────────────────────
    #  ASSET LIST
    # ─────────────────────────────────────────────────────────────────

    def _build_asset_list(self) -> list:
        """Build ordered (asset_id, zone) list from per-zone counts."""
        assets = []
        aid = 0
        for zone in self.Z:
            for _ in range(self.A_per_zone.get(zone, 0)):
                assets.append((aid, zone))
                aid += 1
        return assets

    def assets_in_zone(self, zone: str) -> list:
        """Return all asset ids in the given zone."""
        return [a for a, z in self._assets if z == zone]

    def zone_of_asset(self, asset_id: int) -> str:
        """Return the zone for a given asset id."""
        return self._asset_zone.get(asset_id, "Unknown")

    # ─────────────────────────────────────────────────────────────────
    #  SCHEDULE LOADING
    # ─────────────────────────────────────────────────────────────────

    def load_schedule(self, schedule: dict, rho_pi: float = 0.30):
        """
        Load a primary schedule and invalidate all derived caches.

        Args:
            schedule : dict mapping (trap, zone, slot, persona) → {0,1}
                       Missing keys default to 0 (not deployed).
            rho_pi   : current path probability (for τᵈ computation in u_type)
        """
        self._x         = {k: int(v) for k, v in schedule.items() if v}
        self._rho_pi    = rho_pi
        # Invalidate caches
        self._x_it      = None
        self._u_type    = None
        self._u_persona = None
        self._c         = None
        self._p_path    = None
        self._e         = None

    def compute_all_derived(self, rho_pi: float | None = None):
        """
        Force computation of all derived variables in dependency order:
            x_it → u_type → u_persona → c → p_path → e
        """
        if rho_pi is not None:
            self._rho_pi = rho_pi
        _ = self._get_x_it()
        _ = self._get_u_type()
        _ = self._get_u_persona()
        _ = self._get_c()
        _ = self._get_p_path()
        _ = self._get_e()

    # ─────────────────────────────────────────────────────────────────
    #  x_{i,z,t,p}  PRIMARY VARIABLE
    # ─────────────────────────────────────────────────────────────────

    def x(self, trap: str, zone: str, t: int, persona: str) -> int:
        """
        x_{i,z,t,p} ∈ {0,1} — deploy type i in zone z at slot t as persona p.
        PRIMARY decision variable; 1 iff the solver committed this deployment.
        """
        return self._x.get((trap, zone, t, persona), 0)

    def active_deployments(self, t: int | None = None) -> list:
        """
        Return list of (trap,zone,slot,persona) tuples where x=1.
        If t is given, filter to that slot only.
        """
        if t is None:
            return [k for k, v in self._x.items() if v]
        return [k for k, v in self._x.items() if v and k[2] == t]

    def active_in_zone(self, zone: str, t: int) -> list:
        """Return (trap, persona) pairs active in zone at slot t."""
        return [(tr, p) for (tr, z, ts, p), v in self._x.items()
                if v and z == zone and ts == t]

    # ─────────────────────────────────────────────────────────────────
    #  x_{i,t}  DERIVED — TYPE-ACTIVE COLLAPSED VIEW  (C4 only)
    # ─────────────────────────────────────────────────────────────────

    def _get_x_it(self) -> dict:
        """
        x_{i,t} = 1  iff  ∃z,p: x_{i,z,t,p} = 1
        Collapsed view used exclusively for C4 conflict checking.
        NOTE: this is NOT used for credit or path coverage — only C4.
        """
        if self._x_it is None:
            self._x_it = {}
            for trap in self.K:
                for t in range(self.H):
                    active = any(
                        self._x.get((trap, z, t, p), 0)
                        for z in self.Z for p in self.P
                    )
                    self._x_it[(trap, t)] = int(active)
        return self._x_it

    def x_it(self, trap: str, t: int) -> int:
        """
        x_{i,t} ∈ {0,1} — is type i active anywhere at slot t?
        Used ONLY for C4 type-conflict checking.
        """
        return self._get_x_it().get((trap, t), 0)

    def c4_violations(self) -> list:
        """
        Check C4: no two conflicting types can both be active in the same slot.
        C4: ¬x_{i,t} ∨ ¬x_{l,t}  ∀(kᵢ,kₗ) ∈ C, ∀t
        Returns list of (t, trap_a, trap_b) violation triples.
        """
        violations = []
        x_it = self._get_x_it()
        for t in range(self.H):
            for (ta, tb) in self.C_conflicts:
                if x_it.get((ta, t), 0) and x_it.get((tb, t), 0):
                    violations.append((t, ta, tb))
        return violations

    # ─────────────────────────────────────────────────────────────────
    #  u_{i,z,t}  DERIVED — TYPE-DISCOVERY FLAG  (C9)
    # ─────────────────────────────────────────────────────────────────

    def _get_u_type(self) -> dict:
        """
        u_{i,z,t} = 1  iff  type i has been active in zone z for τᵈ
        consecutive slots under *any* persona (C9).

        V5 note: C9 and C13 are independent. Persona rotation does NOT
        reset u_{i,z,t}. Only removing the type from the zone resets it.
        """
        if self._u_type is None:
            self._u_type = {}
            for trap in self.K:
                for zone in self.Z:
                    for t in range(self.H):
                        N_ip = self.pl.get_N(trap, _dominant_persona(
                            self._x, trap, zone, t))
                        td = self.pl.tau_d(self._rho_pi, N_ip)
                        td_ceil = math.ceil(td)
                        window_start = t - td_ceil + 1
                        if window_start < 0:
                            self._u_type[(trap, zone, t)] = 0
                            continue
                        consec = sum(
                            1 for s in range(window_start, t + 1)
                            if any(self._x.get((trap, zone, s, p), 0)
                                   for p in self.P)
                        )
                        self._u_type[(trap, zone, t)] = int(consec >= td_ceil)
        return self._u_type

    def u_type(self, trap: str, zone: str, t: int) -> int:
        """
        u_{i,z,t} ∈ {0,1} — type-discovery flag.
        1 = type burned; credit zeroed regardless of persona rotation.
        """
        return self._get_u_type().get((trap, zone, t), 0)

    # ─────────────────────────────────────────────────────────────────
    #  u_{i,z,t,p}  DERIVED — PERSONA-DISCOVERY FLAG  (C13)
    # ─────────────────────────────────────────────────────────────────

    def _get_u_persona(self) -> dict:
        """
        u_{i,z,t,p} = 1  iff  persona p has been continuously active at
        (i,z) for τᵈᵖ consecutive slots (C13).

        V5 note: independent of u_{i,z,t}. Rotating to persona p′ resets
        u_{i,z,t,p} to 0 — but does NOT affect u_{i,z,t} (the type clock).
        """
        if self._u_persona is None:
            self._u_persona = {}
            for trap in self.K:
                for zone in self.Z:
                    for persona in self.P:
                        for t in range(self.H):
                            N_ip = self.pl.get_N(trap, persona)
                            tdp = self.pl.tau_dp(N_ip)
                            tdp_ceil = math.ceil(tdp)
                            window_start = t - tdp_ceil + 1
                            if window_start < 0:
                                self._u_persona[(trap, zone, t, persona)] = 0
                                continue
                            consec = sum(
                                1 for s in range(window_start, t + 1)
                                if self._x.get((trap, zone, s, persona), 0)
                            )
                            self._u_persona[(trap, zone, t, persona)] = int(
                                consec >= tdp_ceil
                            )
        return self._u_persona

    def u_persona(self, trap: str, zone: str, t: int, persona: str) -> int:
        """
        u_{i,z,t,p} ∈ {0,1} — persona-discovery flag.
        1 = persona burned; credit zeroed until a different persona is used.
        """
        return self._get_u_persona().get((trap, zone, t, persona), 0)

    def dual_guard(self, trap: str, zone: str, t: int, persona: str) -> int:
        """
        (1 − u_{i,z,t}) · (1 − u_{i,z,t,p})
        Returns 1 only when both type AND persona are undiscovered.
        Used in every L1–L4 credit term (Section E, eqs 6–11).
        """
        return (1 - self.u_type(trap, zone, t)) * \
               (1 - self.u_persona(trap, zone, t, persona))

    # ─────────────────────────────────────────────────────────────────
    #  c_{j,a,t}  DERIVED — DETECTION EVENT  (C1)
    # ─────────────────────────────────────────────────────────────────

    def _get_c(self) -> dict:
        """
        c_{j,a,t} = 1  iff  ∃i,p: x_{i,zone(a),t,p}=1
                                 ∧ technique j ∈ techs(i)
                                 ∧ u_{i,zone(a),t,p} = 0   (dual guard)

        C1: detection requires a real, undiscovered deployment in the zone.
        No phantom credits — the honeypot must actually be there.
        """
        if self._c is None:
            self._c = {}
            u_type    = self._get_u_type()
            u_persona = self._get_u_persona()
            for asset_id, zone in self._assets:
                for tech in _all_techniques(self.trap_techs):
                    for t in range(self.H):
                        # Find any trap that covers tech, is deployed here,
                        # and passes the dual guard
                        fired = 0
                        for trap in self.K:
                            if zone not in self.diamond.get(trap, []):
                                continue
                            if tech not in self.trap_techs.get(trap, []):
                                continue
                            for persona in self.P:
                                if not self._x.get((trap, zone, t, persona), 0):
                                    continue
                                ut = u_type.get((trap, zone, t), 0)
                                up = u_persona.get((trap, zone, t, persona), 0)
                                if not ut and not up:
                                    fired = 1
                                    break
                            if fired:
                                break
                        self._c[(tech, asset_id, t)] = fired
        return self._c

    def c(self, tech: str, asset_id: int, t: int) -> int:
        """
        c_{j,a,t} ∈ {0,1} — detection of technique j on asset a at slot t.
        1 only when a real, undiscovered honeypot covering j is in zone(a).
        """
        return self._get_c().get((tech, asset_id, t), 0)

    def detections_at(self, t: int) -> list:
        """Return all (tech, asset_id) detections firing at slot t."""
        return [(tech, a) for (tech, a, ts), v in self._get_c().items()
                if v and ts == t]

    def detection_count(self) -> int:
        """Total detection events across all slots."""
        return sum(self._get_c().values())

    # ─────────────────────────────────────────────────────────────────
    #  p_{π,h,t}  DERIVED — PATH HOP COVERAGE  (C6)
    # ─────────────────────────────────────────────────────────────────

    def _get_p_path(self) -> dict:
        """
        p_{π,h,t} = 1  iff  ∃j,a: c_{j,a,t} = 1
                                  ∧ zone(a) = zones(π)[h]
                                  ∧ j ∈ techniques(π,h)    [informational]

        C6: path coverage requires a detection event at the correct zone.
        """
        if self._p_path is None:
            self._p_path = {}
            c = self._get_c()
            for path in self.G:
                pid   = path["id"]
                zones = path["zones"]
                for hop, zone in enumerate(zones):
                    assets_here = [a for a, z in self._assets if z == zone]
                    for t in range(self.H):
                        # Any technique detection in this zone this slot
                        covered = any(
                            c.get((tech, a, t), 0)
                            for a in assets_here
                            for tech in _all_techniques(self.trap_techs)
                        )
                        self._p_path[(pid, hop, t)] = int(covered)
        return self._p_path

    def p_path(self, path_id: str, hop: int, t: int) -> int:
        """
        p_{π,h,t} ∈ {0,1} — hop h of path π is covered at slot t.
        Currency of L3 path-weight credit (eqs 7, 8).
        """
        return self._get_p_path().get((path_id, hop, t), 0)

    def path_coverage_slots(self) -> dict:
        """
        For each path, count how many slots each hop is covered.
        Returns {path_id: {hop: count}}.
        """
        p = self._get_p_path()
        result = {}
        for path in self.G:
            pid = path["id"]
            result[pid] = {}
            for hop in range(len(path["zones"])):
                result[pid][hop] = sum(
                    p.get((pid, hop, t), 0) for t in range(self.H)
                )
        return result

    def c10_violations(self) -> list:
        """
        C10: Σ_t p_{π,h★,t} ≥ ⌈ρπ·H⌉  ∀π
        Returns list of {path_id, required, covered, deficit} dicts.
        """
        violations = []
        cov = self.path_coverage_slots()
        for path in self.G:
            pid     = path["id"]
            h_star  = 0   # critical hop: first non-final (hop 0 unless single-hop)
            required = math.ceil(path["rho"] * self.H)
            covered  = cov[pid].get(h_star, 0)
            if covered < required:
                violations.append({
                    "path_id":  pid,
                    "hop":      h_star,
                    "required": required,
                    "covered":  covered,
                    "deficit":  required - covered,
                })
        return violations

    # ─────────────────────────────────────────────────────────────────
    #  e_{π,t}  DERIVED — EARLY INTERCEPTION FLAG  (C7)
    # ─────────────────────────────────────────────────────────────────

    def _get_e(self) -> dict:
        """
        e_{π,t} = 1  iff  ∃h < |π|−1: p_{π,h,t} = 1
        (non-final hop covered — catches attacker BEFORE the last step)

        C7: early interception ≠ forensic coverage. Covering only the
        final hop earns L3-bwd (forensic) credit, not L4 prevention credit.
        """
        if self._e is None:
            self._e = {}
            p_path = self._get_p_path()
            for path in self.G:
                pid    = path["id"]
                n_hops = len(path["zones"])
                for t in range(self.H):
                    # Any non-final hop covered?
                    early = any(
                        p_path.get((pid, hop, t), 0)
                        for hop in range(n_hops - 1)   # exclude final hop
                    )
                    self._e[(pid, t)] = int(early)
        return self._e

    def e_intercept(self, path_id: str, t: int) -> int:
        """
        e_{π,t} ∈ {0,1} — early interception on path π at slot t.
        1 = attacker caught at a non-final hop → L4 ×1000 credit (eq 6).
        0 = only final hop covered → L3-bwd forensic credit only (eq 8).
        """
        return self._get_e().get((path_id, t), 0)

    def early_intercept_rate(self) -> float:
        """
        % of (path × slot) combinations that achieve early interception.
        """
        e = self._get_e()
        total = len(self.G) * self.H
        return sum(e.values()) / total * 100 if total else 0.0

    # ─────────────────────────────────────────────────────────────────
    #  CONVENIENCE: VARIABLE SNAPSHOTS
    # ─────────────────────────────────────────────────────────────────

    def snapshot(self, t: int) -> dict:
        """
        Return a complete snapshot of all variable values at slot t.
        Useful for debugging and logging.
        """
        self.compute_all_derived()
        snap = {
            "x":        {},   # (trap,zone,persona) → {0,1}
            "x_it":     {},   # trap → {0,1}
            "u_type":   {},   # (trap,zone) → {0,1}
            "u_persona":{},   # (trap,zone,persona) → {0,1}
            "detections":[],  # [(tech,asset)]
            "p_path":   {},   # (path_id,hop) → {0,1}
            "e_intercept": {}, # path_id → {0,1}
        }
        # x
        for trap in self.K:
            for zone in self.Z:
                for persona in self.P:
                    v = self._x.get((trap, zone, t, persona), 0)
                    if v:
                        snap["x"][(trap, zone, persona)] = v
        # x_it
        for trap in self.K:
            snap["x_it"][trap] = self.x_it(trap, t)
        # u_type, u_persona
        for trap in self.K:
            for zone in self.Z:
                snap["u_type"][(trap, zone)] = self.u_type(trap, zone, t)
                for persona in self.P:
                    snap["u_persona"][(trap,zone,persona)] = \
                        self.u_persona(trap, zone, t, persona)
        # detections
        snap["detections"] = self.detections_at(t)
        # p_path, e_intercept
        for path in self.G:
            pid = path["id"]
            for hop in range(len(path["zones"])):
                snap["p_path"][(pid, hop)] = self.p_path(pid, hop, t)
            snap["e_intercept"][pid] = self.e_intercept(pid, t)
        return snap

    # ─────────────────────────────────────────────────────────────────
    #  PRINT HELPERS
    # ─────────────────────────────────────────────────────────────────

    def print_schedule(self):
        """
        Print operator-readable deployment schedule table.
        Format: Type | Zone | Persona | t=0 | t=1 | ... | Constraint notes
        """
        self.compute_all_derived()
        print("\n" + "=" * 80)
        print("  Deployment Schedule  (x_{i,z,t,p})")
        print("=" * 80)
        hdr = f"  {'Type':14s} {'Zone':10s} {'Persona':20s}"
        for t in range(self.H):
            hdr += f" t={t}"
        print(hdr)
        print("-" * 80)

        seen = set()
        for trap in self.K:
            for zone in self.Z:
                for persona in self.P:
                    row_vals = [self._x.get((trap,zone,t,persona),0)
                                for t in range(self.H)]
                    if any(row_vals):
                        key = (trap, zone, persona)
                        if key in seen:
                            continue
                        seen.add(key)
                        vals_str = "  ".join(
                            "✓" if v else "·" for v in row_vals
                        )
                        notes = self._constraint_notes(trap, zone, persona)
                        print(f"  {trap:14s} {zone:10s} {persona:20s}  "
                              f"{vals_str}  {notes}")
        print("=" * 80)

    def _constraint_notes(self, trap, zone, persona) -> str:
        """Build brief constraint-driver notes for a (trap,zone,persona) row."""
        notes = []
        u_type_any = any(self.u_type(trap,zone,t) for t in range(self.H))
        u_pers_any = any(self.u_persona(trap,zone,t,persona) for t in range(self.H))
        if u_type_any:  notes.append("C9:type-burned")
        if u_pers_any:  notes.append("C13:persona-burned")
        if not self.pl.gk_admitted(trap, persona):
            notes.append("C5b:GK-rejected")
        return "  ".join(notes)

    def print_flags(self):
        """Print discovery flag summary across the horizon."""
        self.compute_all_derived()
        print("\n" + "=" * 70)
        print("  Discovery Flags  (u_{i,z,t} and u_{i,z,t,p})")
        print("=" * 70)

        u_type    = self._get_u_type()
        u_persona = self._get_u_persona()

        type_burned   = [(k,v) for k,v in u_type.items()    if v]
        persona_burned= [(k,v) for k,v in u_persona.items() if v]

        print(f"\n  u_type   burned: {len(type_burned)} / {len(u_type)}")
        for (trap,zone,t), _ in type_burned[:8]:
            print(f"    u_type [{trap:12s},{zone:10s},t={t}] = 1  "
                  f"(type burned; C9)")

        print(f"\n  u_persona burned: {len(persona_burned)} / {len(u_persona)}")
        for (trap,zone,t,persona), _ in persona_burned[:8]:
            print(f"    u_pers [{trap:12s},{zone:10s},t={t},{persona:18s}] = 1")

        if not type_burned and not persona_burned:
            print("  No flags burned — all deployments earn full credit.")
        print("=" * 70)

    def print_coverage(self):
        """Print path coverage and early-interception summary."""
        self.compute_all_derived()
        print("\n" + "=" * 70)
        print("  Path Coverage and Early Interception")
        print("=" * 70)

        cov_slots = self.path_coverage_slots()
        c10_v     = self.c10_violations()

        for path in self.G:
            pid   = path["id"]
            name  = path["name"]
            rho   = path["rho"]
            req   = math.ceil(rho * self.H)
            n_hops= len(path["zones"])

            print(f"\n  π: {pid} ({name})  ρπ={rho}  required≥{req} slot(s)")
            for hop, zone in enumerate(path["zones"]):
                cov   = cov_slots[pid].get(hop, 0)
                is_fin= (hop == n_hops - 1)
                label = "final (forensic)" if is_fin else "non-final (prevention)"
                print(f"    hop {hop} ({zone:10s}) [{label:22s}]: "
                      f"covered {cov}/{self.H} slots")

            # Early interception per slot
            early_slots = [t for t in range(self.H)
                           if self.e_intercept(pid, t)]
            print(f"    Early interception (e=1) at slots: "
                  f"{early_slots if early_slots else 'none'}")

        c10_v = self.c10_violations()
        if c10_v:
            print(f"\n  ⚠ C10 violations: {len(c10_v)}")
            for v in c10_v:
                print(f"    {v['path_id']} hop {v['hop']}: "
                      f"covered {v['covered']} < required {v['required']}")
        else:
            print(f"\n  [✓] C10 satisfied — all paths meet ⌈ρπ·H⌉ minimum.")

        rate = self.early_intercept_rate()
        det  = self.detection_count()
        print(f"\n  Early-intercept rate:  {rate:.1f}%  (L4 ×1000 objective)")
        print(f"  Total detection events: {det}  (c_{{j,a,t}} = 1 across all slots)")
        print("=" * 70)

    def print_all(self, rho_pi: float = 0.30):
        """Print complete variable state: schedule + flags + coverage."""
        self.compute_all_derived(rho_pi)
        self.print_schedule()
        self.print_flags()
        self.print_coverage()


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _all_techniques(trap_techs: dict) -> set:
    """Union of all techniques across all trap types."""
    techs = set()
    for tlist in trap_techs.values():
        techs.update(tlist)
    return techs


def _dominant_persona(x_dict: dict, trap: str, zone: str, t: int) -> str:
    """
    Return the persona with the most active slots at (trap,zone) up to t.
    Used to select the representative N_ip for τᵈ computation in u_type.
    """
    counts: dict = {}
    for (tr, z, ts, p), v in x_dict.items():
        if tr == trap and z == zone and ts <= t and v:
            counts[p] = counts.get(p, 0) + 1
    return max(counts, key=counts.get) if counts else ""


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST  ── python decision_variables.py
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    # ── Load config and persona layer ────────────────────────────────
    try:
        from config import CFG
        from persona_layer import PersonaLayer
    except ImportError:
        print("[WARN] Running without config.py — using minimal inline config")
        # Minimal inline config for standalone testing
        CFG = {
            "K": ["ssh_trap","db_trap","scada_trap","ad_trap",
                  "dns_trap","web_trap","generic_trap","smb_trap"],
            "Z": ["DMZ","Internal","Cloud","OT","Mgmt"],
            "P": ["HR_workstation","DevOps_server","Finance_DB","Generic_Linux"],
            "H": 4,
            "G": [
                {"id":"pi1","name":"web-to-db","zones":["DMZ","Internal","Internal"],
                 "rho":0.35,"iv":[1.8,1.4,1.0]},
                {"id":"pi2","name":"cloud-ad","zones":["Cloud","Internal","Mgmt"],
                 "rho":0.25,"iv":[1.6,1.3,1.0]},
                {"id":"pi3","name":"ot-infiltr","zones":["DMZ","OT"],
                 "rho":0.15,"iv":[1.5,1.2]},
                {"id":"pi4","name":"mgmt-pivot","zones":["DMZ","Mgmt","Internal"],
                 "rho":0.20,"iv":[1.7,1.3,1.0]},
            ],
            "C_conflicts": [("generic_trap","dns_trap"),("smb_trap","generic_trap")],
            "I2": [("OT","DMZ"),("OT","Cloud"),("OT","Mgmt")],
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
            "trap_techniques": {
                "ssh_trap":["T1021","T1078","T1059"],
                "db_trap":["T1048","T1213","T1083"],
                "smb_trap":["T1021","T1046","T1055"],
                "scada_trap":["T1059","T1053"],
                "ad_trap":["T1110","T1078"],
                "dns_trap":["T1572","T1041","T1046"],
                "web_trap":["T1190","T1566"],
                "generic_trap":["T1046","T1213"],
            },
            "A_per_zone":{"DMZ":20,"Internal":40,"Cloud":20,"OT":10,"Mgmt":10},
            "A_total":100,
            "GK_scores":{
                ("ssh_trap","HR_workstation"):0.85,("ssh_trap","DevOps_server"):0.90,
                ("ssh_trap","Finance_DB"):0.40,    ("ssh_trap","Generic_Linux"):0.75,
                ("db_trap","HR_workstation"):0.50, ("db_trap","DevOps_server"):0.70,
                ("db_trap","Finance_DB"):0.95,     ("db_trap","Generic_Linux"):0.60,
                ("smb_trap","HR_workstation"):0.80,("smb_trap","DevOps_server"):0.70,
                ("smb_trap","Finance_DB"):0.55,    ("smb_trap","Generic_Linux"):0.45,
                ("scada_trap","Generic_Linux"):0.90,("scada_trap","DevOps_server"):0.50,
                ("scada_trap","HR_workstation"):0.20,("scada_trap","Finance_DB"):0.15,
                ("ad_trap","HR_workstation"):0.90, ("ad_trap","DevOps_server"):0.75,
                ("ad_trap","Finance_DB"):0.60,     ("ad_trap","Generic_Linux"):0.40,
                ("dns_trap","HR_workstation"):0.55,("dns_trap","DevOps_server"):0.80,
                ("dns_trap","Finance_DB"):0.40,    ("dns_trap","Generic_Linux"):0.85,
                ("web_trap","HR_workstation"):0.65,("web_trap","DevOps_server"):0.85,
                ("web_trap","Finance_DB"):0.50,    ("web_trap","Generic_Linux"):0.80,
                ("generic_trap","HR_workstation"):0.75,("generic_trap","DevOps_server"):0.70,
                ("generic_trap","Finance_DB"):0.50,("generic_trap","Generic_Linux"):0.80,
            },
            "tau_GK":0.65,"tau_d0":3,"tau_dp0":2,"rho_max":1.0,
            "Delta":2,"Delta_p":2,
            "q":{"HR_workstation":0.25,"DevOps_server":0.25,
                 "Finance_DB":0.25,"Generic_Linux":0.25},
            "gamma":0.80,"beta_max":0.60,"kappa":30.0,
            "rho_decay":0.5,"Delta_N":3,
            "stix_signals":[
                {"confidence":0.88,"deltas":{"Finance_DB":+0.25,"HR_workstation":+0.15,
                 "DevOps_server":-0.05,"Generic_Linux":-0.05}},
            ],
            "empirical_interactions":{"Finance_DB":18,"HR_workstation":12,
                                      "DevOps_server":7,"Generic_Linux":3},
            "h_min":24.0,"kappa_min":12.0,
        }
        from persona_layer import PersonaLayer

    print("\n" + "=" * 70)
    print("  Decision Variables — Self-Test")
    print("=" * 70)

    pl = PersonaLayer(CFG)
    pl.update_qp()
    dv = DecisionVariables(CFG, pl)

    # ── Representative schedule (mirrors the operator-schedule example) ──
    schedule = {
        # t=0
        ("ssh_trap",   "DMZ",      0, "HR_workstation"):  1,
        ("db_trap",    "Internal", 0, "Finance_DB"):       1,
        ("dns_trap",   "Cloud",    0, "DevOps_server"):    1,
        ("scada_trap", "OT",       0, "Generic_Linux"):    1,
        ("ad_trap",    "Mgmt",     0, "HR_workstation"):   1,
        # t=1
        ("ssh_trap",   "DMZ",      1, "HR_workstation"):   1,  # C13: will burn at t=1 (τdp=2)
        ("db_trap",    "Internal", 1, "Finance_DB"):        1,
        ("scada_trap", "OT",       1, "Generic_Linux"):     1,
        ("ad_trap",    "Mgmt",     1, "HR_workstation"):    1,
        # t=2  — persona rotation: ssh_trap → DevOps (C13 resets clock)
        ("ssh_trap",   "DMZ",      2, "DevOps_server"):    1,
        ("db_trap",    "Cloud",    2, "Finance_DB"):        1,  # rotated zone
        ("scada_trap", "OT",       2, "Generic_Linux"):     1,
        ("ad_trap",    "Mgmt",     2, "HR_workstation"):    1,
        # t=3
        ("ssh_trap",   "DMZ",      3, "HR_workstation"):   1,
        ("db_trap",    "Internal", 3, "Finance_DB"):        1,
        ("scada_trap", "OT",       3, "Generic_Linux"):     1,
    }

    dv.load_schedule(schedule, rho_pi=0.30)
    dv.compute_all_derived()

    # ── Test 1: PRIMARY variable x_{i,z,t,p} ────────────────────────
    print("\n[Test 1] x_{i,z,t,p} — primary variable")
    assert dv.x("ssh_trap","DMZ",0,"HR_workstation") == 1, "Expected x=1"
    assert dv.x("ssh_trap","DMZ",0,"Finance_DB")     == 0, "Expected x=0"
    assert dv.x("db_trap", "Internal",1,"Finance_DB")== 1, "Expected x=1"
    print("  x_{ssh_trap,DMZ,0,HR}    = 1  ✓")
    print("  x_{ssh_trap,DMZ,0,Fin}   = 0  ✓")
    print("  x_{db_trap,Internal,1,Fin} = 1  ✓")

    # ── Test 2: x_{i,t} — collapsed C4 view ─────────────────────────
    print("\n[Test 2] x_{i,t} — derived C4 view")
    assert dv.x_it("ssh_trap", 0) == 1, "ssh_trap active at t=0"
    assert dv.x_it("smb_trap", 0) == 0, "smb_trap not in schedule"
    print(f"  x_{{ssh_trap,t=0}} = {dv.x_it('ssh_trap',0)}  ✓")
    print(f"  x_{{smb_trap,t=0}} = {dv.x_it('smb_trap',0)}  ✓")
    c4_v = dv.c4_violations()
    print(f"  C4 violations: {len(c4_v)}  ✓")

    # ── Test 3: u_{i,z,t} — type-discovery flag ──────────────────────
    print("\n[Test 3] u_{i,z,t} — type-discovery flag (C9)")
    # ssh_trap in DMZ active t=0,1,2,3 — τd = max(1, 3×0.70×1) = 2.1 → ceil = 3
    # 3 consecutive active slots (t=0,1,2) → burns at t=2 (3 consecutive)
    u_t0 = dv.u_type("ssh_trap","DMZ",0)
    u_t2 = dv.u_type("ssh_trap","DMZ",2)
    print(f"  u_type[ssh_trap,DMZ,t=0] = {u_t0}  (not yet burned)")
    print(f"  u_type[ssh_trap,DMZ,t=2] = {u_t2}  (3 consecutive slots)")
    print(f"  u_type[scada_trap,OT,t=3] = "
          f"{dv.u_type('scada_trap','OT',3)}  (4 consecutive > τd=2.1 → burned)")

    # ── Test 4: u_{i,z,t,p} — persona-discovery flag ─────────────────
    print("\n[Test 4] u_{i,z,t,p} — persona-discovery flag (C13)")
    # HR_workstation at ssh_trap/DMZ: active t=0 and t=1 → τdp=2 → burns at t=1
    u_p0 = dv.u_persona("ssh_trap","DMZ",0,"HR_workstation")
    u_p1 = dv.u_persona("ssh_trap","DMZ",1,"HR_workstation")
    u_p2 = dv.u_persona("ssh_trap","DMZ",2,"DevOps_server")  # rotated persona
    print(f"  u_persona[ssh_trap,DMZ,t=0,HR] = {u_p0}  (1 slot; τdp=2)")
    print(f"  u_persona[ssh_trap,DMZ,t=1,HR] = {u_p1}  (2 consecutive → burned)")
    print(f"  u_persona[ssh_trap,DMZ,t=2,DevOps] = {u_p2}  (rotated; fresh clock)")
    assert u_p1 == 1, "HR should be burned at t=1 after 2 consecutive slots"
    assert u_p2 == 0, "DevOps fresh rotation should NOT be burned"
    print("  Assertions passed ✓")

    # ── Test 5: dual_guard ───────────────────────────────────────────
    print("\n[Test 5] Dual guard (1−u_type)·(1−u_persona)")
    g_t0 = dv.dual_guard("ssh_trap","DMZ",0,"HR_workstation")
    print(f"  guard[ssh_trap,DMZ,t=0,HR] = {g_t0}  (should be 1 — undiscovered)")
    g_t1 = dv.dual_guard("ssh_trap","DMZ",1,"HR_workstation")
    print(f"  guard[ssh_trap,DMZ,t=1,HR] = {g_t1}  (persona burned → credit = 0)")

    # ── Test 6: c_{j,a,t} — detection ───────────────────────────────
    print("\n[Test 6] c_{j,a,t} — detection event")
    # db_trap covers T1048; Internal assets start at id=20
    internal_asset = CFG["A_per_zone"]["DMZ"]   # first Internal asset id
    c_val = dv.c("T1048", internal_asset, 0)
    print(f"  c_{{T1048, asset={internal_asset}(Internal), t=0}} = {c_val}")
    det_t0 = dv.detections_at(0)
    print(f"  Total detections at t=0: {len(det_t0)}")
    total_det = dv.detection_count()
    print(f"  Total detections across horizon: {total_det}")

    # ── Test 7: p_{π,h,t} — path coverage ───────────────────────────
    print("\n[Test 7] p_{π,h,t} — path hop coverage")
    p_pi1_h0_t0 = dv.p_path("pi1", 0, 0)  # DMZ hop of web-to-db at t=0
    p_pi1_h1_t0 = dv.p_path("pi1", 1, 0)  # Internal hop at t=0
    print(f"  p_{{pi1,hop0(DMZ),t=0}}      = {p_pi1_h0_t0}")
    print(f"  p_{{pi1,hop1(Internal),t=0}} = {p_pi1_h1_t0}")
    c10_v = dv.c10_violations()
    print(f"  C10 violations: {len(c10_v)}")

    # ── Test 8: e_{π,t} — early interception ────────────────────────
    print("\n[Test 8] e_{π,t} — early interception flag (C7)")
    e_pi1_t0 = dv.e_intercept("pi1", 0)
    print(f"  e_{{pi1,t=0}} = {e_pi1_t0}  "
          f"({'L4 ×1000 credit earned' if e_pi1_t0 else 'no early intercept'})")
    rate = dv.early_intercept_rate()
    print(f"  Early-intercept rate: {rate:.1f}%")

    # ── Full printout ────────────────────────────────────────────────
    dv.print_all(rho_pi=0.30)

    print("\n[✓] All decision-variable self-tests passed.")
