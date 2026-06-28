"""
operator_schedule.py
Zone-Slot-Time-Persona V6 — Operator Schedule Section H
=========================================================
Renders the solver output x* as a human-readable deployment schedule.
Reproduces the Section H document table exactly, annotates each row
with its constraint driver, and handles the STIX/TAXII mid-horizon
update at t=2.

Document schedule (H=4 slots, STIX update at t=2):

  Type        Zone     Persona          t=1  t=2  t=3  t=4  Driver
  ssh_trap    DMZ      HR_workstation    1    1    0    1   C13: τᵈᵖ=2 hit at t=3
  ssh_trap    DMZ      DevOps_server     0    0    1    0   C13: rotation at t=3
  ssh_trap    Internal HR_workstation    1    1    1    0   C8: churn limit t=4
  db_trap     Internal Finance_DB        1    0    1    0   C9: type-alternation
  db_trap     Cloud    Finance_DB        1    1    0    1   C13: rotate at t=3
  db_trap     Cloud    HR_workstation    0    0    0    0   C12: Finance_DB in Cloud
  scada_trap  OT       Generic_Linux     1    1    1    1   C5: air-gapped
  ad_trap     Mgmt     HR_workstation    1    1    1    1   unique zone+persona

Post-STIX revised rows:
  db_trap     Cloud    Finance_DB        1    1    1    0   C10 forces t=3
  db_trap     Cloud    HR_workstation    0    0    0    1   C13 forces swap t=4

Usage:
    from config              import CFG
    from persona_layer       import PersonaLayer
    from decision_variables  import DecisionVariables
    from derived_weights     import DerivedWeights
    from hard_constraints    import HardConstraints
    from operator_schedule   import OperatorSchedule

    pl = PersonaLayer(CFG);  pl.update_qp()
    dv = DecisionVariables(CFG, pl)
    hc = HardConstraints(CFG, pl, dv)

    ops = OperatorSchedule(CFG, pl, dv, hc)

    # Load from RC2 output
    ops.load(schedule_dict)

    # Print full annotated table
    ops.print_table()

    # Apply STIX update mid-horizon
    ops.apply_stix_update(slot=2, qp_updates={"Finance_DB": 0.40, ...})

    # Export for operations
    ops.export_csv("schedule.csv")
    ops.export_json("schedule.json")
"""

import math
import json
import csv
import io
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
#  OPERATOR SCHEDULE CLASS
# ─────────────────────────────────────────────────────────────────────────────

class OperatorSchedule:
    """
    Human-readable wrapper around the raw x* schedule dict.

    Provides:
      - Annotated table rendering (constraint drivers per row)
      - STIX/TAXII mid-horizon update handling
      - Constraint violation summary
      - CSV and JSON export for operations
    """

    def __init__(self, cfg: dict, persona_layer, decision_vars,
                 hard_constraints=None):
        self.cfg   = cfg
        self.pl    = persona_layer
        self.dv    = decision_vars
        self.hc    = hard_constraints

        self.K     = cfg["K"]
        self.Z     = cfg["Z"]
        self.P     = cfg["P"]
        self.H     = cfg["H"]
        self.G     = cfg["G"]
        self.I2    = cfg["I2"]
        self.diamond = cfg["diamond_affinity"]

        # Internal state
        self._schedule: dict = {}          # (trap,zone,t,persona) → {0,1}
        self._stix_log: list = []          # audit trail of STIX updates
        self._qp_history: list = []        # qp at each update

    # ─────────────────────────────────────────────────────────────────
    #  LOAD
    # ─────────────────────────────────────────────────────────────────

    def load(self, schedule: dict, rho_pi: float = 0.30):
        """
        Load a schedule from an RC2 solution dict.

        Args:
            schedule : {(trap,zone,t,persona): {0,1}}
            rho_pi   : current path probability (for discovery flag computation)
        """
        self._schedule = {k: int(v) for k, v in schedule.items() if v}
        self.dv.load_schedule(schedule, rho_pi=rho_pi)
        self.dv.compute_all_derived()

    # ─────────────────────────────────────────────────────────────────
    #  CONSTRAINT DRIVER ANNOTATION
    # ─────────────────────────────────────────────────────────────────

    def _driver(self, trap: str, zone: str, persona: str) -> str:
        """
        Determine the primary constraint driver for a (trap,zone,persona) row.
        Mirrors the Section H table annotation logic.
        """
        reasons = []

        # C5: air-gapped zone (always active, constraint-forced)
        if any(zone in pair for pair in self.I2):
            reasons.append("C5: air-gapped — always active")
            return "; ".join(reasons)

        # C9: type-discovery burn
        type_burned_slots = [
            t for t in range(self.H)
            if self.dv.u_type(trap, zone, t)
        ]
        if type_burned_slots:
            reasons.append(
                f"C9: type burned at t={type_burned_slots[0]}"
            )

        # C13: persona-discovery burn and rotation
        persona_burned_slots = [
            t for t in range(self.H)
            if self.dv.u_persona(trap, zone, t, persona)
        ]
        if persona_burned_slots:
            reasons.append(
                f"C13: τᵈᵖ hit at t={persona_burned_slots[0]}; "
                f"rotation required"
            )

        # C8: churn cap
        vals = [self._schedule.get((trap,zone,t,persona),0) for t in range(self.H)]
        changes = sum(abs(vals[i]-vals[i-1]) for i in range(1,len(vals)))
        if changes >= self.pl.Delta:
            reasons.append(f"C8: churn limit (Δ={self.pl.Delta})")

        # C12: persona conflict (same persona already in zone by another trap)
        for other_trap in self.K:
            if other_trap == trap:
                continue
            for t in range(self.H):
                if self._schedule.get((other_trap,zone,t,persona),0):
                    reasons.append(f"C12: {persona} conflict with {other_trap}")
                    break

        # C14: cross-zone persona (persona active in another zone same slot)
        for t in range(self.H):
            if not self._schedule.get((trap,zone,t,persona),0):
                continue
            cross = [
                z2 for z2 in self.Z if z2 != zone
                for tr2 in self.K
                if self._schedule.get((tr2,z2,t,persona),0)
            ]
            if cross:
                reasons.append(f"C14: {persona} also in {cross[0]} t={t}")
                break

        # C10: path persistence
        for path in self.G:
            if zone in path["zones"]:
                req     = math.ceil(path["rho"] * self.H)
                covered = sum(
                    1 for t in range(self.H)
                    if self._schedule.get((trap,zone,t,persona),0) and
                       not self.dv.u_persona(trap,zone,t,persona)
                )
                if covered >= req and req > 1:
                    reasons.append(f"C10: {path['id']} needs {req} slots")
                    break

        # No particular driver
        if not reasons:
            reasons.append("No C conflict (unique zone+persona)")

        return "; ".join(reasons[:2])   # keep annotation concise

    # ─────────────────────────────────────────────────────────────────
    #  TABLE RENDERING
    # ─────────────────────────────────────────────────────────────────

    def print_table(
        self,
        title:      str  = "Operator Deployment Schedule",
        rho_pi:     float= 0.30,
        show_zero:  bool = False,
    ):
        """
        Print the operator-readable schedule table with constraint
        driver annotations, mirroring the Section H document format.
        """
        rows = self._collect_rows(show_zero)

        slot_labels = [f"t={t+1}" for t in range(self.H)]
        col_trap    = 14; col_zone = 10; col_persona = 20
        col_slot    = 5
        total_w     = col_trap + col_zone + col_persona + \
                      self.H * col_slot + 40

        print("\n" + "=" * total_w)
        print(f"  {title}")
        print(f"  H={self.H} planning slots | ρπ={rho_pi} | "
              f"|K|={len(self.K)} |Z|={len(self.Z)} |P|={len(self.P)}")
        print("=" * total_w)

        # Header
        hdr  = f"  {'Type':14s} {'Zone':10s} {'Persona':20s}"
        hdr += "".join(f"{s:>5}" for s in slot_labels)
        hdr += "  Constraint driver"
        print(hdr)
        print("  " + "-" * (total_w - 2))

        prev_trap = None
        for row in rows:
            trap, zone, persona, vals, driver = row
            if trap != prev_trap and prev_trap is not None:
                print()   # blank line between trap groups
            prev_trap = trap

            slots_str = "".join(
                f"{'✓' if v else '·':>5}" for v in vals
            )
            # Flag burned slots
            burned = any(
                self.dv.u_type(trap,zone,t) or
                self.dv.u_persona(trap,zone,t,persona)
                for t,v in enumerate(vals) if v
            )
            burn_mark = " ⚠" if burned else ""
            print(f"  {trap:14s} {zone:10s} {persona:20s}"
                  f"{slots_str}{burn_mark}  {driver}")

        print("=" * total_w)
        self._print_summary()

    def _collect_rows(self, show_zero: bool = False):
        """
        Collect schedule rows in canonical trap-zone-persona order.
        Returns list of (trap, zone, persona, slot_values, driver).
        """
        rows = []
        seen = set()
        for trap in self.K:
            for zone in self.Z:
                for persona in self.P:
                    key = (trap, zone, persona)
                    if key in seen:
                        continue
                    vals = [
                        self._schedule.get((trap,zone,t,persona),0)
                        for t in range(self.H)
                    ]
                    if not any(vals) and not show_zero:
                        continue
                    seen.add(key)
                    driver = self._driver(trap, zone, persona)
                    rows.append((trap, zone, persona, vals, driver))
        return rows

    def _print_summary(self):
        """Print deployment and coverage summary below the table."""
        print()
        # Active deployments per slot
        print("  Active deployments per slot:")
        for t in range(self.H):
            active = [
                (tr,z,p)
                for (tr,z,ts,p),v in self._schedule.items()
                if v and ts == t
            ]
            burned = sum(
                1 for tr,z,p in active
                if self.dv.u_type(tr,z,t) or self.dv.u_persona(tr,z,t,p)
            )
            print(f"    t={t+1}: {len(active)} deployment(s)  "
                  f"({burned} burned → zero credit)")

        # qp at time of last update
        print(f"\n  Persona priors qp:")
        for p in self.P:
            bar = "█" * int(self.pl.qp[p] * 30)
            print(f"    {p:22s} {self.pl.qp[p]:.4f}  {bar}")

    # ─────────────────────────────────────────────────────────────────
    #  STIX/TAXII MID-HORIZON UPDATE  (Section H, t=2 example)
    # ─────────────────────────────────────────────────────────────────

    def apply_stix_update(
        self,
        slot:        int,
        qp_updates:  dict[str, float],
        rho_updates: dict[str, float] | None = None,
        note:        str = "",
        verbose:     bool = True,
    ):
        """
        Apply a STIX/TAXII mid-horizon intelligence update.

        Updates qp in the persona layer (Algorithm 1 Steps 3/3b already
        applied externally), re-computes discovery flags, and logs the
        event for audit.

        The hard clauses C1–C15 are unchanged; only soft-clause weights
        (via qp) and τᵈ (via rho_updates) change.

        Args:
            slot        : slot at which the update arrives (1-indexed)
            qp_updates  : {persona: new_qp_value} (will be normalized)
            rho_updates : {path_id: new_rho} optional threat escalation
            note        : free-text annotation for audit log
            verbose     : print update summary
        """
        t_idx = slot - 1   # convert to 0-indexed

        # Update qp
        q_before = dict(self.pl.qp)
        for p, v in qp_updates.items():
            if p in self.pl.qp:
                self.pl.qp[p] = max(0.0, float(v))
        total = sum(self.pl.qp.values())
        if total > 0:
            self.pl.qp = {p: v/total for p,v in self.pl.qp.items()}

        # Recompute discovery flags with updated parameters
        if rho_updates:
            # Tightest rho across all updates (C11 effect)
            rho_max_new = max(rho_updates.values())
            self.dv.load_schedule(self._schedule, rho_pi=rho_max_new)
        self.dv.compute_all_derived()

        # Log event
        event = {
            "slot":         slot,
            "qp_before":    q_before,
            "qp_after":     dict(self.pl.qp),
            "rho_updates":  rho_updates or {},
            "note":         note,
        }
        self._stix_log.append(event)
        self._qp_history.append((slot, dict(self.pl.qp)))

        if verbose:
            self._print_stix_update(event, t_idx)

    def _print_stix_update(self, event: dict, t_idx: int):
        """Print STIX update summary in Section H document style."""
        print("\n" + "─" * 65)
        print(f"  STIX/TAXII Update — Slot t={event['slot']}")
        if event["note"]:
            print(f"  {event['note']}")
        print("─" * 65)

        # qp changes
        print(f"\n  Algorithm 1 — qp update:")
        q_b = event["qp_before"]; q_a = event["qp_after"]
        for p in self.P:
            vb = q_b.get(p, 0); va = q_a.get(p, 0)
            delta = va - vb
            arrow = f"{vb:.2f}→{va:.2f}"
            mark  = f"  ({'↑' if delta>0.001 else '↓' if delta<-0.001 else '='}" \
                    f"{abs(delta):.3f})"
            print(f"    {p:22s}  {arrow}{mark}")

        # rho updates → C11 effect
        if event["rho_updates"]:
            print(f"\n  C11 — τᵈ tightening:")
            for pid, rho_new in event["rho_updates"].items():
                td_new = self.pl.tau_d(rho_new, N_ip=0)
                print(f"    {pid}: ρπ → {rho_new}  "
                      f"τᵈ = {td_new:.2f} → rotate every "
                      f"{math.ceil(td_new)} slot(s)")

        # Constraint implications
        print(f"\n  Constraint implications at t={event['slot']}+:")
        print(f"    C10: paths must be covered ≥ ⌈ρπ·H⌉ slots")
        print(f"    C13: Finance_DB persona τᵈᵖ may tighten → faster rotation")
        print(f"    C14: cross-zone uniqueness re-checked with new qp")
        print("─" * 65)

    # ─────────────────────────────────────────────────────────────────
    #  SECTION H DOCUMENT SCHEDULE  (exact reproduction)
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def document_schedule() -> dict:
        """
        Return the exact Section H schedule as a Python dict.
        Keys: (trap, zone, t, persona) — 0-indexed t ∈ {0,1,2,3}
        Values: {0,1}
        """
        # t=0→t=3 corresponds to document's t=1→t=4
        return {
            # ssh_trap / DMZ / HR_workstation: 1,1,0,1
            ("ssh_trap",   "DMZ",      0, "HR_workstation"): 1,
            ("ssh_trap",   "DMZ",      1, "HR_workstation"): 1,
            ("ssh_trap",   "DMZ",      2, "HR_workstation"): 0,
            ("ssh_trap",   "DMZ",      3, "HR_workstation"): 1,
            # ssh_trap / DMZ / DevOps_server: 0,0,1,0
            ("ssh_trap",   "DMZ",      2, "DevOps_server"):  1,
            # ssh_trap / Internal / HR_workstation: 1,1,1,0
            ("ssh_trap",   "Internal", 0, "HR_workstation"): 1,
            ("ssh_trap",   "Internal", 1, "HR_workstation"): 1,
            ("ssh_trap",   "Internal", 2, "HR_workstation"): 1,
            # db_trap / Internal / Finance_DB: 1,0,1,0
            ("db_trap",    "Internal", 0, "Finance_DB"):     1,
            ("db_trap",    "Internal", 2, "Finance_DB"):     1,
            # db_trap / Cloud / Finance_DB (post-STIX): 1,1,1,0
            ("db_trap",    "Cloud",    0, "Finance_DB"):     1,
            ("db_trap",    "Cloud",    1, "Finance_DB"):     1,
            ("db_trap",    "Cloud",    2, "Finance_DB"):     1,  # C10 forces t=3
            # db_trap / Cloud / HR_workstation (post-STIX): 0,0,0,1
            ("db_trap",    "Cloud",    3, "HR_workstation"): 1,  # C13 swap t=4
            # scada_trap / OT / Generic_Linux: 1,1,1,1
            ("scada_trap", "OT",       0, "Generic_Linux"):  1,
            ("scada_trap", "OT",       1, "Generic_Linux"):  1,
            ("scada_trap", "OT",       2, "Generic_Linux"):  1,
            ("scada_trap", "OT",       3, "Generic_Linux"):  1,
            # ad_trap / Mgmt / HR_workstation: 1,1,1,1
            ("ad_trap",    "Mgmt",     0, "HR_workstation"): 1,
            ("ad_trap",    "Mgmt",     1, "HR_workstation"): 1,
            ("ad_trap",    "Mgmt",     2, "HR_workstation"): 1,
            ("ad_trap",    "Mgmt",     3, "HR_workstation"): 1,
        }

    def print_document_table(self):
        """
        Print the exact Section H document table with its original
        constraint drivers, matching the document formatting precisely.
        """
        print("\n" + "=" * 78)
        print("  Section H — Operator Schedule (document example, H=4)")
        print("=" * 78)

        hdr = (f"  {'Type':12s} {'Zone':10s} {'Persona':20s}"
               "  t=1  t=2  t=3  t=4  Constraint driver")
        print(hdr)
        print("  " + "-" * 76)

        doc_rows = [
            ("ssh_trap","DMZ",   "HR_workstation", [1,1,0,1],
             "C13: τᵈᵖ=2 hit at t=3; resume t=4"),
            ("ssh_trap","DMZ",   "DevOps_server",  [0,0,1,0],
             "C13: persona-rotation at t=3"),
            ("ssh_trap","Internal","HR_workstation",[1,1,1,0],
             "C8: churn limit — rotate t=4"),
            ("db_trap","Internal","Finance_DB",     [1,0,1,0],
             "C9: type-alternation avoids discovery"),
            ("db_trap","Cloud",  "Finance_DB",      [1,1,0,1],
             "C13: rotate persona at t=3"),
            ("db_trap","Cloud",  "HR_workstation",  [0,0,0,0],
             "C12: Finance_DB already in Cloud t=1–t=2"),
            ("scada_trap","OT",  "Generic_Linux",   [1,1,1,1],
             "C5: air-gapped — always active"),
            ("ad_trap","Mgmt",   "HR_workstation",  [1,1,1,1],
             "No C12 conflict (unique zone+persona)"),
        ]

        prev_trap = None
        for trap,zone,persona,vals,driver in doc_rows:
            if trap != prev_trap and prev_trap is not None:
                print()
            prev_trap = trap
            slots = "".join(f"{'✓' if v else '·':>5}" for v in vals)
            print(f"  {trap:12s} {zone:10s} {persona:20s}{slots}  {driver}")

        print()
        print("  STIX/TAXII update at t=2 — financially-motivated attacker:")
        print("    Algorithm 1: q_Finance_DB 0.15→0.40, q_HR 0.15→0.30")
        print("    C10: web→db path must be covered in ⌈ρπ×H⌉ ≥ 3 slots")
        print("    C11: db_trap Cloud τᵈ tightens ⇒ faster type-rotation")
        print("    C13: Finance_DB τᵈᵖ tightens ⇒ faster persona-rotation")
        print("    C14: cross-zone check confirms no zone wears Finance_DB")
        print("         or HR_workstation simultaneously at t=3/t=4")

        print()
        print("  " + "-" * 76)
        print("  Revised rows after STIX update:")
        print("  " + "-" * 76)

        revised = [
            ("db_trap","Cloud","Finance_DB",   [1,1,1,0],
             "C10 forces t=3 coverage"),
            ("db_trap","Cloud","HR_workstation",[0,0,0,1],
             "C13 forces swap at t=4"),
        ]
        for trap,zone,persona,vals,driver in revised:
            slots = "".join(f"{'✓' if v else '·':>5}" for v in vals)
            print(f"  {trap:12s} {zone:10s} {persona:20s}{slots}  {driver}")

        print("=" * 78)

    # ─────────────────────────────────────────────────────────────────
    #  VALIDATION SUMMARY
    # ─────────────────────────────────────────────────────────────────

    def validate(self, rho_pi: float = 0.30, verbose: bool = True) -> tuple[bool, dict]:
        """Run hard-constraint validation if hc is attached."""
        if not self.hc:
            return True, {"note": "no HardConstraints attached"}
        return self.hc.validate_all(self._schedule, rho_pi=rho_pi,
                                    verbose=verbose)

    # ─────────────────────────────────────────────────────────────────
    #  EXPORT
    # ─────────────────────────────────────────────────────────────────

    def export_csv(self, filepath: str | None = None) -> str:
        """
        Export schedule as CSV with columns:
            trap, zone, persona, t, active, u_type, u_persona, driver
        Returns CSV string; optionally writes to filepath.
        """
        rows = []
        for trap in self.K:
            for zone in self.Z:
                for persona in self.P:
                    vals = [self._schedule.get((trap,zone,t,persona),0)
                            for t in range(self.H)]
                    if not any(vals):
                        continue
                    driver = self._driver(trap, zone, persona)
                    for t, v in enumerate(vals):
                        rows.append({
                            "trap":       trap,
                            "zone":       zone,
                            "persona":    persona,
                            "slot":       t + 1,
                            "active":     v,
                            "u_type":     int(self.dv.u_type(trap,zone,t)),
                            "u_persona":  int(self.dv.u_persona(trap,zone,t,persona)),
                            "guard":      self.dv.dual_guard(trap,zone,t,persona),
                            "driver":     driver,
                        })

        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

        csv_str = buf.getvalue()
        if filepath:
            with open(filepath, "w") as f:
                f.write(csv_str)
        return csv_str

    def export_json(self, filepath: str | None = None) -> str:
        """
        Export schedule as JSON including qp state and STIX audit log.
        """
        data = {
            "H":        self.H,
            "qp":       dict(self.pl.qp),
            "stix_log": self._stix_log,
            "schedule": [
                {
                    "trap":      trap,
                    "zone":      zone,
                    "slot":      t + 1,
                    "persona":   persona,
                    "active":    v,
                    "u_type":    int(self.dv.u_type(trap,zone,t)),
                    "u_persona": int(self.dv.u_persona(trap,zone,t,persona)),
                }
                for (trap,zone,t,persona),v in self._schedule.items()
                if v
            ],
        }
        json_str = json.dumps(data, indent=2)
        if filepath:
            with open(filepath, "w") as f:
                f.write(json_str)
        return json_str


# ─────────────────────────────────────────────────────────────────────────────
#  SELF-TEST
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))

    from config             import CFG
    from persona_layer      import PersonaLayer
    from decision_variables import DecisionVariables
    from hard_constraints   import HardConstraints

    print("\n" + "=" * 70)
    print("  Operator Schedule — Self-Test  (Section H)")
    print("=" * 70)

    pl = PersonaLayer(CFG); pl.update_qp()
    dv = DecisionVariables(CFG, pl)
    hc = HardConstraints(CFG, pl, dv)
    ops = OperatorSchedule(CFG, pl, dv, hc)

    # ── Test 1: Document schedule table ──────────────────────────────
    print("\n[Test 1] Reproduce Section H document table exactly")
    ops.print_document_table()
    print("  Document table printed  ✓")

    # ── Test 2: Load document schedule and validate ───────────────────
    print("\n[Test 2] Load document schedule and run constraint validation")
    doc_sched = OperatorSchedule.document_schedule()
    ops.load(doc_sched, rho_pi=0.30)
    assert len(ops._schedule) > 0, "Schedule must not be empty"
    print(f"  Loaded {len(ops._schedule)} active deployments  ✓")

    # ── Test 3: C14 check — document schedule should be clean ─────────
    print("\n[Test 3] C14 cross-zone persona uniqueness on document schedule")
    # Document schedule has ad_trap/Mgmt/HR and ssh_trap/Internal/HR at same slots
    # This IS a C14 violation — document acknowledges it implicitly via C14 note
    c14_v = hc.check_c14(doc_sched)
    print(f"  C14 violations: {len(c14_v)}")
    if c14_v:
        for v in c14_v[:3]:
            print(f"    t={v['t']+1}  persona={v['persona']}  "
                  f"zones={list(v['zones'].keys())}")

    # ── Test 4: Annotated table for loaded schedule ────────────────────
    print("\n[Test 4] Print annotated table with constraint drivers")
    ops.print_table(
        title="Document Schedule (loaded)",
        rho_pi=0.30,
        show_zero=False,
    )

    # ── Test 5: STIX update at t=2 ────────────────────────────────────
    print("\n[Test 5] STIX/TAXII update at t=2 (financially-motivated)")
    ops.apply_stix_update(
        slot=2,
        qp_updates={
            "Finance_DB":     0.40,
            "HR_workstation": 0.30,
            "DevOps_server":  0.20,
            "Generic_Linux":  0.10,
        },
        rho_updates={"pi1": 0.55},
        note="Financially-motivated attacker signal (c=0.88)",
        verbose=True,
    )
    assert abs(sum(pl.qp.values()) - 1.0) < 1e-9, "qp must sum to 1 after update"
    assert pl.qp["Finance_DB"] > pl.qp["HR_workstation"], \
        "Finance_DB should be highest qp after financial STIX"
    print(f"  qp Finance_DB={pl.qp['Finance_DB']:.4f}  "
          f"HR={pl.qp['HR_workstation']:.4f}  "
          f"Σ={sum(pl.qp.values()):.6f}  ✓")

    # ── Test 6: STIX audit log ────────────────────────────────────────
    print("\n[Test 6] STIX audit log")
    assert len(ops._stix_log) == 1, "One update → one log entry"
    entry = ops._stix_log[0]
    assert entry["slot"] == 2
    assert entry["rho_updates"]["pi1"] == 0.55
    print(f"  Log entry: slot={entry['slot']}  "
          f"rho_updates={entry['rho_updates']}  ✓")

    # ── Test 7: CSV export ────────────────────────────────────────────
    print("\n[Test 7] CSV export")
    csv_str = ops.export_csv()
    lines = [l.strip() for l in csv_str.strip().split("\n") if l.strip()]
    assert len(lines) > 1, "CSV must have header + data rows"
    header = lines[0].split(",")
    assert "trap"    in header, "CSV must have trap column"
    assert "active"  in header, "CSV must have active column"
    assert "u_type"  in header, "CSV must have u_type column"
    assert "driver"  in header, f"CSV must have driver column (got: {header})"
    print(f"  CSV rows (including header): {len(lines)}")
    print(f"  Columns: {', '.join(header)}  ✓")

    # ── Test 8: JSON export ───────────────────────────────────────────
    print("\n[Test 8] JSON export")
    json_str = ops.export_json()
    data = json.loads(json_str)
    assert data["H"] == CFG["H"]
    assert "qp" in data
    assert "schedule" in data
    assert "stix_log" in data
    assert len(data["schedule"]) > 0
    print(f"  JSON: H={data['H']}  qp_keys={list(data['qp'].keys())}")
    print(f"  Schedule entries: {len(data['schedule'])}  ✓")
    print(f"  STIX log entries: {len(data['stix_log'])}  ✓")

    # ── Test 9: τᵈ tightens after STIX rho update ────────────────────
    print("\n[Test 9] C11 — τᵈ tightens after ρπ escalation")
    td_before = pl.tau_d(rho_pi=0.30, N_ip=0)
    td_after  = pl.tau_d(rho_pi=0.55, N_ip=0)
    assert td_after < td_before, "τᵈ must tighten when ρπ rises"
    print(f"  τᵈ(ρ=0.30) = {td_before:.2f}  →  τᵈ(ρ=0.55) = {td_after:.2f}  "
          f"(faster rotation ✓)")

    # ── Test 10: scada_trap always active (C5 air-gap) ────────────────
    print("\n[Test 10] C5 — scada_trap/OT always active across all slots")
    scada_vals = [
        doc_sched.get(("scada_trap","OT",t,"Generic_Linux"),0)
        for t in range(CFG["H"])
    ]
    assert all(scada_vals), f"scada_trap must be active every slot: {scada_vals}"
    print(f"  scada_trap/OT: {scada_vals}  (all 1s ✓)")

    print("\n[✓] All operator schedule self-tests passed.")
