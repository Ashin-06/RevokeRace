"""Deterministic discrete-event revocation experiments with an independent time oracle."""

import copy
import hashlib
import json

from .capability import authenticate, mint
from .lab import canonical, fields, integer, text

APP_NAME = "RevokeRace"
TAGLINE = "Measure how long revoked authority remains usable when connectivity and clocks fail."
PORT = 8761
POLICIES = ("cached_ttl", "bounded_lease", "online_only")
CAPABILITIES = [
    "Compare wall-clock TTL caching, monotonic bounded leases, and online-only decisions on the same request schedule.",
    "Inject outages, clock offset/drift, rollback events, and tampered capability signatures.",
    "Measure stale grants after authority revocation separately from legitimate requests denied before revocation.",
    "Replay deterministic ledgers and sweep lease budgets. Immediate offline revocation is not claimed.",
]


def validate(scenario):
    fields(
        scenario,
        ("name", "duration", "revoke_at", "token_ttl", "lease_seconds", "devices"),
        ("step",),
    )
    text(scenario["name"], "name")
    duration = integer(scenario["duration"], "duration", 1, 3600)
    integer(scenario["revoke_at"], "revoke_at", 0, duration)
    integer(scenario["token_ttl"], "token_ttl", 1, 7200)
    integer(scenario["lease_seconds"], "lease_seconds", 0, 3600)
    step = integer(scenario.get("step", 1), "step", 1, 60)
    devices = scenario["devices"]
    if not isinstance(devices, list) or not 1 <= len(devices) <= 16:
        raise ValueError("Use 1–16 devices")
    if (duration // step + 1) * len(devices) * len(POLICIES) > 100000:
        raise ValueError("Scenario exceeds the 100,000-decision budget; increase step")
    names = set()
    for device in devices:
        fields(
            device,
            ("id", "outages"),
            ("offset", "drift_ppm", "rollback_at", "rollback_seconds", "tamper"),
        )
        name = text(device["id"], "device id", 64)
        if name in names:
            raise ValueError("Device identifiers must be unique")
        names.add(name)
        integer(device.get("offset", 0), "offset", -3600, 3600)
        integer(device.get("drift_ppm", 0), "drift_ppm", -100000, 100000)
        integer(device.get("rollback_seconds", 0), "rollback_seconds", 0, 7200)
        if device.get("rollback_at") is not None:
            integer(device["rollback_at"], "rollback_at", 0, duration)
        if type(device.get("tamper", False)) is not bool:
            raise ValueError("tamper must be a boolean")
        if not isinstance(device["outages"], list) or len(device["outages"]) > 20:
            raise ValueError("Use at most 20 outage intervals per device")
        for interval in device["outages"]:
            if not isinstance(interval, list) or len(interval) != 2:
                raise ValueError("Each outage is [start, end), in seconds")
            start = integer(interval[0], "outage start", 0, duration)
            end = integer(interval[1], "outage end", 1, duration + 1)
            if end <= start:
                raise ValueError("Outage end must follow start")
    return step


def _run(scenario):
    step = validate(scenario)
    # A public deterministic fixture key keeps experiments reproducible. It is
    # intentionally not a deployable secret or an independent trust authority.
    key = hashlib.sha256(b"RevokeRace fixture key\0" + canonical(scenario)).digest()
    events, statistics = [], []
    for policy in POLICIES:
        stats = {
            "policy": policy,
            "requests": 0,
            "stale_grants": 0,
            "legitimate_denials": 0,
            "last_stale_at": None,
            "observed_exposure_seconds": 0,
            "accepted": 0,
        }
        for device in scenario["devices"]:
            token = mint(key, device["id"], 0, scenario["token_ttl"])
            if device.get("tamper"):
                token = token[:-4] + "AAAA"
            try:
                claims = authenticate(key, token)
                valid = claims["subject"] == device["id"]
            except ValueError:
                valid = False
            known_revoked, last_contact = False, 0
            for now in range(0, scenario["duration"] + 1, step):
                online = not any(start <= now < end for start, end in device["outages"])
                revoked = now >= scenario["revoke_at"]
                if online:
                    last_contact = now
                    known_revoked = known_revoked or revoked
                local = (
                    now
                    + device.get("offset", 0)
                    + now * device.get("drift_ppm", 0) / 1000000
                )
                if (
                    device.get("rollback_at") is not None
                    and now >= device["rollback_at"]
                ):
                    local -= device.get("rollback_seconds", 0)
                age = now - last_contact
                if not valid:
                    allowed, reason = False, "invalid_signature"
                elif known_revoked:
                    allowed, reason = False, "revocation_observed"
                elif policy == "online_only" and not online:
                    allowed, reason = False, "online_check_required"
                elif (
                    policy == "bounded_lease"
                    and not online
                    and age >= scenario["lease_seconds"]
                ):
                    allowed, reason = False, "freshness_lease_expired"
                elif policy == "bounded_lease" and now >= scenario["token_ttl"]:
                    allowed, reason = False, "monotonic_token_expiry"
                elif policy == "online_only" and now >= scenario["token_ttl"]:
                    allowed, reason = False, "authority_token_expiry"
                elif policy != "online_only" and local >= scenario["token_ttl"]:
                    allowed, reason = False, "wall_clock_token_expiry"
                else:
                    allowed, reason = (
                        True,
                        "cached_authority" if not online else "authority_checked",
                    )
                stale = allowed and revoked
                # Availability is measured only for otherwise valid, unrevoked,
                # unexpired capabilities, against the authority's real-time oracle.
                legitimate = valid and not revoked and now < scenario["token_ttl"]
                stats["requests"] += 1
                stats["accepted"] += int(allowed)
                stats["stale_grants"] += int(stale)
                stats["legitimate_denials"] += int(legitimate and not allowed)
                if stale:
                    stats["last_stale_at"] = max(stats["last_stale_at"] or 0, now)
                events.append(
                    {
                        "time": now,
                        "policy": policy,
                        "device": device["id"],
                        "online": online,
                        "local_clock": round(local, 6),
                        "contact_age": age,
                        "allowed": allowed,
                        "reason": reason,
                        "authority_revoked": revoked,
                        "stale_grant": stale,
                    }
                )
        if stats["last_stale_at"] is not None:
            stats["observed_exposure_seconds"] = (
                stats["last_stale_at"] - scenario["revoke_at"]
            )
        statistics.append(stats)
    findings = []
    for row in statistics:
        if row["stale_grants"]:
            findings.append(
                {
                    "severity": "high",
                    "title": f"{row['policy']}: revoked requests accepted",
                    "detail": f"{row['stale_grants']} requests were accepted after authority revocation; the last observed stale request was {row['observed_exposure_seconds']} seconds after revocation.",
                }
            )
        if row["legitimate_denials"]:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"{row['policy']}: availability cost",
                    "detail": f"{row['legitimate_denials']} valid, unrevoked, unexpired requests were denied. This measures the cost of the policy on this schedule.",
                }
            )
    findings.append(
        {
            "severity": "info",
            "title": "A sampled exposure window is not a universal bound",
            "detail": "Time is simulated, requests are sampled at step intervals, and server contact is instantaneous when online. Monotonic rollback, malicious enforcement clients, and restored device snapshots are outside this model.",
        }
    )
    return {
        "summary": {
            "devices": len(scenario["devices"]),
            "decisions": len(events),
            "cached_stale": statistics[0]["stale_grants"],
            "lease_stale": statistics[1]["stale_grants"],
            "online_stale": statistics[2]["stale_grants"],
            "lease_seconds": scenario["lease_seconds"],
        },
        "findings": findings,
        "events": events,
        "details": {
            "scenario": scenario["name"],
            "time_unit": "seconds",
            "step": step,
            "outage_intervals": "start inclusive, end exclusive",
            "revocation_boundary": "requests at revoke_at are already revoked",
            "policies": statistics,
            "scenario_sha256": hashlib.sha256(canonical(scenario)).hexdigest(),
        },
    }


def execute(request):
    fields(request, ("scenario",), ("operation",))
    if request.get("operation", "run") != "run":
        raise ValueError("operation must be run")
    return _run(request["scenario"])


def presets():
    base = {
        "name": "Revocation during an outage",
        "duration": 180,
        "revoke_at": 40,
        "token_ttl": 120,
        "lease_seconds": 20,
        "step": 2,
        "devices": [
            {"id": "field-tablet", "outages": [[10, 150]]},
            {"id": "desk-client", "outages": []},
        ],
    }
    rollback = copy.deepcopy(base)
    rollback.update(
        name="Clock rollback extends cached authority", token_ttl=90, lease_seconds=15
    )
    rollback["devices"] = [
        {
            "id": "rollback-client",
            "outages": [[10, 180]],
            "rollback_at": 60,
            "rollback_seconds": 120,
        }
    ]
    gap = copy.deepcopy(base)
    gap.update(
        name="The unavoidable offline revocation gap", revoke_at=12, lease_seconds=30
    )
    tampered = copy.deepcopy(base)
    tampered.update(name="Tampered signed capability")
    tampered["devices"] = [
        {"id": "tampered-client", "outages": [[10, 150]], "tamper": True}
    ]
    return [
        {
            "id": ident,
            "title": scenario["name"],
            "summary": description,
            "input": {"scenario": scenario},
        }
        for ident, scenario, description in [
            (
                "outage",
                base,
                "One client loses connectivity while another receives revocation immediately.",
            ),
            (
                "rollback",
                rollback,
                "Wall-clock rollback is compared with a monotonic expiry and freshness lease.",
            ),
            (
                "offline-gap",
                gap,
                "A still-fresh offline lease can accept a newly revoked capability until its budget expires.",
            ),
            (
                "tamper",
                tampered,
                "All policies must reject a capability with an altered HMAC signature.",
            ),
        ]
    ]


def benchmark():
    return [
        {"scenario": item["id"], **execute(item["input"])["summary"]}
        for item in presets()
    ]


def add_commands(commands):
    sweep = commands.add_parser("sweep", help="Compare lease budgets on one scenario")
    sweep.add_argument("input")
    sweep.add_argument("--budgets", default="0,5,15,30,60")


def cli_request(args):
    from pathlib import Path
    from .lab import read_json

    request = read_json(Path(args.input).read_bytes())
    budgets = [integer(int(x), "budget", 0, 3600) for x in args.budgets.split(",")]
    if not 1 <= len(budgets) <= 20:
        raise ValueError("Use 1–20 budgets")
    rows = []
    for budget in budgets:
        item = copy.deepcopy(request)
        item["scenario"]["lease_seconds"] = budget
        rows.append(execute(item)["details"]["policies"][1])
    # Sweep is an analysis command, not an evidence input with hidden effects.
    print(json.dumps({"lease_sweep": rows}, indent=2))
    raise SystemExit(0)
