import copy
import random
import unittest

from revokerace import engine
from revokerace.capability import authenticate, mint


class RevocationTests(unittest.TestCase):
    def test_generated_schedules_obey_revocation_and_expiry_invariants(self):
        rng = random.Random(20261015)
        for case in range(100):
            request = self.preset("outage")
            scenario = request["scenario"]
            scenario.update(
                duration=60,
                step=1,
                revoke_at=rng.randrange(61),
                token_ttl=rng.randrange(1, 100),
                lease_seconds=rng.randrange(31),
            )
            start = rng.randrange(50)
            scenario["devices"] = [
                {
                    "id": "generated",
                    "outages": [[start, rng.randrange(start + 1, 62)]],
                    "offset": rng.randrange(-30, 31),
                    "rollback_at": rng.randrange(61),
                    "rollback_seconds": rng.randrange(121),
                }
            ]
            result = engine.execute(request)
            for event in result["events"]:
                with self.subTest(
                    case=case, time=event["time"], policy=event["policy"]
                ):
                    if event["policy"] == "online_only" and event["stale_grant"]:
                        self.fail("Online enforcement accepted revoked authority")
                    if event["policy"] == "bounded_lease" and event["allowed"]:
                        self.assertLess(event["time"], scenario["token_ttl"])
                        if not event["online"]:
                            self.assertLess(
                                event["contact_age"], scenario["lease_seconds"]
                            )
                    self.assertEqual(
                        event["stale_grant"],
                        event["allowed"] and event["time"] >= scenario["revoke_at"],
                    )

    def preset(self, ident):
        return copy.deepcopy(
            next(p["input"] for p in engine.presets() if p["id"] == ident)
        )

    def test_baseline_has_measured_stale_grants(self):
        result = engine.execute(self.preset("outage"))
        self.assertEqual(result["summary"]["cached_stale"], 40)
        self.assertEqual(result["summary"]["lease_stale"], 0)
        self.assertEqual(result["summary"]["online_stale"], 0)

    def test_a_fresh_offline_lease_does_not_claim_instant_revocation(self):
        result = engine.execute(self.preset("offline-gap"))
        self.assertGreater(result["summary"]["lease_stale"], 0)
        self.assertEqual(result["summary"]["online_stale"], 0)

    def test_rollback_extends_cached_ttl_but_not_monotonic_expiry(self):
        request = self.preset("rollback")
        rolled = engine.execute(request)
        request["scenario"]["devices"][0]["rollback_seconds"] = 0
        normal = engine.execute(request)
        self.assertGreater(
            rolled["summary"]["cached_stale"], normal["summary"]["cached_stale"]
        )
        self.assertEqual(
            rolled["summary"]["lease_stale"], normal["summary"]["lease_stale"]
        )

    def test_exact_revocation_and_lease_boundaries(self):
        request = {
            "scenario": {
                "name": "boundary",
                "duration": 6,
                "revoke_at": 2,
                "token_ttl": 10,
                "lease_seconds": 3,
                "devices": [{"id": "one", "outages": [[1, 7]]}],
            }
        }
        result = engine.execute(request)
        rows = {
            e["time"]: e for e in result["events"] if e["policy"] == "bounded_lease"
        }
        self.assertTrue(rows[2]["stale_grant"])
        self.assertFalse(rows[3]["allowed"])
        self.assertEqual(rows[3]["reason"], "freshness_lease_expired")

    def test_online_clients_observe_revocation_and_never_forget_it(self):
        result = engine.execute(self.preset("outage"))
        rows = [
            e
            for e in result["events"]
            if e["device"] == "desk-client" and e["time"] >= 40
        ]
        self.assertTrue(all(not e["allowed"] for e in rows))

    def test_signed_claim_tampering_is_rejected(self):
        key = b"test-only-key"
        token = mint(key, "client", 0, 60)
        self.assertEqual(authenticate(key, token)["subject"], "client")
        with self.assertRaises(ValueError):
            authenticate(b"wrong-key", token)
        result = engine.execute(self.preset("tamper"))
        self.assertTrue(
            all(e["reason"] == "invalid_signature" for e in result["events"])
        )

    def test_budget_duplicate_devices_and_boolean_numbers_rejected(self):
        for mutation in ("budget", "duplicate", "boolean"):
            with self.subTest(mutation=mutation):
                request = self.preset("outage")
                if mutation == "budget":
                    request["scenario"]["duration"] = 3600
                    request["scenario"]["step"] = 1
                    request["scenario"]["devices"] = [
                        {"id": str(i), "outages": []} for i in range(16)
                    ]
                elif mutation == "duplicate":
                    request["scenario"]["devices"][1]["id"] = "field-tablet"
                else:
                    request["scenario"]["duration"] = True
                with self.assertRaises(ValueError):
                    engine.execute(request)

    def test_results_are_deterministic_and_record_availability_cost(self):
        request = self.preset("outage")
        result = engine.execute(request)
        self.assertEqual(result, engine.execute(request))
        self.assertGreater(result["details"]["policies"][2]["legitimate_denials"], 0)

    def test_zero_lease_fails_closed_while_offline(self):
        request = self.preset("offline-gap")
        request["scenario"]["lease_seconds"] = 0
        result = engine.execute(request)
        self.assertFalse(
            any(
                e["allowed"]
                for e in result["events"]
                if e["policy"] == "bounded_lease" and not e["online"]
            )
        )
