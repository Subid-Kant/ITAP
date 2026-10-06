"""
ITAP v2.0 — telemetry fingerprint deduplication and lock lifecycle.

The previous version of this file asserted against ``TelemetryCollector.DATASET_PATH``
directly, which is the *real* ML training corpus at ``data/telemetry_dataset.jsonl``.
Every run appended five rows to the dataset the models train on — ``data/
telemetry_history.json`` still carries the ``concurrent-test-*`` domains it left
behind — and because dedup is stateful, the assertions only held the first time:
the second run found the fingerprint already recorded and produced zero eligible
records. It also wired nothing else up, leaving the collector's class-level state
and whatever corpus a previous developer had already written to decide the outcome.

Here the corpus is redirected into pytest's tmp dir by the shared autouse
``isolate_telemetry`` fixture, and the tests cover both directions of the
dedup contract: identical scans must collapse to one training candidate, and
genuinely different scans must not be collapsed — including when those scans
arrive from different threads and different event loops.
"""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import uuid

from app.services.telemetry_service import TelemetryCollector


def osint_payload(open_ports=(80, 443), cve="CVE-2021-1234"):
    return {
        "summary": {"open_ports": list(open_ports)},
        "vulnerabilities_by_service": [
            {
                "service": "nginx",
                "port": 443,
                "version": "1.18",
                "cves": [{"cve_id": cve}],
            }
        ],
    }


def dataset_rows():
    """Parse the isolated JSONL corpus the collector was pointed at."""
    with open(TelemetryCollector.DATASET_PATH, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def log_scan(domain, osint_data=None):
    return TelemetryCollector.log_scan(
        domain=domain,
        osint_data=osint_data or osint_payload(),
        lstm_results={"prediction": "exploit"},
        autoencoder_results={"anomaly_score": 0.5},
        llm_output={"triage": "critical"},
        model_metadata={"test": True},
    )


def unique_domain(prefix):
    return f"{prefix}-{uuid.uuid4().hex}.example.com"


async def burst(domain, times):
    """N identical scans in flight at once inside the caller's loop."""
    return await asyncio.gather(*(log_scan(domain) for _ in range(times)))


def scan_in_fresh_loop(domain, times):
    """
    Run ``times`` concurrent scans on a throwaway event loop. This is how a
    background monitor, a worker thread or an ``ai_training/`` script reaches the
    collector: a loop that is not the API's loop.
    """
    return asyncio.run(burst(domain, times))


def test_isolation_fixture_moves_the_corpus_off_the_repo(isolate_telemetry, tmp_path):
    """
    Guard the guard: if a future fixture stops redirecting, these tests would
    silently go back to writing into the real training corpus.
    """
    dataset = Path(TelemetryCollector.DATASET_PATH)
    history = Path(TelemetryCollector.HISTORY_PATH)
    assert tmp_path in dataset.resolve().parents, dataset
    assert tmp_path in history.resolve().parents, history
    assert not dataset.exists(), "telemetry corpus leaked in from a previous run"


def test_scans_survive_a_change_of_event_loop(isolate_telemetry):
    """
    Two successive event loops, each running a concurrent burst. The collector keeps
    class-level state, so the second loop must neither crash nor lose the dedup
    index the first one built.
    """
    first, second = unique_domain("loop-a"), unique_domain("loop-b")
    scan_in_fresh_loop(first, 4)     # loop #1
    scan_in_fresh_loop(second, 4)    # loop #2, same process, same collector

    rows = dataset_rows()
    for domain in (first, second):
        scoped = [row for row in rows if row["domain"] == domain]
        assert len(scoped) == 4, f"{domain}: all four scans must be recorded"
        assert sum(1 for row in scoped if row["training_eligible"]) == 1, (
            f"{domain}: dedup must survive the loop handoff, not reset or collapse"
        )


def test_scans_from_many_threads_and_loops_yield_one_candidate(isolate_telemetry):
    """
    Eight worker threads, each with its own event loop, scanning the same domain at
    once — the shape the dedup contract really has to hold in a deployed system (API
    loop + background monitors + CLI jobs), and the shape the original ``asyncio``
    lock could not serve: it only ever serialised tasks inside one loop, so parallel
    loops raced, and a contended cross-loop await raises RuntimeError outright.

    A threading lock covers every thread and loop in the process. Multi-process
    writers still need OS file locking; see the note on TelemetryCollector._write_lock.
    """
    domain = unique_domain("threaded")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: scan_in_fresh_loop(domain, 1), range(8)))

    rows = [row for row in dataset_rows() if row["domain"] == domain]
    assert len(rows) == 8, "every thread's scan must be recorded"
    assert sum(1 for row in rows if row["training_eligible"]) == 1, (
        "parallel cross-thread scans must still collapse to one training candidate"
    )


async def test_concurrent_identical_scans_produce_exactly_one_candidate(isolate_telemetry):
    """
    The race the transaction lock exists for: five identical scans in flight at
    once all read "no previous fingerprint" and used to each record a candidate,
    multiplying one observation into five training labels.
    """
    domain = unique_domain("concurrent-identical")
    await asyncio.gather(*(log_scan(domain) for _ in range(5)))

    rows = [row for row in dataset_rows() if row["domain"] == domain]
    eligible = [row for row in rows if row["training_eligible"]]
    duplicates = [row for row in rows if not row["training_eligible"]]

    assert len(rows) == 5, "every scan must be recorded, eligible or not"
    assert len(eligible) == 1, f"expected exactly 1 candidate, got {len(eligible)}"
    assert len(duplicates) == 4

    fingerprint = eligible[0]["fingerprint"]
    for row in duplicates:
        assert row["fingerprint"] == fingerprint
        assert row["duplicate_of"] == fingerprint, "duplicates must cite their origin"
        assert row["reason"] == "unchanged_scan_state"


async def test_concurrent_scans_of_different_domains_stay_independent(isolate_telemetry):
    """
    The other failure mode: an over-broad lock or a domain-blind fingerprint
    collapses unrelated assets into a single record. Dedup must be per domain.
    """
    domains = [unique_domain(f"multi-{i}") for i in range(6)]
    await asyncio.gather(*(log_scan(d) for d in domains for _ in range(2)))

    rows = dataset_rows()
    assert len(rows) == 12
    for domain in domains:
        scoped = [row for row in rows if row["domain"] == domain]
        assert len(scoped) == 2, domain
        assert sum(1 for row in scoped if row["training_eligible"]) == 1, domain


async def test_history_tracks_the_latest_fingerprint_per_domain(isolate_telemetry):
    """``telemetry_history.json`` is the dedup index; it must stay consistent."""
    domain = unique_domain("history")
    await log_scan(domain)

    with open(TelemetryCollector.HISTORY_PATH, "r", encoding="utf-8") as handle:
        history = json.load(handle)

    assert domain in history
    assert history[domain]["fingerprint"] == TelemetryCollector.generate_fingerprint(
        domain, osint_payload()
    )
    assert history[domain]["last_event_id"].startswith("evt-")


async def test_changed_scan_state_is_not_suppressed_as_a_duplicate(isolate_telemetry):
    """
    Dedup that ignored real change would starve the training set: a scan that sees
    a new CVE is a new observation even on the same domain.
    """
    domain = unique_domain("changed-state")
    await log_scan(domain, osint_payload(open_ports=(80,)))
    await log_scan(domain, osint_payload(open_ports=(80, 443, 8443)))
    await log_scan(domain, osint_payload(open_ports=(80, 443, 8443), cve="CVE-2023-9999"))

    rows = [row for row in dataset_rows() if row["domain"] == domain]
    assert len(rows) == 3
    assert [row["training_eligible"] for row in rows] == [True, True, True], (
        "each distinct scan state must be recorded as a new candidate"
    )
    assert len({row["fingerprint"] for row in rows}) == 3


async def test_event_ids_are_unique_across_a_burst(isolate_telemetry):
    """
    event_id keys rows in the training corpus. It was derived from
    ``datetime.utcnow()``, whose Windows tick is coarse enough that a burst of
    scans shared an id — now it also mixes in uuid4 entropy.
    """
    domain = unique_domain("event-ids")
    await asyncio.gather(*(log_scan(domain) for _ in range(12)))

    ids = [row["event_id"] for row in dataset_rows() if row["domain"] == domain]
    assert len(ids) == 12
    assert len(set(ids)) == 12, f"event_id collision inside a burst: {ids}"
