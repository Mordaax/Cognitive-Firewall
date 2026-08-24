"""Print case-level detector metrics and warm p95 latency on synthetic fixtures."""

from __future__ import annotations

import json
import runpy
import statistics
import time
from pathlib import Path

from cognitive_firewall.detectors.injection import detect_injection
from cognitive_firewall.detectors.pii import detect_pii
from cognitive_firewall.engine import Evaluator
from cognitive_firewall.policy.loader import load_policy
from cognitive_firewall.schemas import EvaluationRequest, Operation
from cognitive_firewall.storage.audit import SqlAuditStore
from cognitive_firewall.storage.db import Database
from cognitive_firewall.storage.mappings import SqlMappingStore


def counts(labels: list[bool], predictions: list[bool]) -> dict[str, float | int]:
    tp = sum(label and prediction for label, prediction in zip(labels, predictions))
    fp = sum(not label and prediction for label, prediction in zip(labels, predictions))
    fn = sum(label and not prediction for label, prediction in zip(labels, predictions))
    tn = sum(not label and not prediction for label, prediction in zip(labels, predictions))
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "tests/security/test_regression_corpus.py"
    cases = runpy.run_path(str(path))["CORPUS"]
    pii_labels, pii_predictions = [], []
    injection_labels, injection_predictions = [], []
    for _, payload, pii, injection, _ in cases:
        pii_labels.append(pii)
        pii_predictions.append(bool(detect_pii(payload)))
        injection_labels.append(injection)
        injection_predictions.append(
            any(finding.severity >= 80 for finding in detect_injection(payload, source="retrieval"))
        )
    durations = []
    for _ in range(20):
        for _, payload, *_ in cases:
            start = time.perf_counter_ns()
            detect_pii(payload)
            detect_injection(payload, source="retrieval")
            durations.append((time.perf_counter_ns() - start) / 1_000_000)
    db = Database("sqlite:///:memory:")
    db.create_all()
    engine = Evaluator(
        load_policy(root / "policies/default.yaml"),
        SqlAuditStore(db),
        SqlMappingStore(db, encryption_key=b"e" * 32, hmac_key=b"h" * 32),
    )
    evaluation_durations = []
    for _ in range(10):
        for _, payload, *_ in cases:
            request = EvaluationRequest(
                operation=Operation.MODEL_INPUT,
                payload=payload,
                source="user",
                destination="openai",
                case_id="bench",
                agent_id="bench",
            )
            start = time.perf_counter_ns()
            engine.evaluate(request)
            evaluation_durations.append((time.perf_counter_ns() - start) / 1_000_000)
    report = {
        "cases": len(cases),
        "pii": counts(pii_labels, pii_predictions),
        "injection": counts(injection_labels, injection_predictions),
        "p95_detector_latency_ms": round(statistics.quantiles(durations, n=100)[94], 4),
        "iterations": len(durations),
        "p95_local_evaluation_latency_ms": round(
            statistics.quantiles(evaluation_durations, n=100)[94], 4
        ),
        "evaluation_iterations": len(evaluation_durations),
        "known_misses": [
            name
            for name, payload, _, injection, supported in cases
            if not supported
            and injection
            and not any(
                finding.severity >= 80 for finding in detect_injection(payload, source="retrieval")
            )
        ],
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
