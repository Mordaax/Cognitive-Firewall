"""Optional strictly offline prompt-injection classifier adapter."""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


class SemanticScreeningError(RuntimeError):
    """Screening could not cover or classify the entire input safely."""


class LocalSemanticDetector:
    """Return explicit malicious-label probability; any failure raises."""

    def __init__(self, model_path: str, *, malicious_labels: set[str],
                 max_input_bytes: int = 65_536, pipeline: Any = None):
        try:
            path = Path(model_path)
            if not path.is_absolute() or not path.is_dir():
                raise ValueError('an existing absolute local model directory is required')
            if not malicious_labels or max_input_bytes < 1:
                raise ValueError('explicit malicious labels and positive bound required')
            if pipeline is None:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                from transformers import pipeline as build_pipeline

                tokenizer = AutoTokenizer.from_pretrained(
                    str(path), local_files_only=True, trust_remote_code=False)
                model = AutoModelForSequenceClassification.from_pretrained(
                    str(path), local_files_only=True, trust_remote_code=False,
                    use_safetensors=True)
                pipeline = build_pipeline('text-classification', model=model, tokenizer=tokenizer)
            self._pipeline = pipeline
            self._labels = set(pipeline.model.config.id2label.values())
            self._malicious = set(malicious_labels)
            if (len(self._labels) < 2 or not self._malicious <= self._labels
                    or self._malicious == self._labels):
                raise ValueError('malicious labels must match a subset of model labels')
            bounds = [getattr(pipeline.tokenizer, 'model_max_length', None),
                      getattr(pipeline.model.config, 'max_position_embeddings', None)]
            self._token_limit = min(x for x in bounds if isinstance(x, int) and 0 < x < 1_000_000)
            self._max_bytes = max_input_bytes
        except Exception as exc:
            raise SemanticScreeningError('local semantic initialization failed') from exc

    def score(self, payload: str | dict[str, Any]) -> float:
        """Score all input, rejecting inputs larger than the model context."""
        try:
            if not isinstance(payload, (str, dict)):
                raise ValueError('payload must be text or an object')
            text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
            if len(text.encode('utf-8')) > self._max_bytes:
                raise ValueError('semantic input exceeds byte limit')
            tokens = self._pipeline.tokenizer(text, truncation=False, add_special_tokens=True)
            if len(tokens['input_ids']) > self._token_limit:
                raise ValueError('semantic input exceeds model token context')
            output = self._pipeline(text, truncation=False, top_k=None)
            if not isinstance(output, list) or len(output) != len(self._labels):
                raise ValueError('classifier did not return all labels')
            scores = {}
            for item in output:
                label, value = item['label'], item['score']
                if (label not in self._labels or label in scores or isinstance(value, bool)
                        or not isinstance(value, (int, float)) or not math.isfinite(value)
                        or not 0 <= value <= 1):
                    raise ValueError('invalid classifier label or probability')
                scores[label] = float(value)
            if set(scores) != self._labels or not math.isclose(sum(scores.values()), 1, abs_tol=1e-4):
                raise ValueError('classifier probabilities are incomplete or unnormalized')
            return min(1.0, sum(scores[label] for label in self._malicious))
        except Exception as exc:
            raise SemanticScreeningError('semantic screening failed') from exc
