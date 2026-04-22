#!/usr/bin/env python3
"""
In-process BART zero-shot classification runner for the Go correlation engine.

Protocol:
- Reads one JSON object per line from stdin.
- Writes one JSON object per line to stdout.

Request shape:
{
  "text": "...",
  "threshold": 0.30,
  "labels": ["Malicious", "Benign"]
}

Response shape:
{
  "classification": "malicious|benign",
  "confidence": 0.0,
  "scores": {"Malicious": 0.0, "Benign": 0.0},
  "model": "facebook/bart-large-mnli"
}
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, Any

from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline


def build_classifier(model_ref: str):
    tokenizer = AutoTokenizer.from_pretrained(model_ref)
    model = AutoModelForSequenceClassification.from_pretrained(model_ref)
    return pipeline("zero-shot-classification", model=model, tokenizer=tokenizer)


def safe_response(payload: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BART in-process runner")
    parser.add_argument("--model-id", default="facebook/bart-large-mnli")
    parser.add_argument("--model-path", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    model_ref = args.model_path.strip() or args.model_id.strip() or "facebook/bart-large-mnli"

    try:
        classifier = build_classifier(model_ref)
        safe_response({"ready": True, "model": model_ref})
    except Exception as exc:
        safe_response({"ready": False, "error": str(exc), "model": model_ref})
        return 1

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
            text = str(req.get("text", ""))
            labels = req.get("labels") or ["Malicious", "Benign"]

            result = classifier(text, candidate_labels=labels, multi_label=False)

            labels_out = result.get("labels", [])
            scores_out = result.get("scores", [])
            score_map = {str(lbl): float(score) for lbl, score in zip(labels_out, scores_out)}

            top_label = str(labels_out[0]).lower() if labels_out else "benign"
            top_conf = float(scores_out[0]) if scores_out else 0.0

            safe_response(
                {
                    "classification": top_label,
                    "confidence": top_conf,
                    "scores": score_map,
                    "model": model_ref,
                }
            )
        except Exception as exc:
            safe_response(
                {
                    "classification": "benign",
                    "confidence": 0.0,
                    "error": str(exc),
                    "model": model_ref,
                }
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
