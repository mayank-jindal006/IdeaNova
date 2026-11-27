"""Stable digest of the exact persisted proposal and its source revision."""
import hashlib
import json


def proposal_digest(fix) -> str:
    payload = {
        "finding_id": fix.finding_id,
        "target_file": fix.target_file,
        "base_hash": fix.base_hash,
        "patch": fix.patch,
        "edits": fix.edits,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
