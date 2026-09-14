"""
Evidence preservation module.
Saves raw email bytes to the evidence vault and verifies cryptographic integrity.
"""

from pathlib import Path
from typing import Tuple

from app.evidence.hasher import calculate_sha256

# Root directory for preserved forensic artifacts
EVIDENCE_BASE_DIR = Path("evidence")


def preserve_evidence(
    case_id: str,
    raw_bytes: bytes,
    filename: str = "raw.eml",
    base_dir: Path = EVIDENCE_BASE_DIR,
    overwrite: bool = False,
) -> Tuple[Path, int, str]:
    """
    Preserve exact raw bytes into evidence vault at base_dir/{case_id}/{filename}.

    Args:
        case_id: Case identifier (e.g. MT-2026-000001).
        raw_bytes: Exact email file bytes.
        filename: Stored artifact name (defaults to 'raw.eml').
        base_dir: Evidence root directory.
        overwrite: If True, allow replacing existing artifact; if False, raise FileExistsError.

    Returns:
        Tuple of (stored_path, size_bytes, sha256)

    Raises:
        FileExistsError: If evidence file already exists and overwrite is False.
        ValueError: If read-back integrity check fails.
    """
    case_dir = Path(base_dir) / case_id
    case_dir.mkdir(parents=True, exist_ok=True)

    evidence_path = case_dir / filename
    if evidence_path.exists() and not overwrite:
        raise FileExistsError(f"Evidence artifact already exists at '{evidence_path}'. Overwrite not permitted.")

    # Write exact bytes without alteration
    evidence_path.write_bytes(raw_bytes)

    # Verify write integrity by reading back
    stored_bytes = evidence_path.read_bytes()
    size_bytes = len(stored_bytes)
    sha256_stored = calculate_sha256(stored_bytes)
    sha256_expected = calculate_sha256(raw_bytes)

    if sha256_stored != sha256_expected:
        raise ValueError(
            f"Forensic integrity check failed! Expected SHA-256 {sha256_expected}, got {sha256_stored}"
        )

    return evidence_path, size_bytes, sha256_stored
