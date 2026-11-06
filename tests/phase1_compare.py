from pathlib import Path
import hashlib

pairs = [
    ("tx", "dist/python_tx.bin", "dist/goose_tx.bin"),
    ("state", "dist/python_state.bin", "dist/goose_state.bin"),
    ("invalid_state", "dist/python_invalid_state.bin", "dist/goose_invalid_state.bin"),
]

for name, expected_path, actual_path in pairs:
    expected = Path(expected_path).read_bytes()
    actual = Path(actual_path).read_bytes()

    if expected != actual:
        raise SystemExit(
            f"{name}: byte mismatch: expected={len(expected)} actual={len(actual)}"
        )

    print(
        f"{name.upper()}_SHA256="
        f"{hashlib.sha256(actual).hexdigest()}"
    )

print("PYTHON_GOOSE_BYTE_CONFORMANCE=GREEN")
