from __future__ import annotations
import hashlib

TX_MAGIC = b"FLOCKTX1"
STATE_MAGIC = b"FLOCKSTATE1"
MAX_PAYLOAD = 4096
MAX64 = 0xFFFFFFFFFFFFFFFF

def be(value: int, width: int) -> bytes:
    if value < 0 or value >= (1 << (width * 8)):
        raise ValueError("integer outside canonical width")
    return value.to_bytes(width, "big")

def encode_transaction(t: dict) -> bytes:
    if len(t["sender"]) != 32 or len(t["recipient"]) != 32:
        raise ValueError("account id width")
    if len(t["payload"]) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    return b"".join((
        TX_MAGIC, be(t["chain_id"], 4), be(t["nonce"], 8), t["sender"], t["recipient"],
        be(t["amount"], 8), be(t["compute_limit"], 8), be(t["state_limit"], 8),
        be(t["memory_limit"], 8), be(len(t["payload"]), 4), t["payload"],
    ))

def transition(state: dict[bytes, dict], t: dict):
    original = {k: {"nonce": v["nonce"], "balance": v["balance"]} for k, v in state.items()}
    result = {k: {"nonce": v["nonce"], "balance": v["balance"]} for k, v in state.items()}
    src = result.get(t["sender"])
    valid = (
        len(t["payload"]) <= MAX_PAYLOAD and src is not None and t["amount"] > 0
        and t["sender"] != t["recipient"] and src["nonce"] != MAX64
        and src["nonce"] == t["nonce"] and src["balance"] >= t["amount"]
    )
    if not valid:
        return original, False
    dst = result.setdefault(t["recipient"], {"nonce": 0, "balance": 0})
    if dst["balance"] + t["amount"] > MAX64:
        return original, False
    src["balance"] -= t["amount"]
    src["nonce"] += 1
    dst["balance"] += t["amount"]
    return result, True

def state_bytes(state: dict[bytes, dict]) -> bytes:
    parts = [STATE_MAGIC, be(len(state), 4)]
    for address in sorted(state):
        a = state[address]
        parts.extend((address, be(a["nonce"], 8), be(a["balance"], 8)))
    return b"".join(parts)

def fingerprint(state) -> str:
    return hashlib.sha256(state_bytes(state)).hexdigest()
