from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct

TX_DOMAIN = b"FLOCKTX1"
STATE_DOMAIN = b"FLOCKSTATE1"
MAX_PAYLOAD = 4096
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1

@dataclass(frozen=True)
class Tx:
    chain_id: int
    nonce: int
    sender: bytes
    recipient: bytes
    amount: int
    compute_limit: int
    state_limit: int
    memory_limit: int
    payload: bytes = b""

def _check_u32(v: int) -> None:
    if not 0 <= v <= U32_MAX:
        raise ValueError("u32 out of range")

def _check_u64(v: int) -> None:
    if not 0 <= v <= U64_MAX:
        raise ValueError("u64 out of range")

def encode_tx(tx: Tx) -> bytes:
    if len(tx.sender) != 32 or len(tx.recipient) != 32:
        raise ValueError("account id must be exactly 32 bytes")
    if len(tx.payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    _check_u32(tx.chain_id)
    for value in (tx.nonce, tx.amount, tx.compute_limit, tx.state_limit, tx.memory_limit):
        _check_u64(value)
    return b"".join((
        TX_DOMAIN,
        struct.pack(">I", tx.chain_id),
        struct.pack(">Q", tx.nonce),
        tx.sender,
        tx.recipient,
        struct.pack(">Q", tx.amount),
        struct.pack(">Q", tx.compute_limit),
        struct.pack(">Q", tx.state_limit),
        struct.pack(">Q", tx.memory_limit),
        struct.pack(">I", len(tx.payload)),
        tx.payload,
    ))

def apply_tx(state: dict[bytes, tuple[int, int]], tx: Tx):
    nxt = dict(state)
    if len(tx.payload) > MAX_PAYLOAD or tx.amount == 0 or tx.sender == tx.recipient:
        return nxt, False
    sender = nxt.get(tx.sender)
    if sender is None:
        return nxt, False
    sender_nonce, sender_balance = sender
    if sender_nonce == U64_MAX or tx.nonce != sender_nonce or sender_balance < tx.amount:
        return nxt, False
    recipient_nonce, recipient_balance = nxt.get(tx.recipient, (0, 0))
    if recipient_balance > U64_MAX - tx.amount:
        return nxt, False
    nxt[tx.sender] = (sender_nonce + 1, sender_balance - tx.amount)
    nxt[tx.recipient] = (recipient_nonce, recipient_balance + tx.amount)
    return nxt, True

def encode_state(state: dict[bytes, tuple[int, int]]) -> bytes:
    if len(state) > U32_MAX:
        raise ValueError("too many accounts")
    out = bytearray(STATE_DOMAIN)
    out += struct.pack(">I", len(state))
    for address in sorted(state):
        if len(address) != 32:
            raise ValueError("account id must be exactly 32 bytes")
        nonce, balance = state[address]
        _check_u64(nonce); _check_u64(balance)
        out += address
        out += struct.pack(">Q", nonce)
        out += struct.pack(">Q", balance)
    return bytes(out)

def fingerprint(state) -> str:
    return hashlib.sha256(encode_state(state)).hexdigest()
