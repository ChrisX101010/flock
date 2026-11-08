from __future__ import annotations
from dataclasses import dataclass
import hashlib
import struct

TX_DOMAIN = b"FLOCKTX1"
STATE_DOMAIN = b"FLOCKSTATE1"
MAX_PAYLOAD = 4096
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
TX_FIXED_LEN = len(TX_DOMAIN) + 4 + 8 + 32 + 32 + (4 * 8) + 4

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

def decode_tx(raw: bytes) -> Tx:
    fixed = TX_FIXED_LEN
    if len(raw) < fixed:
        raise ValueError("truncated transaction")
    if not raw.startswith(TX_DOMAIN):
        raise ValueError("wrong transaction domain")

    at = len(TX_DOMAIN)
    chain_id = struct.unpack_from(">I", raw, at)[0]
    at += 4
    nonce = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    sender = raw[at:at + 32]
    at += 32
    recipient = raw[at:at + 32]
    at += 32
    amount = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    compute_limit = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    state_limit = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    memory_limit = struct.unpack_from(">Q", raw, at)[0]
    at += 8
    payload_len = struct.unpack_from(">I", raw, at)[0]
    at += 4

    if payload_len > MAX_PAYLOAD:
        raise ValueError("payload too large")
    if len(raw) != at + payload_len:
        raise ValueError("wrong transaction payload length")

    tx = Tx(
        chain_id=chain_id,
        nonce=nonce,
        sender=sender,
        recipient=recipient,
        amount=amount,
        compute_limit=compute_limit,
        state_limit=state_limit,
        memory_limit=memory_limit,
        payload=raw[at:],
    )

    if encode_tx(tx) != raw:
        raise ValueError("non-canonical transaction encoding")
    return tx


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
