from __future__ import annotations

from dataclasses import dataclass
import hashlib
import socket
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tools.mempool import MAX_CANONICAL_TX, Mempool, MempoolLimits
from tools.reference_model import Tx, decode_tx, encode_tx
from tools.transport import PeerSession, PeerState, recv_frame, send_frame

ADDRESS_DOMAIN = b"FLOCKADDR1"
SIGNATURE_DOMAIN = b"FLOCKSIG1"
SIGNED_TX_DOMAIN = b"FLOCKSIGNEDTX1"

PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64
SIGNED_TX_FIXED = len(SIGNED_TX_DOMAIN) + PUBLIC_KEY_LEN + SIGNATURE_LEN + 4
MAX_SIGNED_TX = SIGNED_TX_FIXED + MAX_CANONICAL_TX


@dataclass(frozen=True)
class SignedTx:
    public_key: bytes
    signature: bytes
    tx_bytes: bytes


@dataclass(frozen=True)
class AuthenticatedAdmission:
    accepted: bool
    reason: str
    tx_hash: bytes


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def address_from_public_key(public_key: bytes) -> bytes:
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(ADDRESS_DOMAIN + public_key).digest()


def signature_message(tx_bytes: bytes) -> bytes:
    if not tx_bytes:
        raise ValueError("transaction bytes cannot be empty")
    if len(tx_bytes) > MAX_CANONICAL_TX:
        raise ValueError("transaction exceeds canonical maximum")
    return SIGNATURE_DOMAIN + tx_bytes


def sign_tx(tx: Tx, private_key: Ed25519PrivateKey) -> SignedTx:
    tx_bytes = encode_tx(tx)
    pub = public_key_bytes(private_key.public_key())
    if tx.sender != address_from_public_key(pub):
        raise ValueError("transaction sender does not match signing public key")
    sig = private_key.sign(signature_message(tx_bytes))
    return SignedTx(pub, sig, tx_bytes)


def encode_signed_tx(signed: SignedTx) -> bytes:
    if len(signed.public_key) != PUBLIC_KEY_LEN:
        raise ValueError("Ed25519 public key must be 32 bytes")
    if len(signed.signature) != SIGNATURE_LEN:
        raise ValueError("Ed25519 signature must be 64 bytes")
    if not signed.tx_bytes:
        raise ValueError("transaction bytes cannot be empty")
    if len(signed.tx_bytes) > MAX_CANONICAL_TX:
        raise ValueError("transaction exceeds canonical maximum")

    tx = decode_tx(signed.tx_bytes)
    if encode_tx(tx) != signed.tx_bytes:
        raise ValueError("non-canonical transaction")

    return b"".join(
        (
            SIGNED_TX_DOMAIN,
            signed.public_key,
            signed.signature,
            struct.pack(">I", len(signed.tx_bytes)),
            signed.tx_bytes,
        )
    )


def decode_signed_tx(raw: bytes) -> SignedTx:
    if len(raw) < SIGNED_TX_FIXED:
        raise ValueError("truncated signed transaction")
    if not raw.startswith(SIGNED_TX_DOMAIN):
        raise ValueError("wrong signed-transaction domain")

    at = len(SIGNED_TX_DOMAIN)
    public_key = raw[at : at + PUBLIC_KEY_LEN]
    at += PUBLIC_KEY_LEN
    signature = raw[at : at + SIGNATURE_LEN]
    at += SIGNATURE_LEN
    tx_len = struct.unpack_from(">I", raw, at)[0]
    at += 4

    if tx_len == 0:
        raise ValueError("transaction bytes cannot be empty")
    if tx_len > MAX_CANONICAL_TX:
        raise ValueError("transaction exceeds canonical maximum")
    if len(raw) != at + tx_len:
        raise ValueError("wrong signed-transaction payload length")

    tx_bytes = raw[at:]
    tx = decode_tx(tx_bytes)
    if encode_tx(tx) != tx_bytes:
        raise ValueError("non-canonical transaction")

    signed = SignedTx(public_key, signature, tx_bytes)
    if encode_signed_tx(signed) != raw:
        raise ValueError("non-canonical signed transaction")
    return signed


def verify_signed_tx(signed: SignedTx) -> Tx:
    if len(signed.public_key) != PUBLIC_KEY_LEN:
        raise ValueError("invalid public key length")
    if len(signed.signature) != SIGNATURE_LEN:
        raise ValueError("invalid signature length")

    tx = decode_tx(signed.tx_bytes)
    expected_sender = address_from_public_key(signed.public_key)
    if tx.sender != expected_sender:
        raise ValueError("sender/public-key mismatch")

    try:
        Ed25519PublicKey.from_public_bytes(signed.public_key).verify(
            signed.signature,
            signature_message(signed.tx_bytes),
        )
    except InvalidSignature as exc:
        raise ValueError("invalid signature") from exc

    return tx


class AuthenticatedMempool:
    def __init__(self, limits: MempoolLimits | None = None):
        self._pool = Mempool(limits)
        self._nonce_index: dict[tuple[bytes, int], bytes] = {}
        self._hash_to_nonce: dict[bytes, tuple[bytes, int]] = {}

    @property
    def limits(self) -> MempoolLimits:
        return self._pool.limits

    def __len__(self) -> int:
        return len(self._pool)

    @property
    def total_bytes(self) -> int:
        return self._pool.total_bytes

    def hashes(self) -> tuple[bytes, ...]:
        return self._pool.hashes()

    def transactions(self) -> tuple[Tx, ...]:
        return self._pool.transactions()

    def raw_transactions(self) -> tuple[bytes, ...]:
        return self._pool.raw_transactions()

    def admit_signed(self, signed: SignedTx, *, chain_id: int) -> AuthenticatedAdmission:
        try:
            envelope = encode_signed_tx(signed)
        except ValueError:
            digest = hashlib.sha256(repr(signed).encode("utf-8")).digest()
            return AuthenticatedAdmission(False, "signed_encoding", digest)
        return self.admit_signed_raw(envelope, chain_id=chain_id)

    def admit_signed_raw(self, raw_signed: bytes, *, chain_id: int) -> AuthenticatedAdmission:
        digest = hashlib.sha256(raw_signed).digest()

        if len(raw_signed) > MAX_SIGNED_TX:
            return AuthenticatedAdmission(False, "signed_bytes", digest)

        try:
            signed = decode_signed_tx(raw_signed)
        except ValueError:
            return AuthenticatedAdmission(False, "signed_encoding", digest)

        try:
            tx = verify_signed_tx(signed)
        except ValueError as exc:
            reason = str(exc)
            if reason == "sender/public-key mismatch":
                return AuthenticatedAdmission(False, "sender_binding", digest)
            if reason == "invalid signature":
                return AuthenticatedAdmission(False, "signature", digest)
            return AuthenticatedAdmission(False, "authentication", digest)

        nonce_key = (tx.sender, tx.nonce)
        existing = self._nonce_index.get(nonce_key)
        tx_hash = hashlib.sha256(signed.tx_bytes).digest()

        if existing is not None:
            if existing == tx_hash:
                return AuthenticatedAdmission(False, "duplicate", tx_hash)
            return AuthenticatedAdmission(False, "nonce_conflict", tx_hash)

        admission = self._pool.admit_raw(signed.tx_bytes, chain_id=chain_id)
        if not admission.accepted:
            return AuthenticatedAdmission(False, admission.reason, admission.tx_hash)

        self._nonce_index[nonce_key] = admission.tx_hash
        self._hash_to_nonce[admission.tx_hash] = nonce_key
        return AuthenticatedAdmission(True, "accepted", admission.tx_hash)

    def remove(self, tx_hashes) -> int:
        hashes = tuple(tx_hashes)
        removed = self._pool.remove(hashes)
        for tx_hash in hashes:
            nonce_key = self._hash_to_nonce.pop(tx_hash, None)
            if nonce_key is not None:
                self._nonce_index.pop(nonce_key, None)
        return removed


def _require_established(session: PeerSession, *, chain_id: int) -> None:
    if session.state is not PeerState.ESTABLISHED or session.remote_hello is None:
        raise RuntimeError("authenticated mempool transport requires an established peer session")
    if session.remote_hello.chain_id != chain_id:
        raise ValueError("remote hello has a different chain id")


def send_signed_transaction(
    sock: socket.socket,
    session: PeerSession,
    raw_signed: bytes,
    *,
    chain_id: int,
) -> None:
    _require_established(session, chain_id=chain_id)
    if not raw_signed or len(raw_signed) > MAX_SIGNED_TX:
        raise ValueError("signed transaction exceeds transport bounds")
    send_frame(sock, raw_signed, max_payload=MAX_SIGNED_TX)


def receive_signed_transaction(
    sock: socket.socket,
    session: PeerSession,
    mempool: AuthenticatedMempool,
    *,
    chain_id: int,
) -> AuthenticatedAdmission:
    _require_established(session, chain_id=chain_id)
    raw_signed = recv_frame(sock, max_payload=MAX_SIGNED_TX)
    return mempool.admit_signed_raw(raw_signed, chain_id=chain_id)
