# Flock Phase 7 — Bounded sequential block synchronization

Phase 7 adds the smallest post-handshake synchronization surface: an
established peer may request one exact block height and receive either the
canonical persisted Phase 4 record for that height or an explicit not-found
response.

It does **not** add fork choice, reorganization, gossip, mempool transport,
peer scoring, consensus, validator membership, signatures, economics or
real-value operation.

## Exact-height request

A request is exactly:

    FLOCKGETBLK1
    height:u64

Integers use network byte order.

## Bounded response

A response is:

    FLOCKBLK1
    status:u8
    height:u64
    record_length:u32
    record:[record_length]u8

`status = 0` means not found and requires `record_length = 0`.

`status = 1` means found and requires a non-empty persisted Phase 4 block
record.

The receiver enforces an explicit maximum record size before accepting the
payload. The outer Phase 6 frame remains bounded as well.

## Admission before mutation

Before `ChainStore.append()` the client verifies:

1. the response is tagged with the exact requested height;
2. the complete Phase 4 persisted record parses and verifies;
3. the record header height equals the requested height;
4. the record chain id equals the established chain id; and
5. when the requested height is the peer's advertised tip, the block hash
   equals the tip hash from the Phase 6 hello.

`ChainStore.append()` remains the only persistent mutation boundary. It then
rechecks contiguous height, parent block hash and state-root continuity.

Malformed, corrupt, wrong-height and wrong-terminal-tip responses therefore
leave the local `HEAD` and immutable block directory unchanged.

## Sequential extension only

Synchronization starts from the verified local tip and requests exactly:

    local_tip.height + 1

After a successful append, the next iteration requests the next height. A
bounded `max_blocks` parameter limits work per synchronization call.

A same-height different tip is rejected because fork choice and reorganization
are explicitly outside Phase 7.

A peer behind the local tip causes no rollback.

## Serving

The reference server answers an exact height only from
`ChainStore.verify_chain()`. Heights outside the verified local chain return
not found.

## Explicitly out of scope

Phase 8 adds bounded mempool transport and admission. Fork choice, consensus,
validators, signatures/accounts and economics remain later phases.
