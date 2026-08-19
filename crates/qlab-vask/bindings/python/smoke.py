#!/usr/bin/env python3
"""Smoke-test the qvask ABI from a foreign runtime (lab #483 stage 1).

Drives the committed parse fixtures (fixtures/README.md is the manifest)
through the Python binding: peek fields, every named refusal code, the
reason string, and the claim-filled-on-parse-success contract. If the
QVASK_OK fixture (golden-envelope-v1.bin) has been minted and committed, it
verifies that too — a real STARK verification from Python; otherwise it says
so and skips that step by name.

Usage: python3 smoke.py <path-to-libqlab_vask .dylib/.so>
       (build one with: cargo build -p qlab-vask)
"""

import sys
from pathlib import Path

from qvask import (
    QVASK_MALFORMED,
    QVASK_OK,
    QVASK_PROOF_DECODE,
    QVASK_UNKNOWN_CLAIM_TYPE,
    QVASK_UNKNOWN_VERSION,
    CODE_NAMES,
    Qvask,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def check(label, got, want):
    if got != want:
        print(f"FAIL {label}: got {got!r}, want {want!r}")
        sys.exit(1)
    print(f"ok   {label}: {CODE_NAMES.get(got, got) if isinstance(got, int) else got!r}")


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    q = Qvask(sys.argv[1])
    check("envelope_ver", q.envelope_ver(), 0x01)

    peek_bytes = (FIXTURES / "peek-claim-v1.bin").read_bytes()
    code, claim = q.peek(peek_bytes)
    check("peek code", code, QVASK_OK)
    check("peek tx_ref", claim["tx_ref"], bytes(range(32)))
    check("peek value", claim["value"], 42_000_000)
    check("peek addr_commitment", claim["addr_commitment"], bytes(0xA0 + i for i in range(32)))
    check("peek output_index", claim["output_index"], 7)

    # The garbage proof refuses at the decode gate — with the claim still
    # present (parse succeeded; the refusal is loggable) and a reason string.
    code, claim, reason = q.verify(peek_bytes, bytes(32))
    check("verify garbage-proof code", code, QVASK_PROOF_DECODE)
    check("claim filled on parse success", claim["value"], 42_000_000)
    if not reason:
        print("FAIL refusal carried no reason")
        sys.exit(1)
    print(f"ok   reason: {reason!r}")

    for name, want in [
        ("refuse-unknown-version.bin", QVASK_UNKNOWN_VERSION),
        ("refuse-unknown-claim.bin", QVASK_UNKNOWN_CLAIM_TYPE),
        ("refuse-truncated.bin", QVASK_MALFORMED),
        ("refuse-trailing.bin", QVASK_MALFORMED),
        ("refuse-varint-truncated.bin", QVASK_MALFORMED),
    ]:
        code, _ = q.peek((FIXTURES / name).read_bytes())
        check(name, code, want)

    golden = FIXTURES / "golden-envelope-v1.bin"
    golden_cm = FIXTURES / "golden-chain-cm-v1.bin"
    if golden.exists() and golden_cm.exists():
        code, claim, reason = q.verify(golden.read_bytes(), golden_cm.read_bytes())
        check("golden envelope verifies", code, QVASK_OK)
        check("golden value", claim["value"], 250_000_000)
    else:
        print("skip golden-envelope-v1.bin: not minted yet (fixtures/README.md) — no STARK verification exercised")

    print("PASS")


if __name__ == "__main__":
    main()
