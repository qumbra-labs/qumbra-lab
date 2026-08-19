"""ctypes reference binding for the qvask C ABI (lab #483 stage 1).

Mirrors include/qvask.h exactly — read that header for the contract; this
file adds nothing to it. It is the kit's "one reference binding": no
toolchain beyond a built qlab-vask shared library, and it exercises the ABI
the way any foreign runtime would (raw codes, out-params, the string free).

Deliberately thin: functions return the raw (code, ...) tuples rather than
raising, so a consumer sees the named-refusal taxonomy instead of a
Python-shaped translation of it. Wrap to taste.
"""

import ctypes
from ctypes import POINTER, c_char_p, c_int32, c_size_t, c_uint8, c_uint64

QVASK_OK = 0
QVASK_INVALID_CALL = -1
QVASK_MALFORMED = -2
QVASK_UNKNOWN_VERSION = -3
QVASK_UNKNOWN_CLAIM_TYPE = -4
QVASK_PROOF_DECODE = -5
QVASK_PROOF_INVALID = -6

CODE_NAMES = {
    QVASK_OK: "QVASK_OK",
    QVASK_INVALID_CALL: "QVASK_INVALID_CALL",
    QVASK_MALFORMED: "QVASK_MALFORMED",
    QVASK_UNKNOWN_VERSION: "QVASK_UNKNOWN_VERSION",
    QVASK_UNKNOWN_CLAIM_TYPE: "QVASK_UNKNOWN_CLAIM_TYPE",
    QVASK_PROOF_DECODE: "QVASK_PROOF_DECODE",
    QVASK_PROOF_INVALID: "QVASK_PROOF_INVALID",
}


class QvaskClaim(ctypes.Structure):
    """qvask_claim_t — offsets 0 / 32 / 40 / 72, size 80 (pinned Rust-side)."""

    _fields_ = [
        ("tx_ref", c_uint8 * 32),
        ("value", c_uint64),
        ("addr_commitment", c_uint8 * 32),
        ("output_index", c_uint8),
    ]

    def as_dict(self):
        return {
            "tx_ref": bytes(self.tx_ref),
            "value": self.value,
            "addr_commitment": bytes(self.addr_commitment),
            "output_index": self.output_index,
        }


class Qvask:
    def __init__(self, library_path):
        lib = ctypes.CDLL(str(library_path))
        lib.qvask_abi_version.restype = c_int32
        lib.qvask_abi_version.argtypes = []
        lib.qvask_envelope_ver.restype = c_uint8
        lib.qvask_envelope_ver.argtypes = []
        lib.qvask_envelope_peek.restype = c_int32
        lib.qvask_envelope_peek.argtypes = [
            POINTER(c_uint8),
            c_size_t,
            POINTER(QvaskClaim),
        ]
        lib.qvask_verify.restype = c_int32
        lib.qvask_verify.argtypes = [
            POINTER(c_uint8),
            c_size_t,
            POINTER(c_uint8),
            POINTER(QvaskClaim),
            POINTER(c_char_p),
        ]
        lib.qvask_string_free.restype = None
        lib.qvask_string_free.argtypes = [c_char_p]
        abi = lib.qvask_abi_version()
        if abi != 1:
            raise RuntimeError(f"qvask ABI version {abi}, this binding speaks 1")
        self._lib = lib

    def envelope_ver(self):
        return self._lib.qvask_envelope_ver()

    def peek(self, envelope: bytes):
        """-> (code, claim_dict | None). Claim only on QVASK_OK."""
        buf = (c_uint8 * len(envelope)).from_buffer_copy(envelope)
        claim = QvaskClaim()
        code = self._lib.qvask_envelope_peek(buf, len(envelope), ctypes.byref(claim))
        return code, claim.as_dict() if code == QVASK_OK else None

    def verify(self, envelope: bytes, chain_cm: bytes):
        """-> (code, claim_dict | None, reason | None).

        chain_cm: the 32-byte commitment YOU read at (tx_ref, output_index)
        on YOUR finalized view — §3 rule 1 is the caller's. The claim is
        present on any parse success (OK / PROOF_DECODE / PROOF_INVALID).
        """
        if len(chain_cm) != 32:
            raise ValueError("chain_cm must be 32 bytes")
        buf = (c_uint8 * len(envelope)).from_buffer_copy(envelope)
        cm = (c_uint8 * 32).from_buffer_copy(chain_cm)
        claim = QvaskClaim()
        reason_p = c_char_p()
        code = self._lib.qvask_verify(
            buf, len(envelope), cm, ctypes.byref(claim), ctypes.byref(reason_p)
        )
        reason = None
        if reason_p.value is not None:
            reason = reason_p.value.decode("utf-8", "replace")
            # c_char_p already copied the bytes into `reason`; release the
            # library's allocation through the library's own free.
            self._lib.qvask_string_free(reason_p)
        parsed = code in (QVASK_OK, QVASK_PROOF_DECODE, QVASK_PROOF_INVALID)
        return code, claim.as_dict() if parsed else None, reason
