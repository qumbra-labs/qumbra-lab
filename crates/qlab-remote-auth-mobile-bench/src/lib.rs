//! Research-only Candidate A mobile benchmark ABI.
//!
//! This crate measures the thin-phone work that a shared prover cannot safely
//! perform: derive every public ML-DSA leaf for a private address master,
//! independently compute the committed root with `O(depth)` memory, derive a
//! private rotation schedule, and create plus verify the two fixed-shape intent
//! signatures. The prover, AIR, transaction wire, wallet seed hierarchy,
//! persistence, restore, and Keychain/Keystore are deliberately absent.

use std::{
    ffi::{c_char, c_void, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::OnceLock,
    time::{Duration, Instant},
};

use qlab_remote_auth::{
    codec::{AuthSection, Slot},
    intent::{fixture_intent, Scheme},
    mldsa::{self, Key},
    rotation,
    tree::RootAccumulator,
    Hash32,
};

pub const QRA_MOBILE_BENCH_ABI_VERSION: u32 = 1;
pub const QRA_MOBILE_BENCH_OK: i32 = 0;
pub const QRA_MOBILE_BENCH_INVALID_CALL: i32 = -1;
pub const QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH: i32 = -2;
pub const QRA_MOBILE_BENCH_CANCELLED: i32 = -3;
pub const QRA_MOBILE_BENCH_INTERNAL: i32 = -4;

pub const MIN_MEASURED_DEPTH: u32 = 12;
pub const MAX_MEASURED_DEPTH: u32 = 16;
const PROGRESS_GRANULARITY: u32 = 64;

// Public synthetic benchmark material. It is intentionally constant so two
// platforms at the same revision must report the same root and intent digest.
const SYNTHETIC_ADDRESS_MASTER: Hash32 = [0x24; 32];
const SYNTHETIC_ROTATION_SEED: Hash32 = [0x42; 32];

pub type ProgressFn = Option<unsafe extern "C" fn(*mut c_void, completed: u32, total: u32) -> i32>;

/// Fixed-layout result mirrored by the hand-maintained C header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QraMobileBenchResult {
    pub struct_size: u32,
    pub abi_version: u32,
    pub depth: u32,
    pub leaf_count: u32,
    pub address_leaf_generation_ns: u64,
    pub address_tree_hashing_ns: u64,
    pub rotation_schedule_ns: u64,
    pub spend_signing_ns: u64,
    pub spend_verification_ns: u64,
    pub total_ns: u64,
    pub auth_section_bytes: u32,
    pub verifying_key_bytes_per_slot: u32,
    pub signature_bytes_per_slot: u32,
    pub rotation_schedule_bytes: u32,
    pub selected_indices: [u32; 2],
    pub root: Hash32,
    pub intent_digest: Hash32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchError {
    UnsupportedDepth,
    Cancelled,
    Internal,
}

impl BenchError {
    const fn status(self) -> i32 {
        match self {
            Self::UnsupportedDepth => QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH,
            Self::Cancelled => QRA_MOBILE_BENCH_CANCELLED,
            Self::Internal => QRA_MOBILE_BENCH_INTERNAL,
        }
    }
}

fn nanoseconds(duration: Duration) -> u64 {
    duration.as_nanos().min(u64::MAX as u128) as u64
}

fn run_inner<F>(
    depth: u32,
    enforce_measurement_range: bool,
    mut progress: F,
) -> Result<QraMobileBenchResult, BenchError>
where
    F: FnMut(u32, u32) -> bool,
{
    let allowed = if enforce_measurement_range {
        (MIN_MEASURED_DEPTH..=MAX_MEASURED_DEPTH).contains(&depth)
    } else {
        depth <= MAX_MEASURED_DEPTH
    };
    if !allowed {
        return Err(BenchError::UnsupportedDepth);
    }

    let leaf_count = 1u32 << depth;
    if !progress(0, leaf_count) {
        return Err(BenchError::Cancelled);
    }

    let total_started = Instant::now();
    let mut leaf_generation = Duration::ZERO;
    let mut tree_hashing = Duration::ZERO;
    let mut accumulator = RootAccumulator::new(depth as u8).map_err(|_| BenchError::Internal)?;

    for leaf_index in 0..leaf_count {
        let leaf_started = Instant::now();
        let key = Key::from_seed(mldsa::derive_leaf_seed(
            &SYNTHETIC_ADDRESS_MASTER,
            leaf_index,
        ));
        let leaf = key.descriptor(leaf_index).leaf();
        leaf_generation += leaf_started.elapsed();

        let tree_started = Instant::now();
        accumulator.push(leaf).map_err(|_| BenchError::Internal)?;
        tree_hashing += tree_started.elapsed();

        let completed = leaf_index + 1;
        if (completed % PROGRESS_GRANULARITY == 0 || completed == leaf_count)
            && !progress(completed, leaf_count)
        {
            return Err(BenchError::Cancelled);
        }
    }
    let root = accumulator.finish().map_err(|_| BenchError::Internal)?;

    let rotation_started = Instant::now();
    let order = rotation::selection_order(&SYNTHETIC_ROTATION_SEED, depth as u8)
        .map_err(|_| BenchError::Internal)?;
    let selected_indices = [order[0], order[1]];
    let rotation_schedule_bytes = order
        .capacity()
        .checked_mul(std::mem::size_of::<u32>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or(BenchError::Internal)?;
    let rotation_schedule_ns = nanoseconds(rotation_started.elapsed());

    let signing_started = Instant::now();
    let keys: [Key; 2] = std::array::from_fn(|slot| {
        Key::from_seed(mldsa::derive_leaf_seed(
            &SYNTHETIC_ADDRESS_MASTER,
            selected_indices[slot],
        ))
    });
    let descriptors = std::array::from_fn(|slot| keys[slot].descriptor(selected_indices[slot]));
    let intent = fixture_intent(Scheme::MlDsa44, descriptors);
    let intent_digest = intent.digest();
    let slots = std::array::from_fn(|slot| Slot::MlDsa44 {
        descriptor: descriptors[slot],
        verifying_key: keys[slot].verifying_key_bytes(),
        signature: keys[slot].sign(&intent_digest),
    });
    let auth = AuthSection::new(Scheme::MlDsa44, slots).map_err(|_| BenchError::Internal)?;
    let encoded = auth.encode().map_err(|_| BenchError::Internal)?;
    let spend_signing_ns = nanoseconds(signing_started.elapsed());

    let verification_started = Instant::now();
    auth.verify_intent(&intent)
        .map_err(|_| BenchError::Internal)?;
    let spend_verification_ns = nanoseconds(verification_started.elapsed());

    Ok(QraMobileBenchResult {
        struct_size: std::mem::size_of::<QraMobileBenchResult>() as u32,
        abi_version: QRA_MOBILE_BENCH_ABI_VERSION,
        depth,
        leaf_count,
        address_leaf_generation_ns: nanoseconds(leaf_generation),
        address_tree_hashing_ns: nanoseconds(tree_hashing),
        rotation_schedule_ns,
        spend_signing_ns,
        spend_verification_ns,
        total_ns: nanoseconds(total_started.elapsed()),
        auth_section_bytes: encoded.len() as u32,
        verifying_key_bytes_per_slot: mldsa::VERIFYING_KEY_BYTES as u32,
        signature_bytes_per_slot: mldsa::SIGNATURE_BYTES as u32,
        rotation_schedule_bytes,
        selected_indices,
        root,
        intent_digest,
    })
}

fn static_c_string(value: &'static str) -> *const c_char {
    static VALUES: OnceLock<Vec<CString>> = OnceLock::new();
    // Every status/build string is ASCII and contains no interior NUL. Keep a
    // single stable table so returned pointers remain valid for process life.
    let values = VALUES.get_or_init(|| {
        vec![
            CString::new(option_env!("QLAB_REMOTE_AUTH_BENCH_REVISION").unwrap_or("unknown"))
                .expect("revision has no NUL"),
            CString::new(option_env!("QLAB_REMOTE_AUTH_BENCH_SHELL_REVISION").unwrap_or("unknown"))
                .expect("shell revision has no NUL"),
            CString::new("ok").unwrap(),
            CString::new("invalid call").unwrap(),
            CString::new("depth must be in 12..=16").unwrap(),
            CString::new("cancelled").unwrap(),
            CString::new("internal benchmark failure").unwrap(),
            CString::new("unknown status").unwrap(),
        ]
    });
    let index = match value {
        "revision" => 0,
        "shell_revision" => 1,
        "ok" => 2,
        "invalid" => 3,
        "depth" => 4,
        "cancelled" => 5,
        "internal" => 6,
        _ => 7,
    };
    values[index].as_ptr()
}

#[no_mangle]
pub extern "C" fn qra_mobile_bench_abi_version() -> u32 {
    QRA_MOBILE_BENCH_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn qra_mobile_bench_build_revision() -> *const c_char {
    static_c_string("revision")
}

#[no_mangle]
pub extern "C" fn qra_mobile_bench_shell_revision() -> *const c_char {
    static_c_string("shell_revision")
}

#[no_mangle]
pub extern "C" fn qra_mobile_bench_status_message(status: i32) -> *const c_char {
    static_c_string(match status {
        QRA_MOBILE_BENCH_OK => "ok",
        QRA_MOBILE_BENCH_INVALID_CALL => "invalid",
        QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH => "depth",
        QRA_MOBILE_BENCH_CANCELLED => "cancelled",
        QRA_MOBILE_BENCH_INTERNAL => "internal",
        _ => "unknown",
    })
}

/// Run one synthetic D12..D16 benchmark synchronously.
///
/// # Safety
/// `result_out` must be a valid writable `QraMobileBenchResult`. If supplied,
/// `progress` must be callable for this function's duration with
/// `progress_context`; neither pointer is retained after return.
#[no_mangle]
pub unsafe extern "C" fn qra_mobile_bench_run(
    depth: u32,
    progress: ProgressFn,
    progress_context: *mut c_void,
    result_out: *mut QraMobileBenchResult,
) -> i32 {
    if result_out.is_null() {
        return QRA_MOBILE_BENCH_INVALID_CALL;
    }

    let run = catch_unwind(AssertUnwindSafe(|| {
        run_inner(depth, true, |completed, total| match progress {
            Some(callback) => callback(progress_context, completed, total) == 0,
            None => true,
        })
    }));
    match run {
        Ok(Ok(result)) => {
            result_out.write(result);
            QRA_MOBILE_BENCH_OK
        }
        Ok(Err(error)) => error.status(),
        Err(_) => QRA_MOBILE_BENCH_INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};
    use std::ptr;

    unsafe extern "C" fn cancel_immediately(
        _context: *mut c_void,
        _completed: u32,
        _total: u32,
    ) -> i32 {
        1
    }

    #[test]
    fn small_run_is_deterministic_and_covers_the_two_slot_flow() {
        let first = run_inner(2, false, |_, _| true).unwrap();
        let second = run_inner(2, false, |_, _| true).unwrap();
        assert_eq!(first.root, second.root);
        assert_eq!(first.intent_digest, second.intent_digest);
        assert_eq!(first.selected_indices, second.selected_indices);
        assert_eq!(first.leaf_count, 4);
        assert_eq!(first.auth_section_bytes, 7_544);
        assert_eq!(first.verifying_key_bytes_per_slot, 1_312);
        assert_eq!(first.signature_bytes_per_slot, 2_420);
        assert_eq!(first.rotation_schedule_bytes, 16);
    }

    #[test]
    fn d12_cross_platform_outputs_are_pinned() {
        let result = run_inner(12, true, |_, _| true).unwrap();
        let root: Hash32 = qlab_remote_auth::decode_hex(
            "c8c3a1582bd6c57ad4b3e878d807e105e48c39e5998ca61ff06fde8ced17a086",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let digest: Hash32 = qlab_remote_auth::decode_hex(
            "993a54c86ea3725afa30e98cf270fd3686f6c224615939c480a5308826434739",
        )
        .unwrap()
        .try_into()
        .unwrap();
        assert_eq!(result.selected_indices, [3_322, 507]);
        assert_eq!(result.rotation_schedule_bytes, 16_384);
        assert_eq!(result.root, root);
        assert_eq!(result.intent_digest, digest);
    }

    #[test]
    fn cancellation_and_public_depth_bounds_are_named() {
        assert_eq!(
            run_inner(2, false, |completed, _| completed == 0).unwrap_err(),
            BenchError::Cancelled
        );
        assert_eq!(
            run_inner(11, true, |_, _| true).unwrap_err(),
            BenchError::UnsupportedDepth
        );
        assert_eq!(
            run_inner(17, true, |_, _| true).unwrap_err(),
            BenchError::UnsupportedDepth
        );
        unsafe {
            let sentinel = QraMobileBenchResult {
                depth: 99,
                ..QraMobileBenchResult::default()
            };
            let mut result = sentinel;
            assert_eq!(
                qra_mobile_bench_run(12, Some(cancel_immediately), ptr::null_mut(), &mut result,),
                QRA_MOBILE_BENCH_CANCELLED
            );
            assert_eq!(result, sentinel, "cancel must not write a partial result");
            assert_eq!(
                qra_mobile_bench_run(11, None, ptr::null_mut(), &mut result),
                QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH
            );
            assert_eq!(result, sentinel, "refusal must not write result_out");
            assert_eq!(
                qra_mobile_bench_run(12, None, ptr::null_mut(), ptr::null_mut()),
                QRA_MOBILE_BENCH_INVALID_CALL
            );
        }
    }

    #[test]
    fn result_layout_and_header_pin_the_same_abi() {
        assert_eq!(offset_of!(QraMobileBenchResult, struct_size), 0);
        assert_eq!(offset_of!(QraMobileBenchResult, abi_version), 4);
        assert_eq!(offset_of!(QraMobileBenchResult, depth), 8);
        assert_eq!(offset_of!(QraMobileBenchResult, leaf_count), 12);
        assert_eq!(
            offset_of!(QraMobileBenchResult, address_leaf_generation_ns),
            16
        );
        assert_eq!(offset_of!(QraMobileBenchResult, total_ns), 56);
        assert_eq!(offset_of!(QraMobileBenchResult, auth_section_bytes), 64);
        assert_eq!(
            offset_of!(QraMobileBenchResult, rotation_schedule_bytes),
            76
        );
        assert_eq!(offset_of!(QraMobileBenchResult, selected_indices), 80);
        assert_eq!(offset_of!(QraMobileBenchResult, root), 88);
        assert_eq!(offset_of!(QraMobileBenchResult, intent_digest), 120);
        assert_eq!(size_of::<QraMobileBenchResult>(), 152);

        let header = include_str!("../include/qlab_remote_auth_mobile_bench.h");
        let source = include_str!("lib.rs");
        for function in [
            "qra_mobile_bench_abi_version",
            "qra_mobile_bench_build_revision",
            "qra_mobile_bench_shell_revision",
            "qra_mobile_bench_status_message",
            "qra_mobile_bench_run",
        ] {
            assert!(header.contains(function));
            assert!(source.contains(function));
        }
        assert!(header.contains("#define QRA_MOBILE_BENCH_ABI_VERSION 1"));
        for (name, value) in [
            ("QRA_MOBILE_BENCH_OK", 0),
            ("QRA_MOBILE_BENCH_INVALID_CALL", -1),
            ("QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH", -2),
            ("QRA_MOBILE_BENCH_CANCELLED", -3),
            ("QRA_MOBILE_BENCH_INTERNAL", -4),
        ] {
            assert!(
                header.contains(&format!("#define {name} {value}")),
                "header is missing {name} = {value}"
            );
        }
        assert_eq!(QRA_MOBILE_BENCH_OK, 0);
        assert_eq!(QRA_MOBILE_BENCH_INVALID_CALL, -1);
        assert_eq!(QRA_MOBILE_BENCH_UNSUPPORTED_DEPTH, -2);
        assert_eq!(QRA_MOBILE_BENCH_CANCELLED, -3);
        assert_eq!(QRA_MOBILE_BENCH_INTERNAL, -4);
        assert_eq!(qra_mobile_bench_abi_version(), 1);
    }
}
