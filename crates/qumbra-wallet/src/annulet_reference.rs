//! **The pre-WA1 verified scan, verbatim** (lab #858 WA1). The equality
//! reference for `tests/annulet_driver.rs`: the caller-pumped
//! [`crate::annulet_driver::AnnuletVerifyDriver`] must give what this gives —
//! the same [`VerifiedAnnulet`] or the same [`VerifyRefusal`], over the same
//! fetch sequence. **Not a scan path**; deleted with WA2, the
//! `annulet_rows_per_index` precedent. The only edits from the pre-WA1 text
//! are visibility, the multi-scan reference it calls, and the struct literal's
//! new field.

#![allow(clippy::all)]

use std::cell::RefCell;

use qlab_cbserver::client::{light_client_scan_l2_multi_with_reference, MultiScanRefusal, ScanConfig};
use qlab_devnet::annulet::body_commitment_annulet_for;
use qlab_devnet::chain::ChainState;
use qlab_devnet::forms::GenesisForm;
use qlab_devnet::header::BlockHeader;
use qlab_ledger::assets::{AssetIndex, OwnedL2Note};
use qlab_ledger::spent::{coverage_for, widest_range, NullifierChunk, NullifierSource, SpentSet};
use qlab_ledger::vocab::SpentCoverage;
use qlab_node::annulet_genesis::{h32, AnnuletGenesisFile};
use qlab_note::l2note::{GenesisPlaintext, L2Note};
use qlab_p2p::served::{decode_body_answer, decode_headers_page, sealed, MAX_HEADERS_PAGE};
use rand::rngs::StdRng;

use crate::annulet::{AnnuletReport, AnnuletRow};
use crate::annulet_verify::{
    load_chain_cache, save_chain_cache, ChainCache, VerifiedAnnulet, VerifiedChain, VerifiedGenesis, VerifyRefusal,
    GENESIS_FILE_PATH, MAX_GENESIS_FILE_BYTES,
};
use crate::store::WalletDir;

/// Step 1: fetch the genesis file, hash it against `pin`, decode and check it.
fn verify_genesis<F>(fetch: &mut F, pin: [u8; 32]) -> Result<VerifiedGenesis, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let bytes = fetch(GENESIS_FILE_PATH).map_err(|why| VerifyRefusal::GenesisUnavailable { why })?;
    if bytes.len() > MAX_GENESIS_FILE_BYTES {
        return Err(VerifyRefusal::GenesisTooLarge { got: bytes.len() });
    }
    let fetched = qlab_devnet::hash::keccak256(&bytes);
    if fetched != pin {
        return Err(VerifyRefusal::GenesisMismatch { pinned: pin, fetched });
    }
    let file = AnnuletGenesisFile::from_bytes(&bytes).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    file.verify(None).map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let header_hash = file.genesis_block_header().header_hash_for(GenesisForm::Annulet);
    let l2_auth = file.l2_auth().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    Ok(VerifiedGenesis { hash: fetched, file, header_hash, l2_auth })
}

/// Step 2: verify every sealed header from height 1 up to `up_to` (or the
/// endpoint's last), through the consensus header rule.
fn verify_chain<F>(fetch: &mut F, genesis: VerifiedGenesis, up_to: u64) -> Result<VerifiedChain, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
    let mut headers = Vec::new();
    extend_chain(fetch, &genesis, &mut state, &mut headers, up_to)?;
    Ok(VerifiedChain { genesis, headers })
}

/// Admit sealed headers past `headers` (heights `headers.len() + 1 ..`) up to
/// `up_to` or the endpoint's last — the one admission path, from genesis or
/// from a resumed record.
fn extend_chain<F>(
    fetch: &mut F,
    genesis: &VerifiedGenesis,
    state: &mut ChainState,
    headers: &mut Vec<BlockHeader>,
    up_to: u64,
) -> Result<(), VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let key = genesis.file.sequencer().map_err(|e| VerifyRefusal::GenesisInvalid { why: e.to_string() })?;
    let mut parent = headers.last().map_or(genesis.header_hash, |h| h.header_hash_for(GenesisForm::Annulet));
    loop {
        let from = headers.len() as u64 + 1;
        if from > up_to {
            break;
        }
        let to = up_to.min(from + MAX_HEADERS_PAGE as u64 - 1);
        let path = format!("/v1/headers?from={from}&to={to}");
        let bytes = fetch(&path).map_err(|why| VerifyRefusal::HeadersUnavailable { from, why })?;
        let units = decode_headers_page(genesis.wire(), from, &bytes)
            .map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
        let asked = to - from + 1;
        let got = units.len() as u64;
        for unit in &units {
            let s = sealed(unit).map_err(|e| VerifyRefusal::HeadersMalformed { from, why: e.to_string() })?;
            let want = headers.len() as u64 + 1;
            if s.header.height != want {
                return Err(VerifyRefusal::HeaderGap { want, got: s.header.height });
            }
            if s.header.prev != parent {
                return Err(VerifyRefusal::HeaderFork { height: want });
            }
            qlab_devnet::validation::validate_sealed_header_annulet(state, s, &key)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            parent = state
                .insert_header(s.header)
                .map_err(|e| VerifyRefusal::HeaderInvalid { height: want, why: format!("{e:?}") })?;
            headers.push(s.header);
        }
        if got < asked {
            break;
        }
    }
    Ok(())
}

/// Resume from a loaded record: re-check the endpoint's header at the
/// anchor (the recorded tip, or `up_to` below it) against the record, then
/// admit what is past it. An endpoint that serves nothing at the anchor is
/// behind the record: the chain is clamped to the endpoint's stated tip,
/// re-checked there the same way — never claimed above what this endpoint
/// serves.
fn resume_chain<F>(
    fetch: &mut F,
    genesis: VerifiedGenesis,
    cached: Vec<BlockHeader>,
    up_to: u64,
) -> Result<VerifiedChain, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut anchor = (cached.len() as u64).min(up_to);
    if anchor == 0 {
        return verify_chain(fetch, genesis, up_to);
    }
    let served_at = |fetch: &mut F, h: u64| -> Result<Option<BlockHeader>, VerifyRefusal> {
        let bytes = fetch(&format!("/v1/headers?from={h}&to={h}"))
            .map_err(|why| VerifyRefusal::HeadersUnavailable { from: h, why })?;
        let units = decode_headers_page(genesis.wire(), h, &bytes)
            .map_err(|e| VerifyRefusal::HeadersMalformed { from: h, why: e.to_string() })?;
        match units.first() {
            None => Ok(None),
            Some(u) => Ok(Some(sealed(u).map_err(|e| VerifyRefusal::HeadersMalformed { from: h, why: e.to_string() })?.header)),
        }
    };
    let served = match served_at(fetch, anchor)? {
        Some(h) => h,
        None => {
            // Behind the record: clamp to the endpoint's own stated tip.
            let stated = fetch("/v1/registry/root")
                .ok()
                .and_then(|b| qlab_cbserver::registry::decode_registry_root(&b).ok())
                .map(|(height, _)| height)
                .unwrap_or(0);
            anchor = stated.min(anchor);
            if anchor == 0 {
                return Ok(VerifiedChain { genesis, headers: Vec::new() });
            }
            served_at(fetch, anchor)?.ok_or(VerifyRefusal::CachedTipForked { height: anchor })?
        }
    };
    if served != cached[anchor as usize - 1] {
        return Err(VerifyRefusal::CachedTipForked { height: anchor });
    }
    let mut headers: Vec<BlockHeader> = cached;
    headers.truncate(anchor as usize);
    let mut state = ChainState::new_for(GenesisForm::Annulet, genesis.file.genesis_block_header());
    for h in &headers {
        state.insert_header(*h).map_err(|e| VerifyRefusal::ChainCacheInvalid { why: format!("{e:?}") })?;
    }
    if anchor as usize == headers.len() && anchor < up_to {
        extend_chain(fetch, &genesis, &mut state, &mut headers, up_to)?;
    }
    Ok(VerifiedChain { genesis, headers })
}

/// **The verified Annulet scan**: steps 1–3 of the module doc, then the
/// unchanged scan body over the verified range and genesis.
pub fn scan_annulet_verified_reference<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    pin: Option<[u8; 32]>,
    rng: &mut StdRng,
) -> Result<VerifiedAnnulet, VerifyRefusal>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let pin = pin.ok_or(VerifyRefusal::NoPin)?;
    let genesis = verify_genesis(fetch, pin)?;
    let recorded = load_chain_cache(w, &genesis);
    let recorded_len = recorded.as_ref().ok().and_then(|r| r.as_ref().map(Vec::len)).unwrap_or(0);
    let (chain, cache) = match recorded {
        Ok(None) => (verify_chain(fetch, genesis, to)?, ChainCache::Unused),
        Err(why) => (verify_chain(fetch, genesis, to)?, ChainCache::Discarded(VerifyRefusal::ChainCacheInvalid { why })),
        Ok(Some(cached)) => match resume_chain(fetch, genesis.clone(), cached, to) {
            Ok(chain) => {
                let anchor = (recorded_len as u64).min(to).min(chain.tip());
                (chain, ChainCache::Resumed { anchor, recorded: recorded_len as u64 })
            }
            Err(e @ VerifyRefusal::CachedTipForked { .. }) | Err(e @ VerifyRefusal::ChainCacheInvalid { .. }) => {
                (verify_chain(fetch, genesis, to)?, ChainCache::Discarded(e))
            }
            Err(e) => return Err(e),
        },
    };
    let to = to.min(chain.tip());

    let genesis_notes: Vec<([u8; 32], L2Note)> = chain
        .genesis
        .file
        .genesis_notes
        .iter()
        .map(|n| {
            let note = GenesisPlaintext::open(&n.payload).expect("the file's structural check opened every payload");
            (n.cm, note)
        })
        .collect();
    let report = scan_annulet_from(w, fetch, from, to, chain.genesis.hash, &genesis_notes, rng);

    // Each block with a hit is fetched and bound once, whichever address's
    // row found it; what is kept is each transaction's commitments.
    let (mut bodies_fetched, mut body_bytes) = (0u64, 0u64);
    let mut bound: std::collections::BTreeMap<u64, Vec<Vec<[u8; 32]>>> = std::collections::BTreeMap::new();
    for owned in &report.owned {
        let Some(tx_index) = owned.tx_index else {
            if !genesis_notes.iter().any(|(cm, _)| *cm == owned.cm) {
                return Err(VerifyRefusal::ForgedGenesisNote { cm: owned.cm });
            }
            continue;
        };
        let height = owned.height;
        let forged = |why: &str| VerifyRefusal::ForgedNote { height, tx_index, why: why.to_string() };
        if h32(&owned.note.commitment()) != owned.cm {
            return Err(forged("the note does not open to the commitment it was served under"));
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = bound.entry(height) {
            let header = chain.header(height).ok_or_else(|| forged("above the verified tip"))?;
            let bytes = fetch(&format!("/v1/block/{height}/body"))
                .map_err(|why| VerifyRefusal::BodyUnavailable { height, why })?;
            bodies_fetched += 1;
            body_bytes += bytes.len() as u64;
            let ann = decode_body_answer(chain.genesis.wire(), height, &bytes)
                .map_err(|e| VerifyRefusal::BodyMalformed { height, why: e.to_string() })?;
            if ann.header != header {
                return Err(VerifyRefusal::BodyHeaderMismatch { height });
            }
            let body = qlab_p2p::served::body_of(&ann);
            crate::annulet_verify::check_body_counts(height, &body)?;
            if body_commitment_annulet_for(&body, chain.genesis.l2_auth) != header.tx_body_commitment {
                return Err(VerifyRefusal::BodyCommitmentMismatch { height });
            }
            slot.insert(body.txs.iter().map(|tx| tx.public.commitments.clone()).collect());
        }
        let txs = &bound[&height];
        let cms = txs.get(tx_index as usize).ok_or_else(|| forged("the block has no such transaction"))?;
        if !cms.contains(&owned.cm) {
            return Err(forged("the transaction carries no such commitment"));
        }
    }
    // Freshness, not trust: the node's own word on its tip, for the line that
    // says how far behind the verified chain is.
    let stated_tip = fetch("/v1/registry/root")
        .ok()
        .and_then(|b| qlab_cbserver::registry::decode_registry_root(&b).ok())
        .map(|(height, _)| height);
    // The record is written only now, after every check passed — a refused
    // scan never writes it — and only when it would grow or was discarded.
    let grows = chain.headers.len() > recorded_len;
    let cache_write = match (&cache, grows) {
        (ChainCache::Discarded(_), _) | (_, true) => save_chain_cache(w, &chain.genesis.hash, &chain.headers).err(),
        _ => None,
    };
    Ok(VerifiedAnnulet { report, chain, range: (from, to), bodies_fetched, body_bytes, stated_tip, cache, write_record: false, cache_write })
}

/// A [`NullifierSource`] over a fetch closure.
struct FetchNullifiers<'a, F>(RefCell<&'a mut F>);

impl<F> NullifierSource for FetchNullifiers<'_, F>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    fn fetch_range(&self, from: u64, to: u64) -> Result<NullifierChunk, String> {
        let path = format!("/v1/nullifiers?from={from}&to={to}");
        let bytes = (self.0.borrow_mut())(&path).map_err(|e| format!("GET {path}: {e}"))?;
        let page = qlab_cbserver::codec::NullifierPage::from_bytes(&bytes)
            .map_err(|e| format!("GET {path} did not decode: {e:?}"))?;
        Ok(NullifierChunk {
            from: page.from,
            to: page.to,
            blocks: page.blocks.into_iter().map(|b| (b.height, b.nullifiers)).collect(),
        })
    }
}

/// Where the nullifier stream must start for owned genesis notes: height 1
/// is the first a genesis note can be spent in, and height 0 when the scan
/// starts there — so a chain still at its genesis (tip 0) is covered by the
/// genesis block itself rather than asked for a height 1 that does not
/// exist yet (lab #722: C3's first lane run, a mint at tip 0 read `NoBalance`).
fn genesis_from(from: u64) -> u64 {
    from.min(1)
}

/// [`scan_annulet`] after its genesis is known: scan every allocated address
/// over `from ..= to`, match `genesis`'s notes, read the spends, and index.
/// Lab #850 (AD1) split it out so the verified scan
/// ([`crate::annulet_verify`]) runs the same body over genesis notes read from
/// the genesis **file** it hashed, not from `/v1/genesis/notes`.
fn scan_annulet_from<F>(
    w: &WalletDir,
    fetch: &mut F,
    from: u64,
    to: u64,
    genesis_hash: [u8; 32],
    genesis: &[([u8; 32], L2Note)],
    rng: &mut StdRng,
) -> AnnuletReport
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let wallet = w.wallet();
    let rows = annulet_rows(w, fetch, from, to, rng);

    let mut owned = Vec::new();
    let mut refused = Vec::new();
    for (cm, note) in genesis {
        for &idx in &w.allocated {
            if wallet.rkm(wallet.diversifier_at_index(idx)) == note.rkm {
                match OwnedL2Note::from_genesis(&wallet, idx, *cm, *note) {
                    Ok(n) => owned.push(n),
                    Err(e) => refused.push(format!("genesis note: {e}")),
                }
            }
        }
    }
    let genesis_owned = owned.len();
    for row in &rows {
        if let Ok(outcome) = &row.scan {
            for located in &outcome.notes {
                match OwnedL2Note::from_located(&wallet, row.index, located) {
                    Ok(n) => owned.push(n),
                    Err(e) => refused.push(format!("height {} tx {}: {e}", located.height, located.tx_index)),
                }
            }
        }
    }

    // The nullifier stream must cover everything the owned notes could have
    // been spent in: a genesis note from height 1 on (from 0 when the scan
    // starts at 0, which also covers a chain still at its genesis).
    let outputs = widest_range(
        rows.iter()
            .filter_map(|r| r.scan.as_ref().ok())
            .map(|o| o.stats.compact_range_served)
            .chain(std::iter::once((genesis_owned > 0).then_some((genesis_from(from), genesis_from(from))))),
    );
    let nf_from = if genesis_owned > 0 { genesis_from(from) } else { from };
    let source = FetchNullifiers(RefCell::new(fetch));
    let (spent, set): (SpentCoverage, Option<SpentSet>) = coverage_for(&source, nf_from, to, outputs);

    let every_scan_started = rows.iter().all(|r| r.scan.is_ok());
    let index = match (&set, every_scan_started) {
        (Some(set), true) => Some(AssetIndex::build(&wallet, owned.clone(), set)),
        _ => None,
    };
    AnnuletReport { genesis_hash, rows, genesis_owned, owned, spent, index, refused }
}

/// One row per allocated index, scanned over **one** fetch of the range (lab
/// #819): `light_client_scan_l2_multi_with` runs each index's key through the
/// unchanged scan driver over a shared fetch, so the range and every `/full`
/// are requested once — not once per index, which cost N× the pages and
/// told the server how many addresses this wallet holds.
///
/// Each row is what [`annulet_rows_per_index`] (the pre-#819 path) gives on
/// the same responses. A range that cannot be read fails every row with the
/// driver's message, exactly as each per-index scan of it failed.
fn annulet_rows<F>(w: &WalletDir, fetch: &mut F, from: u64, to: u64, rng: &mut StdRng) -> Vec<AnnuletRow>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let wallet = w.wallet();
    if w.allocated.is_empty() {
        return Vec::new();
    }
    let keys: Vec<_> =
        w.allocated.iter().map(|&idx| (idx, wallet.diversified_keypair(&wallet.diversifier_at_index(idx)).dk)).collect();
    let short = |idx: u64| wallet.address_at_index(idx).short().encode();
    match light_client_scan_l2_multi_with_reference(fetch, &keys, from, to, ScanConfig::default(), rng) {
        Ok(multi) => multi.outcomes.into_iter().map(|(idx, outcome)| AnnuletRow { index: idx, short: short(idx), scan: Ok(outcome) }).collect(),
        Err(refusal) => {
            let why = match refusal {
                MultiScanRefusal::Range(why) => why,
                other => format!("{other:?}"),
            };
            w.allocated.iter().map(|&idx| AnnuletRow { index: idx, short: short(idx), scan: Err(why.clone()) }).collect()
        }
    }
}

