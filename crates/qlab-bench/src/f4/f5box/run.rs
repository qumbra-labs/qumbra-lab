//! Lab #785 F5-6 (1) — **the `f5box` command**.
//!
//! ```text
//! qlab-bench f5box --burn-rkm --genesis FILE
//! qlab-bench f5box --genesis FILE --chain URL --state FILE --out DIR --seed TEXT [--check]
//! qlab-bench f5box --next --genesis FILE --chain URL --state FILE --out DIR
//!                  --exit-rkm HEX [--exit-v BESSEL] [--check]
//! ```
//!
//! - `--burn-rkm` prints `rkm_burn(l2_id)` of the genesis in `miner_rkm`'s
//!   form (64 hex, lane-major LE): what the box producer mines to.
//! - The first run builds **the deposit** (sixteen claims) and starts the
//!   state file; it refuses a state file that already exists.
//! - `--next` replays the state file and builds **the mix**
//!   (`default_kinds(16)`), the first P paying `--exit-v` (default 1 QMB) to
//!   `--exit-rkm` (`qumbra-wallet miner-rkm`'s form).
//! - `--check` plans and stops: no prove, nothing written — whether the chain
//!   is ready, and why not.
//!
//! A built bundle is proven, signed, judged by the node's own rule
//! ([`super::bundle::self_check`]) and only then written: `DIR/bundle.bin`,
//! `DIR/manifest.json`, and the state file. A bundle the rule refuses is
//! written as `DIR/bundle.refused.bin` beside a manifest naming the refusal,
//! and the state file is not touched. Progress goes to stderr, the manifest
//! path to stdout.
use std::path::{Path, PathBuf};
use std::time::Instant;

use qlab_wrapper::codec::{digest_to_bytes, encode_surface, Exit};
use qumbra_node::bundle::WrapperRule;
use qumbra_node::genesis_v6::GenesisFileV6;
use serde_json::json;

use super::bundle::{assemble, manifest, prove, rehearsal_signer, self_check, sign, Timings};
use super::chain::{self, Http};
use super::members::{plan, Ask, Chain, Keys};
use super::state::{digest_hex, plan_surface, RunState};
use crate::f4::bench::default_kinds;
use crate::f4::native::WTag;

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Cmd {
    BurnRkm { genesis: PathBuf },
    Build(Build),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Build {
    pub genesis: PathBuf,
    pub chain: String,
    pub state: PathBuf,
    pub out: PathBuf,
    /// `Some` on the first run, `None` with `--next` (the state holds it).
    pub seed: Option<String>,
    /// `Some` with `--next`: the exit the first P pays.
    pub exit: Option<Exit>,
    pub check: bool,
}

/// Parse `args` (after the mode). Every refusal names the flag.
pub(crate) fn parse(args: &[String]) -> Result<Cmd, String> {
    let has = |k: &str| args.iter().any(|a| a == k);
    let get = |k: &str| -> Result<Option<String>, String> {
        match args.iter().position(|a| a == k) {
            None => Ok(None),
            Some(i) => args.get(i + 1).filter(|v| !v.starts_with("--")).cloned().map(Some).ok_or_else(|| format!("{k} takes a value")),
        }
    };
    let need = |k: &str| -> Result<String, String> { get(k)?.ok_or_else(|| format!("{k} is required")) };
    let known = [
        "--burn-rkm", "--genesis", "--chain", "--state", "--out", "--seed", "--next", "--exit-rkm", "--exit-v", "--check",
    ];
    if let Some(bad) = args.iter().filter(|a| a.starts_with("--")).find(|a| !known.contains(&a.as_str())) {
        return Err(format!("unknown flag {bad}"));
    }
    let genesis = PathBuf::from(need("--genesis")?);
    if has("--burn-rkm") {
        return Ok(Cmd::BurnRkm { genesis });
    }
    let next = has("--next");
    let seed = get("--seed")?;
    let exit = match (next, get("--exit-rkm")?, get("--exit-v")?) {
        (true, Some(hex), v) => {
            let rkm = qumbra_node::config::rkm_lanes_from_hex(&hex).map_err(|e| format!("--exit-rkm: {e:?}"))?;
            let v = match v {
                Some(v) => v.parse::<u64>().map_err(|_| "--exit-v takes bessel, a u64".to_string())?,
                None => qlab_devnet::emission_exact::BESSEL_PER_QMB,
            };
            if v == 0 {
                return Err("--exit-v must be nonzero (a zero-amount redeem is no exit)".into());
            }
            Some(Exit { rkm, v })
        }
        (true, None, _) => return Err("--next needs --exit-rkm (the mix's first P pays the exit)".into()),
        (false, Some(_), _) | (false, _, Some(_)) => return Err("--exit-rkm/--exit-v ride the mix: pass --next".into()),
        (false, None, None) => None,
    };
    match (next, &seed) {
        (false, None) => return Err("the first run needs --seed (the run's key schedule)".into()),
        (true, Some(_)) => return Err("--next reads the seed from the state file; drop --seed".into()),
        _ => {}
    }
    Ok(Cmd::Build(Build {
        genesis,
        chain: need("--chain")?,
        state: PathBuf::from(need("--state")?),
        out: PathBuf::from(need("--out")?),
        seed,
        exit,
        check: has("--check"),
    }))
}

/// `rkm_burn(l2_id)` as `miner_rkm` carries it.
pub(crate) fn burn_rkm_hex(l2_id: u64) -> String {
    digest_hex(&qlab_air::claim::rkm_burn(l2_id))
}

fn load_genesis(path: &Path) -> Result<GenesisFileV6, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let g = GenesisFileV6::from_bytes(&bytes).map_err(|e| format!("{}: {e:?}", path.display()))?;
    g.verify_startup(None).map_err(|e| format!("{}: {e:?}", path.display()))?;
    Ok(g)
}

/// `qlab-bench f5box …`.
pub(crate) fn run(args: &[String]) -> Result<(), String> {
    match parse(args)? {
        Cmd::BurnRkm { genesis } => {
            println!("{}", burn_rkm_hex(load_genesis(&genesis)?.wrapper.l2_id));
            Ok(())
        }
        Cmd::Build(b) => build(&b),
    }
}

fn build(b: &Build) -> Result<(), String> {
    let genesis = load_genesis(&b.genesis)?;
    let (net, params, form) = (genesis.hash(), genesis.wrapper.clone(), genesis.forms().0);
    let signer = rehearsal_signer(&params)?;
    let mut run = match &b.seed {
        Some(seed) => {
            if b.state.exists() {
                return Err(format!("{} exists: a run's state is never overwritten — pass --next to continue it", b.state.display()));
            }
            RunState::new(net, params.l2_id, seed)
        }
        None => {
            let s = RunState::load(&b.state)?;
            if s.genesis != net || s.l2_id != params.l2_id {
                return Err(format!("{} belongs to another genesis or l2_id", b.state.display()));
            }
            if s.bundles.is_empty() {
                return Err(format!("{} holds no deposit yet: --next continues a run", b.state.display()));
            }
            s
        }
    };
    let (state, prev) = run.replay()?;
    let keys = Keys::from_text(&run.seed);
    eprintln!("f5box: reading {}", b.chain);
    let view = chain::read(&Http { base: b.chain.clone() })?;
    let burns = view.burns(form, params.l2_id)?;
    let claims = vec![WTag::C; 16];
    let mix = default_kinds(16);
    let kinds: &[WTag] = if b.exit.is_some() { &mix } else { &claims };
    let ask = Ask { kinds, burns: &burns, owned: &run.owned, exit: b.exit };
    let chain = Chain { view: &view, l2_id: params.l2_id, fee_tier: params.claim_fee_tier };
    let p = match plan(&state, &prev, &chain, &keys, &ask) {
        Ok(p) => p,
        Err(e) => {
            let young = view.immature_burns(params.l2_id);
            return Err(format!(
                "not plannable at tip {}: {e:?} ({} burns appended; the next to mature: {:?})",
                view.anchors.tip_height,
                burns.len(),
                young.first()
            ));
        }
    };
    if b.check {
        let report = json!({
            "mode": "f5box --check", "plannable": true, "tip": view.anchors.tip_height,
            "kinds": p.members.iter().map(|m| format!("{:?}", m.tag)).collect::<Vec<_>>(),
            "absorbed_leaf_counts": p.absorbed.map(|a| a.count),
            "claimed_burn_heights": p.claimed.iter().map(|b| b.height).collect::<Vec<_>>(),
            "d_batch": p.inp.d_batch, "exits": p.exits.len(),
        });
        println!("{}", serde_json::to_string_pretty(&report).expect("json"));
        return Ok(());
    }

    // Both destinations exist before the prove, so an hour of proving can
    // never end with nowhere to write.
    std::fs::create_dir_all(&b.out).map_err(|e| format!("{}: {e}", b.out.display()))?;
    if let Some(dir) = b.state.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut timings = Timings::new();
    let mut log = |what: &str| eprintln!("f5box: proving {what}");
    let proofs = prove(&p, &mut timings, &mut log)?;
    let mut wb = assemble(&p, params.l2_id, proofs);
    sign(&mut wb, &signer, &net);
    let bytes = wb.encode();
    eprintln!("f5box: the node's rule over {} bytes", bytes.len());
    let rule = WrapperRule::from_genesis(&genesis).map_err(|e| format!("{e:?}"))?;
    let t = Instant::now();
    let verdict = self_check(&rule, &bytes, &prev, &view);
    timings.push(("self_check".into(), t.elapsed().as_secs_f64()));
    let mut m = manifest(&p, &wb, &bytes, &net, &view, &timings);
    let stated = plan_surface(params.l2_id, &p);
    let ok = match &verdict {
        Ok(o) => o.surface == encode_surface(&stated) && o.exits == p.exits.iter().map(|e| (digest_to_bytes(&e.rkm), e.v)).collect::<Vec<_>>(),
        Err(_) => false,
    };
    m["self_check"] = match &verdict {
        Ok(o) => json!({"accepted": true, "surface_is_stated": ok, "d_batch": o.d_batch, "e_batch": o.e_batch}),
        Err(r) => json!({"accepted": false, "refusal": format!("{r:?}")}),
    };
    let name = if ok { "bundle.bin" } else { "bundle.refused.bin" };
    std::fs::write(b.out.join(name), &bytes).map_err(|e| format!("{name}: {e}"))?;
    let mpath = b.out.join("manifest.json");
    std::fs::write(&mpath, serde_json::to_string_pretty(&m).expect("json")).map_err(|e| format!("manifest: {e}"))?;
    if !ok {
        return Err(format!("the node's rule refuses the bundle: {verdict:?} — wrote {name}; the state is unchanged"));
    }
    run.push(&p);
    run.save(&b.state)?;
    println!("{}", mpath.display());
    Ok(())
}
