//! Lab #785 F5-6 (1) — **the run's state file** (`--state FILE`): every
//! wrapper f5box has built, as the inputs and members W threaded, and every
//! note credited to the run. Nothing derived is stored: the wrapper state and
//! the surface the next bundle threads from are **replayed** from the V6
//! genesis state through the native statement, so a state file that does not
//! thread — tampered, or from another genesis — is refused, never trusted.
//!
//! The file records bundles **built**, not mined: a bundle the chain never
//! carried leaves the file ahead of the chain, and the node refuses the next
//! one at V5/V6 (its `prev` is not the chain's surface).
//!
//! JSON, digests as 64-hex of their wire bytes (`digest_to_bytes`).
use qlab_air::l2::RegistryLeaf;
use qlab_wrapper::codec::{digest_from_bytes, digest_to_bytes, exit_chain, stated_surface, Exit};
use qlab_wrapper::genesis::genesis_surface;
use qlab_wrapper::verify::Surface;
use qumbra_node::genesis_v6::{v6_genesis_registry, v6_genesis_registry_root};
use serde_json::{json, Value};

use super::members::{Owned, Plan};
use qlab_wprover::f3::native::Digest;
use qlab_wprover::f4::native::{check_wrapper_leaf, Member, WInputs, WRoots, WState, WTag, M_ABS};
use qlab_wprover::f4::wleaf::{fee_of, w_pvs};

/// The file's format.
pub const STATE_FORMAT: u64 = 1;

/// One wrapper as built.
#[derive(Clone, Debug)]
pub struct Built {
    pub inp: WInputs,
    pub members: Vec<Member>,
    pub exits: Vec<Exit>,
}

/// What f5box has built for one chain.
#[derive(Clone, Debug)]
pub struct RunState {
    /// The V6 genesis hash (the net id the sequencer signs).
    pub genesis: [u8; 32],
    pub l2_id: u64,
    /// The run seed (a rehearsal key schedule, in the clear by design).
    pub seed: String,
    pub bundles: Vec<Built>,
    /// Every note credited to the run, in order; spent ones are skipped by
    /// the planner by their nullifier.
    pub owned: Vec<Owned>,
    /// Lab #847 S4: the id (Keccak-256 of the bytes) of each bundle the
    /// sequencer recorded as landed, in order — so a landing replayed after a
    /// crash is recognised and not recorded twice. Empty for an f5box run.
    pub ids: Vec<[u8; 32]>,
    /// Lab #847 S4: the next bundle number the sequencer hands out —
    /// monotonic over the run's life (drafted bundles included), never reused.
    pub next_n: u64,
}

/// The surface a wrapper states, from its statement — `verify_wrapper`'s
/// success value and the sequencer's signed commitment.
pub fn surface_of(l2_id: u64, rin: &WRoots, rout: &WRoots, inp: &WInputs, members: &[Member], exit_cmt: &Digest) -> Result<Surface, String> {
    let pvs: Vec<u32> =
        w_pvs(rin, rout, inp, fee_of(members), exit_cmt).iter().map(p3_field::PrimeField32::as_canonical_u32).collect();
    stated_surface(qlab_wrapper::genesis::CHAIN_VERSION, l2_id, &pvs).ok_or_else(|| "W's public values state no surface".to_string())
}

/// The surface `plan` states.
pub fn plan_surface(l2_id: u64, p: &Plan) -> Result<Surface, String> {
    surface_of(l2_id, &p.rin, &p.rout, &p.inp, &p.members, &p.exit_cmt)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("not 64 hex characters: {s:?}")); // debug-ok: a hex string from the state file, an id not an opening
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked");
    }
    Ok(out)
}

pub fn digest_hex(d: &Digest) -> String {
    hex(&digest_to_bytes(d))
}

fn digest_of(v: &Value) -> Result<Digest, String> {
    Ok(digest_from_bytes(&unhex32(v.as_str().ok_or("a digest is a string")?)?))
}

fn u64_of(v: &Value, what: &str) -> Result<u64, String> {
    v.as_u64().ok_or_else(|| format!("{what} is not a u64"))
}

pub(crate) fn tag_name(t: WTag) -> &'static str {
    match t {
        WTag::S => "S",
        WTag::P => "P",
        WTag::R => "R",
        WTag::C => "C",
    }
}

pub fn tag_of(s: &str) -> Result<WTag, String> {
    match s {
        "S" => Ok(WTag::S),
        "P" => Ok(WTag::P),
        "R" => Ok(WTag::R),
        "C" => Ok(WTag::C),
        o => Err(format!("unknown member tag {o:?}")), // debug-ok: a tag string from the state file
    }
}

fn leaf_json(l: &RegistryLeaf) -> Value {
    json!({
        "asset": l.asset, "issuer_key": digest_hex(&l.issuer_key), "mode": l.mode,
        "freeze_root": digest_hex(&l.freeze_root), "allow_root": digest_hex(&l.allow_root), "flags": l.flags,
    })
}

fn leaf_of(v: &Value) -> Result<RegistryLeaf, String> {
    Ok(RegistryLeaf {
        asset: u64_of(&v["asset"], "write.asset")?,
        issuer_key: digest_of(&v["issuer_key"])?,
        mode: u64_of(&v["mode"], "write.mode")?,
        freeze_root: digest_of(&v["freeze_root"])?,
        allow_root: digest_of(&v["allow_root"])?,
        flags: u64_of(&v["flags"], "write.flags")?,
    })
}

fn owned_json(n: &Owned) -> Value {
    json!({"value": n.value, "rho": digest_hex(&n.rho), "rseed": digest_hex(&n.rseed)})
}

fn owned_of(v: &Value) -> Result<Owned, String> {
    Ok(Owned { value: u64_of(&v["value"], "owned.value")?, rho: digest_of(&v["rho"])?, rseed: digest_of(&v["rseed"])? })
}

fn exit_json(e: &Exit) -> Value {
    json!({"rkm": digest_hex(&e.rkm), "v": e.v})
}

fn exit_of(v: &Value) -> Result<Exit, String> {
    Ok(Exit { rkm: digest_of(&v["rkm"])?, v: u64_of(&v["v"], "exit.v")? })
}

impl Built {
    pub fn of(p: &Plan) -> Self {
        Built { inp: p.inp.clone(), members: p.members.clone(), exits: p.exits.clone() }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "inputs": {
                "prev": digest_hex(&self.inp.prev),
                "rkm_seq": digest_hex(&self.inp.rkm_seq),
                "absorbed": self.inp.absorbed.iter().map(digest_hex).collect::<Vec<_>>(),
                "d_batch": self.inp.d_batch,
            },
            "members": self.members.iter().map(|m| json!({
                "tag": tag_name(m.tag), "pvs": m.pvs, "write": m.write.as_ref().map(leaf_json),
            })).collect::<Vec<_>>(),
            "exits": self.exits.iter().map(exit_json).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        let i = &v["inputs"];
        let abs: Vec<Digest> = i["absorbed"].as_array().ok_or("inputs.absorbed")?.iter().map(digest_of).collect::<Result<_, _>>()?;
        let absorbed: [Digest; M_ABS] = abs.try_into().map_err(|_| format!("inputs.absorbed is not {M_ABS} roots"))?;
        let inp = WInputs { prev: digest_of(&i["prev"])?, rkm_seq: digest_of(&i["rkm_seq"])?, absorbed, d_batch: u64_of(&i["d_batch"], "d_batch")? };
        let members = v["members"]
            .as_array()
            .ok_or("members")?
            .iter()
            .map(|m| {
                let pvs = m["pvs"]
                    .as_array()
                    .ok_or("member.pvs")?
                    .iter()
                    .map(|w| w.as_u64().and_then(|x| u32::try_from(x).ok()).ok_or("a PV word is not a u32"))
                    .collect::<Result<Vec<u32>, _>>()?;
                let write = if m["write"].is_null() { None } else { Some(leaf_of(&m["write"])?) };
                Ok(Member { tag: tag_of(m["tag"].as_str().ok_or("member.tag")?)?, pvs, write })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let exits = v["exits"].as_array().ok_or("exits")?.iter().map(exit_of).collect::<Result<_, _>>()?;
        Ok(Built { inp, members, exits })
    }
}

impl RunState {
    pub fn new(genesis: [u8; 32], l2_id: u64, seed: &str) -> Self {
        RunState { genesis, l2_id, seed: seed.to_string(), bundles: Vec::new(), owned: Vec::new(), ids: Vec::new(), next_n: 0 }
    }

    /// Record a wrapper the chain applied, as built (lab #847 S4: the loop
    /// pushes only on an observed inclusion). It credits this run nothing —
    /// a claims-only wrapper's credits are its depositors'.
    pub fn push_built(&mut self, id: [u8; 32], b: Built) {
        self.bundles.push(b);
        self.ids.push(id);
    }

    /// Record a built wrapper and its credits.
    pub fn push(&mut self, p: &Plan) {
        self.bundles.push(Built::of(p));
        self.owned.extend(p.credited.iter().copied());
    }

    pub fn to_json(&self) -> Value {
        json!({
            "format": STATE_FORMAT,
            "genesis": hex(&self.genesis),
            "l2_id": self.l2_id,
            "seed": self.seed,
            "bundles": self.bundles.iter().map(Built::to_json).collect::<Vec<_>>(),
            "owned": self.owned.iter().map(owned_json).collect::<Vec<_>>(),
            "ids": self.ids.iter().map(|i| hex(i)).collect::<Vec<_>>(),
            "next_n": self.next_n,
        })
    }

    pub fn from_json(v: &Value) -> Result<Self, String> {
        if v["format"].as_u64() != Some(STATE_FORMAT) {
            return Err(format!("state format {} (this f5box reads {STATE_FORMAT})", v["format"]));
        }
        Ok(RunState {
            genesis: unhex32(v["genesis"].as_str().ok_or("genesis")?)?,
            l2_id: u64_of(&v["l2_id"], "l2_id")?,
            seed: v["seed"].as_str().ok_or("seed")?.to_string(),
            bundles: v["bundles"].as_array().ok_or("bundles")?.iter().map(Built::from_json).collect::<Result<_, _>>()?,
            owned: v["owned"].as_array().ok_or("owned")?.iter().map(owned_of).collect::<Result<_, _>>()?,
            // Absent in an f5box state file (it records neither).
            ids: match v.get("ids") {
                None => Vec::new(),
                Some(a) => a.as_array().ok_or("ids")?.iter().map(|i| unhex32(i.as_str().ok_or("an id")?)).collect::<Result<_, _>>()?,
            },
            next_n: match v.get("next_n") {
                None => 0,
                Some(n) => n.as_u64().ok_or("next_n")?,
            },
        })
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::from_json(&v).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Written atomically ([`write_atomic`]).
    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.to_json()).map_err(|e| format!("state json: {e}"))?;
        write_atomic(path, text.as_bytes())
    }

    /// **Replay** every recorded wrapper from the V6 genesis state through
    /// the native statement: the state and surface the next bundle threads
    /// from. A wrapper that does not thread from its predecessor's surface,
    /// that the statement refuses, or whose exit list does not chain to its
    /// `exit_cmt` is refused by index.
    pub fn replay(&self) -> Result<(WState, Surface), String> {
        let mut state = WState::genesis(&v6_genesis_registry());
        let mut prev = genesis_surface(self.l2_id, &v6_genesis_registry_root());
        for (i, b) in self.bundles.iter().enumerate() {
            if b.inp.prev != prev.commitment {
                return Err(format!("bundle {i} does not thread from its predecessor's surface"));
            }
            let (rin, wit, rout) = state.apply(&b.inp, &b.members).map_err(|e| format!("bundle {i}: {e:?}"))?; // debug-ok: WError: unit and value-free variants only
            let exit_cmt = check_wrapper_leaf(&rin, &b.inp, &b.members, &wit).map_err(|e| format!("bundle {i}: {e:?}"))?.1; // debug-ok: WError: unit and value-free variants only
            if exit_chain(&b.exits) != exit_cmt {
                return Err(format!("bundle {i}: the exit list does not chain to its exit_cmt"));
            }
            prev = surface_of(self.l2_id, &rin, &rout, &b.inp, &b.members, &exit_cmt).map_err(|e| format!("bundle {i}: {e}"))?;
        }
        Ok((state, prev))
    }
}

/// Write `bytes` to `path` via `<file name>.tmp` beside it: written, fsynced,
/// renamed over. A crash leaves the old file or the new one, never half of
/// either; a failed rename removes the temp.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let name = path.file_name().ok_or_else(|| format!("{}: not a file path", path.display()))?;
    let mut tmp_name = name.to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

/// A run's exclusive hold on its state file: `<state>.lock`, created with
/// `create_new` (O_EXCL), removed on drop. Two runs on one state file would
/// both replay the same `prev` and race the rename.
pub struct StateLock(std::path::PathBuf);

impl StateLock {
    pub fn take(state: &std::path::Path) -> Result<Self, String> {
        let mut name = state.file_name().ok_or_else(|| format!("{}: not a file path", state.display()))?.to_os_string();
        name.push(".lock");
        let path = state.with_file_name(name);
        std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| {
            format!("{}: {e} — another f5box run holds this state; remove the lock only if no run is live", path.display())
        })?;
        Ok(StateLock(path))
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
