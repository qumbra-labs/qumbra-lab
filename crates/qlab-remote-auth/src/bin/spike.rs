use std::{hint::black_box, time::Instant};

use qlab_remote_auth::{
    codec::{AuthSection, Slot},
    hex,
    intent::{fixture_intent, AuthDescriptor, Intent, Scheme},
    keccak256,
    mldsa::{self, Key as MlDsaKey},
    rotation,
    state::{birthday_bound, multi_target_birthday_bound, MAX_TREE_DEPTH},
    tree, wots, Hash32,
};

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("qlab-remote-auth-spike: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("report") {
        "report" if args.len() == 1 => report(),
        "vector" if args.len() == 1 => vector(),
        "measure" => {
            let iterations = parse_number(&args, "--iterations", 10)?;
            measure(iterations)
        }
        "address" => {
            let candidate = args.get(1).ok_or("address needs mldsa or wots")?;
            let depth = args
                .get(2)
                .ok_or("address needs a tree depth")?
                .parse::<u8>()
                .map_err(|_| "address depth is not an integer")?;
            measure_address(candidate, depth)
        }
        _ => Err(
            "usage: qlab-remote-auth-spike [report|vector|measure [--iterations N]|address <mldsa|wots> <depth>]"
                .into(),
        ),
    }
}

fn parse_number(args: &[String], flag: &str, default: usize) -> Result<usize, String> {
    let Some(position) = args.iter().position(|arg| arg == flag) else {
        return Ok(default);
    };
    args.get(position + 1)
        .ok_or_else(|| format!("{flag} needs a value"))?
        .parse()
        .map_err(|_| format!("{flag} is not an integer"))
}

fn report() -> Result<(), String> {
    println!("remote proving authorization spike — research only (lab #630)");
    println!(
        "intent_preimage_bytes mldsa44={} wotsp_sha2_256={}",
        Intent::encoded_len_for(Scheme::MlDsa44),
        Intent::encoded_len_for(Scheme::WotsSha2Stateful)
    );
    let stable_intent = fixture_intent(
        Scheme::MlDsa44,
        [
            AuthDescriptor::MlDsa44 {
                leaf_index: 0x1122_3344,
                leaf: [0x72; 32],
            },
            AuthDescriptor::MlDsa44 {
                leaf_index: 0x5566_7788,
                leaf: [0x82; 32],
            },
        ],
    );
    println!("intent_fixture_digest={}", hex(&stable_intent.digest()));
    println!(
        "auth_section_bytes mldsa44={} wotsp_sha2_256_stateful={} wotsp_sha2_256_random={}",
        AuthSection::encoded_len_for(Scheme::MlDsa44),
        AuthSection::encoded_len_for(Scheme::WotsSha2Stateful),
        AuthSection::encoded_len_for(Scheme::WotsSha2RandomIndex)
    );
    println!(
        "mldsa_minus_wots_bytes={}",
        AuthSection::encoded_len_for(Scheme::MlDsa44)
            - AuthSection::encoded_len_for(Scheme::WotsSha2Stateful)
    );
    let leaf_cost = wots::leaf_cost();
    println!(
        "wots_leaf sha256={} expand={} chain_steps={} ltree_nodes={}",
        leaf_cost.total_sha256, leaf_cost.expand, leaf_cost.chain_steps, leaf_cost.ltree_nodes
    );

    println!("candidate_air_arithmetic current_slots=84 drop_role_ank=2 auth_hash_slots=2*depth");
    // Depth 0 is meaningful for the reusable ML-DSA row: the committed root
    // is the sole leaf and there is no authorization path. WOTS+ still needs
    // a non-empty tree because every leaf is one-time.
    for depth in 0..=MAX_TREE_DEPTH {
        let slots = 84usize - 2 + 2 * depth as usize;
        let active_rows = slots * 3_072;
        let trace_rows = active_rows.next_power_of_two();
        println!(
            "air depth={depth} slots={slots} active_rows={active_rows} trace_rows={trace_rows} outer_tree_nodes={}",
            (1u64 << depth) - 1
        );
    }

    for depth in 1..=MAX_TREE_DEPTH {
        for uses in [10u64, 100, 1_000] {
            println!(
                "random_wots depth={depth} uses_per_target={uses} targets=1 birthday_bound={:.9e}",
                birthday_bound(uses, depth)
            );
            println!(
                "random_wots depth={depth} uses_per_target={uses} targets=1000 birthday_bound={:.9e}",
                multi_target_birthday_bound(uses, 1_000, depth)
            );
        }
    }
    println!("stateful_wots_verdict=blocked_by_old-backup_and-multi-device-index-reuse");
    println!("random_wots_verdict=collision-is-catastrophic; comparator-only; not-SLH-DSA");
    println!("mldsa44_verdict=advance-rotation-tree-only; depth0-fails-public-unlinkability");
    println!(
        "mldsa44_rotation_selector=private-keccak-shuffle-without-replacement; persistence-and-multi-device-are-open-gates"
    );
    println!("mldsa44_rotation_depth=unselected; measure-12-through-16-before-binding");
    Ok(())
}

fn mldsa_fixture() -> (Intent, AuthSection) {
    let keys = [
        MlDsaKey::from_seed([1u8; 32]),
        MlDsaKey::from_seed([2u8; 32]),
    ];
    let descriptors = [keys[0].descriptor(7), keys[1].descriptor(11)];
    let intent = fixture_intent(Scheme::MlDsa44, descriptors);
    let digest = intent.digest();
    let slots = std::array::from_fn(|i| Slot::MlDsa44 {
        descriptor: descriptors[i],
        verifying_key: keys[i].verifying_key_bytes(),
        signature: keys[i].sign(&digest),
    });
    (intent, AuthSection::new(Scheme::MlDsa44, slots).unwrap())
}

fn wots_fixture(scheme: Scheme) -> (Intent, AuthSection, [Hash32; 2]) {
    assert!(matches!(
        scheme,
        Scheme::WotsSha2Stateful | Scheme::WotsSha2RandomIndex
    ));
    let secret_seeds = [[0xb1; 32], [0xb2; 32]];
    let contexts = [[0xc1; 32], [0xc2; 32]];
    let indices = [13, 17];
    let descriptors =
        std::array::from_fn(|i| wots::descriptor(&secret_seeds[i], contexts[i], indices[i]));
    let intent = fixture_intent(scheme, descriptors);
    let digest = intent.digest();
    let slots = std::array::from_fn(|i| Slot::WotsSha2 {
        descriptor: descriptors[i],
        signature: wots::sign(&digest, &secret_seeds[i], &contexts[i], indices[i]).encode(),
    });
    (
        intent,
        AuthSection::new(scheme, slots).unwrap(),
        secret_seeds,
    )
}

fn vector() -> Result<(), String> {
    let (mldsa_intent, mldsa_section) = mldsa_fixture();
    let (wots_intent, wots_section, wots_secrets) = wots_fixture(Scheme::WotsSha2Stateful);

    let reference_secret: Hash32 = std::array::from_fn(|i| i as u8);
    let reference_public: Hash32 = std::array::from_fn(|i| (2 * i) as u8);
    let reference_message: Hash32 = std::array::from_fn(|i| (3 * i) as u8);
    let reference_index = 7u32;
    let reference_descriptor =
        wots::descriptor(&reference_secret, reference_public, reference_index);
    let reference_signature = wots::sign(
        &reference_message,
        &reference_secret,
        &reference_public,
        reference_index,
    );
    let outer_leaves = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];
    let outer_root = tree::root(outer_leaves.to_vec())?;
    let rotation_order = rotation::selection_order(&[0xd1; 32], 4)?;

    println!("format=qlab-remote-auth-vector-v1");
    println!("material=synthetic-public-test-vector-never-use-as-secret");
    println!("rfc8391_reference_commit=171ccbd26f098542a67eb5d2b128281c80bd71a6");
    println!("mldsa_intent_preimage={}", hex(&mldsa_intent.encode()));
    println!("mldsa_intent_digest={}", hex(&mldsa_intent.digest()));
    println!("mldsa_auth_section={}", hex(&mldsa_section.encode()?));
    println!("wots_secret_seed_0={}", hex(&wots_secrets[0]));
    println!("wots_secret_seed_1={}", hex(&wots_secrets[1]));
    println!("wots_intent_preimage={}", hex(&wots_intent.encode()));
    println!("wots_intent_digest={}", hex(&wots_intent.digest()));
    println!("wots_auth_section={}", hex(&wots_section.encode()?));
    println!("reference_wots_secret_seed={}", hex(&reference_secret));
    println!("reference_wots_public_seed={}", hex(&reference_public));
    println!("reference_wots_message={}", hex(&reference_message));
    println!("reference_wots_index={reference_index}");
    println!("reference_wots_leaf={}", hex(&reference_descriptor.leaf()));
    println!(
        "reference_wots_signature={}",
        hex(&reference_signature.encode())
    );
    println!("reference_outer_tree_root={}", hex(&outer_root));
    println!(
        "reference_mldsa_rotation_order_depth4={}",
        rotation_order
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    Ok(())
}

fn measure(iterations: usize) -> Result<(), String> {
    if iterations == 0 {
        return Err("--iterations must be positive".into());
    }
    let digest = [0x5au8; 32];

    let start = Instant::now();
    let mut mldsa_material = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let key = MlDsaKey::from_seed(seed);
        let descriptor = key.descriptor(i as u32);
        black_box(&descriptor);
        mldsa_material.push((key, descriptor));
    }
    let mldsa_keygen = start.elapsed();

    let start = Instant::now();
    let signatures: Vec<_> = mldsa_material
        .iter()
        .map(|(key, _)| black_box(key.sign(&digest)))
        .collect();
    let mldsa_sign = start.elapsed();
    let start = Instant::now();
    for ((key, descriptor), signature) in mldsa_material.iter().zip(&signatures) {
        assert!(mldsa::verify(
            descriptor,
            &key.verifying_key_bytes(),
            signature,
            &digest
        ));
    }
    let mldsa_verify = start.elapsed();

    let secret_seed = [0x11; 32];
    let public_seed = [0x22; 32];
    let start = Instant::now();
    let wots_descriptors: Vec<_> = (0..iterations)
        .map(|i| black_box(wots::descriptor(&secret_seed, public_seed, i as u32)))
        .collect();
    let wots_leaf = start.elapsed();
    let start = Instant::now();
    let wots_signatures: Vec<_> = (0..iterations)
        .map(|i| black_box(wots::sign(&digest, &secret_seed, &public_seed, i as u32).encode()))
        .collect();
    let wots_sign = start.elapsed();
    let start = Instant::now();
    for (descriptor, signature) in wots_descriptors.iter().zip(&wots_signatures) {
        assert!(wots::verify(descriptor, signature, &digest));
    }
    let wots_verify = start.elapsed();

    println!("iterations={iterations}");
    timing("mldsa44_leaf_keygen", mldsa_keygen, iterations);
    timing("mldsa44_sign", mldsa_sign, iterations);
    timing("mldsa44_verify", mldsa_verify, iterations);
    timing("wotsp_sha2_256_leaf", wots_leaf, iterations);
    timing("wotsp_sha2_256_sign", wots_sign, iterations);
    timing("wotsp_sha2_256_verify", wots_verify, iterations);
    Ok(())
}

fn timing(label: &str, elapsed: std::time::Duration, iterations: usize) {
    println!(
        "{label} total_ms={:.3} mean_us={:.3}",
        elapsed.as_secs_f64() * 1_000.0,
        elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
    );
}

fn derive_mldsa_seed(master: &Hash32, index: u32) -> Hash32 {
    keccak256(&[
        b"qumbra:remote-auth:mldsa44-seed:spike-v1",
        master,
        &index.to_le_bytes(),
    ])
}

fn measure_address(candidate: &str, depth: u8) -> Result<(), String> {
    if depth > 24 {
        return Err("address measurement depth must be in 0..=24".into());
    }
    if candidate == "wots" && depth == 0 {
        return Err("WOTS+ needs a non-empty one-time-key tree".into());
    }
    let count = 1usize << depth;
    let public_seed = [0x42u8; 32];
    // Synthetic stand-in for a unique private per-address master. Production
    // derivation must not reuse one master across receiving addresses.
    let address_master = [0x24u8; 32];
    let start = Instant::now();
    let leaves: Vec<Hash32> = match candidate {
        "mldsa" => (0..count)
            .map(|index| {
                let key = MlDsaKey::from_seed(derive_mldsa_seed(&address_master, index as u32));
                key.descriptor(index as u32).leaf()
            })
            .collect(),
        "wots" => (0..count)
            .map(|index| wots::leaf(&address_master, &public_seed, index as u32))
            .collect(),
        _ => return Err("address candidate must be mldsa or wots".into()),
    };
    let leaves_elapsed = start.elapsed();
    let start = Instant::now();
    let root = tree::root(leaves)?;
    let tree_elapsed = start.elapsed();
    println!("candidate={candidate} depth={depth} leaves={count}");
    println!("leaf_generation_secs={:.6}", leaves_elapsed.as_secs_f64());
    println!("outer_tree_secs={:.6}", tree_elapsed.as_secs_f64());
    println!("root={}", hex(&root));
    Ok(())
}
