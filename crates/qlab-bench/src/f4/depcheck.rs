//! `qlab-bench f4dep --check`: the deposit AIR's bench entry point, kept in
//! the bench when `f4::dep` moved to qlab-wprover (lab #847 S1a) — a
//! production crate carries no console. Verbatim.
use super::dep::*;

/// `qlab-bench f4dep --check [--n N]`: an honest deposit trace, scanned in full.
pub fn check(args: &[String]) -> Result<(), String> {
    let n = args.iter().position(|a| a == "--n").and_then(|i| args.get(i + 1)).map_or(Ok(3), |s| s.parse::<usize>()).map_err(|e| e.to_string())?;
    let entries = dep_entries(n, 0x775_de9);
    let pvs = dep_pvs(&entries).ok_or("the entries do not fit")?;
    let t = std::time::Instant::now();
    let trace = dep_render(&dep_plan(&entries));
    let gen = t.elapsed();
    let v = dep_first_violation(&trace, &pvs);
    println!(
        "# f4dep --check n={n}: {} rows x {} cols; gen {gen:.2?}, scan {:.2?}; {}",
        DEP_HEIGHT,
        DEP_WIDTH,
        t.elapsed() - gen,
        match &v {
            None => "every row holds".to_string(),
            Some((r, ph)) => format!("VIOLATED at row {r} (perm {}, round {}): {ph:?}", r / 24, r % 24),
        }
    );
    v.map_or(Ok(()), |_| Err("the honest deposit trace does not hold".into()))
}
