//! `detaudit` mode (lab #758): the determination census, run from the bench.
//!
//! ```text
//! qlab-bench detaudit --toy [--fixed]            # the engine's probe self-test
//! qlab-bench detaudit --air claim|narrow [--perms N] [--confirm]
//! ```
//!
//! `--toy` runs a 3-column synthetic AIR with a planted class-2 freedom — a
//! mux select `s` pinned only by booleanity and constancy, feeding a value
//! bound to a public value — and must flag it, rank `s` the root, and confirm
//! it SAT with the public value moved (`--fixed` adds `s = 0` and must come
//! back clean). `--air` builds the AIR's house fixture and runs the census
//! over its first `N` perms (default: the whole trace).
//!
//! 🔴 **Local output only.** On a real AIR this prints flagged cells; it is
//! run on the coordinator's box or under a named local-run ruling, never in
//! a public CI log (lab #758 ruling).

use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use std::collections::BTreeMap;

use qlab_air::detaudit::{Census, ManifestEntry, Program, Report, Var};

use crate::Val;

// ---------------------------------------------------------------------------
// Printing and the confirm step
// ---------------------------------------------------------------------------

fn print_report(rep: &Report, width: usize) {
    print_report_named(rep, width, &[]);
}

/// The report, columns named from the AIR's `audit_col_regions()`, flags
/// grouped by pattern (the set of (column, role) buckets) with counts — a
/// million one-row flags are a few patterns repeated per row — and the
/// undetermined public values listed by index.
fn print_report_named(rep: &Report, width: usize, regions: &[(&'static str, usize)]) {
    let name = |col: u32| if regions.is_empty() { format!("col{col}") } else { qlab_air::detaudit::col_name(regions, col as usize) };
    if !rep.pvs_undetermined.is_empty() {
        println!("  PVs undetermined: {:?}", rep.pvs_undetermined);
    }
    let mut patterns: BTreeMap<String, (usize, usize, usize, usize, std::collections::BTreeSet<u32>)> = BTreeMap::new();
    for c in rep.flags() {
        let key: Vec<String> = c.buckets.keys().map(|(col, role)| format!("{}@role{role}", name(*col))).collect();
        let e = patterns.entry(key.join(" ")).or_insert((0, 0, usize::MAX, 0, Default::default()));
        e.0 += 1;
        e.1 += c.cells;
        e.2 = e.2.min(c.min_row);
        e.3 = e.3.max(c.max_row);
        e.4.extend(c.pvs.iter().copied());
    }
    if !patterns.is_empty() {
        println!("  flag patterns ({} distinct):", patterns.len());
        let mut pv: Vec<_> = patterns.into_iter().collect();
        pv.sort_by_key(|(_, e)| std::cmp::Reverse(e.0));
        for (k, (n, cells, lo, hi, pvs)) in pv.iter().take(40) {
            println!("    ×{n} ({cells} cells, rows {lo}..={hi}, PVs {:?}): {k}", pvs.iter().collect::<Vec<_>>());
        }
    }
    println!(
        "cells {} | determined {} | undetermined {} (unconsumed {} in {} malleable classes) | PVs undetermined {} | components {} (flags {})",
        rep.cells,
        rep.determined,
        rep.undetermined,
        rep.unconsumed,
        rep.malleable,
        rep.pvs_undetermined.len(),
        rep.components.len(),
        rep.flags().count()
    );
    let _ = (width, name);
    if rep.copies_underived.is_empty() {
        println!("  witness copies: every tie solved ({} copy groups move with a component's freedom)", rep.copies_in_components.len());
    } else {
        println!("  🔴 WITNESS COPIES WITH AN UNSOLVED TIE — the census below is not sound to read:");
        for (f, r, n) in &rep.copies_underived {
            println!("    {f} @ role{r}: {n} cells");
        }
    }
    for (f, r, n) in &rep.copies_in_components {
        println!("    (in a component: {f} @ role{r}, {n} cells)");
    }
    let allowed: Vec<&qlab_air::detaudit::Component> = rep.components.iter().filter(|c| c.allowed.is_some()).collect();
    if !allowed.is_empty() {
        println!(
            "  allowed: {} components, {} cells, rows {}..={}, reaching PVs {:?}",
            allowed.len(),
            allowed.iter().map(|c| c.cells).sum::<usize>(),
            allowed.iter().map(|c| c.min_row).min().unwrap_or(0),
            allowed.iter().map(|c| c.max_row).max().unwrap_or(0),
            allowed.iter().flat_map(|c| c.pvs.iter()).collect::<Vec<_>>()
        );
    }
    let mut shown: Vec<&qlab_air::detaudit::Component> = rep.components.iter().filter(|c| c.allowed.is_none()).collect();
    shown.sort_by_key(|c| (c.pvs.is_empty(), std::cmp::Reverse(c.cells)));
    for (k, c) in shown.into_iter().enumerate().take(24) {
        let top: Vec<String> = {
            let mut b: Vec<_> = c.buckets.iter().collect::<Vec<_>>();
            b.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
            b.iter().take(6).map(|((col, role), n)| format!("{}@role{role}×{n}", name(*col))).collect()
        };
        if !c.untied_fields.is_empty() {
            println!("  flag {k}: UNTIED WITNESS COPY — {:?} (no other root: the copy's tie is missing)", c.untied_fields);
        }
        println!(
            "  flag {k}: {} cells, rows {}..={}, PVs {:?}, {} | {} orientation roots (+{} copy) | {}",
            c.cells,
            c.min_row,
            c.max_row,
            c.pvs,
            c.allowed.map_or("FLAG".to_string(), |a| format!("allowed: {a}")),
            c.roots.len(),
            c.copy_roots.len(),
            top.join(" ")
        );
    }
}

/// Rank each flag's buckets by a **single-cell** hypothetical pin — a 1-bit
/// freedom's source resolves its whole component from one cell (its carries
/// spread it), a consequence does not — ties broken toward the orientation
/// roots. Confirm the top one by perturbing that one cell and replaying.
fn rank_and_confirm(census: &mut Census<Val>, rep: &Report, confirm: bool, confirm_pv: Option<usize>, p3check: &dyn Fn(RowMajorMatrix<Val>, Vec<Val>) -> bool) {
    let w = census.width();
    // A budget per flag, so a false mega-flag cannot eat a box (lab #758 R2).
    let budget_s: u64 = std::env::var("DETAUDIT_FLAG_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(180);
    let budget = std::time::Duration::from_secs(budget_s);
    // Flags that reach a public value first, smallest first among those (a
    // 74M-cell component must not eat the budget before a 3M-cell one that
    // reaches a different PV — R8's P3), then the rest largest first: a
    // million one-row malleable flags must not crowd out the one that
    // matters (R6's P3). `--confirm-pv N` keeps only the flags reaching PV N.
    let mut order: Vec<&qlab_air::detaudit::Component> =
        rep.components.iter().filter(|c| c.allowed.is_none()).filter(|c| confirm_pv.is_none_or(|p| c.pvs.contains(&(p as u32)))).collect();
    order.sort_by_key(|c| (c.pvs.is_empty(), if c.pvs.is_empty() { -(c.cells as i64) } else { c.cells as i64 }));
    if let Some(p) = confirm_pv {
        println!("  --confirm-pv {p}: {} flags reach it", order.len());
    }
    for (k, c) in order.into_iter().enumerate().take(8) {
        let t0 = std::time::Instant::now();
        // Confirm order differs from the report's: say which component this is.
        println!("  flag {k}: target {} cells, rows {}..={}, PVs {:?}", c.cells, c.min_row, c.max_row, c.pvs);
        let mut ranked = Vec::new();
        // Scope the pins' elimination sweeps to this component (± a perm).
        let rpp = census.rows_per_perm();
        census.set_scope(Some(c.min_row.saturating_sub(rpp)..c.max_row + rpp + 1));
        // Candidates: the orientation roots (never a witness copy) when there
        // are any, else the largest buckets. A root resolving ≥ 90 % of the
        // component ends the ranking — it is the freedom's source.
        let pool: &Vec<(u32, u32)> = if !c.roots.is_empty() { &c.roots } else { &c.copy_roots };
        // `DETAUDIT_CONFIRM_COL=N` (lab #758 R18): confirm from column N's
        // buckets only — a named root the ranking would not reach in budget.
        let forced: Option<u32> = std::env::var("DETAUDIT_CONFIRM_COL").ok().and_then(|v| v.parse().ok());
        let mut cand: Vec<(&(u32, u32), &Vec<usize>)> = match forced {
            Some(col) => c.samples.iter().filter(|(b, _)| b.0 == col).collect(),
            None => c.samples.iter().filter(|(b, _)| pool.is_empty() || pool.contains(b)).collect(),
        };
        if let Some(col) = forced {
            println!("  flag {k}: DETAUDIT_CONFIRM_COL={col}: {} buckets", cand.len());
        }
        cand.sort_by_key(|(b, _)| std::cmp::Reverse(c.buckets[*b]));
        for (&(col, role), cells) in cand.into_iter().take(64) {
            if t0.elapsed() > budget / 2 {
                println!("  flag {k}: ranking stopped at the budget ({} s)", (budget / 2).as_secs());
                break;
            }
            let cell = Var::Cell { row: (cells[0] / w) as u32, col: (cells[0] % w) as u32 };
            let snap = census.snapshot();
            let resolved = census.pin_cells_with(&[cell], false).len();
            census.restore(snap);
            ranked.push(((col, role), cell, resolved, pool.contains(&(col, role))));
            if resolved * 10 >= c.cells * 9 {
                break;
            }
        }
        // Orientation roots first, always: a multi-bit freedom's root (a
        // copy lane) resolves little from one cell, while an accumulator cell
        // summing it resolves a lot — resolution alone ranks the summary over
        // the source. Resolution breaks ties among roots.
        ranked.sort_by_key(|(_, _, n, root)| (!*root, std::cmp::Reverse(*n)));
        let show: Vec<_> = ranked.iter().take(6).map(|(b, _, n, r)| format!("col{}@role{}:{n}{}", b.0, b.1, if *r { "(root)" } else { "" })).collect();
        println!("  flag {k}: single-cell ranking {}", show.join(" "));
        if !confirm {
            continue;
        }
        let Some(&((col, role), _, _, _)) = ranked.first() else { continue };
        // Confirm from the root's sample cells in turn; report the first
        // that moves a public value (else the last tried).
        let cells: Vec<Var> = c.samples[&(col, role)].iter().map(|i| Var::Cell { row: (i / w) as u32, col: (i % w) as u32 }).collect();
        'cells: for (n, cell) in cells.iter().copied().enumerate() {
            // Cone first (the fixpoint carries the flip down its cone — cheap
            // on any size); only if that is UNSAT, retry with the ties a pin
            // re-opens solved (elimination, scoped to the component).
            for with_elim in [false, true] {
                if t0.elapsed() > budget {
                    println!("  flag {k}: confirm stopped at the budget ({} s) — unconfirmed", budget.as_secs());
                    break 'cells;
                }
                let snap = census.snapshot();
                // Pin the chosen cell; the root column's other free cells, the
                // component's other roots, and any copy root still free after
                // that are held at their honest values — only `cell` moves.
                let mut resolved = census.pin_cells_with(&[cell], with_elim);
                let mut hold: Vec<(u32, u32)> = vec![(col, role)];
                hold.extend(c.roots.iter().copied().filter(|b| *b != (col, role)));
                hold.extend(c.copy_roots.iter().copied().filter(|b| *b != (col, role)));
                for (oc, orole) in hold {
                    let other = census.undetermined_in(oc, orole);
                    if !other.is_empty() {
                        resolved.extend(census.pin_cells_with(&other, with_elim));
                    }
                }
                // Flip a boolean root (0 ↔ 1); nudge anything else by one.
                let rep = census.repair(&[cell], |v| if v == Val::ZERO { Val::ONE } else if v == Val::ONE { Val::ZERO } else { v + Val::ONE }, &resolved);
                let bad = census.violations(&rep, 5);
                let moved: Vec<usize> = (0..rep.pvs.len()).filter(|i| rep.pvs[*i] != census.pvs()[*i]).collect();
                if !bad.is_empty() && !with_elim {
                    census.restore(snap);
                    continue; // retry with elimination
                }
                let last = n + 1 == cells.len();
                if bad.is_empty() && moved.is_empty() && !last {
                    census.restore(snap);
                    continue 'cells;
                }
                let cells_moved = rep.overlay.iter().filter(|(i, x)| **x != census.value(**i)).count();
                println!(
                    "  flag {k}: confirm col{col}@role{role} {cell:?} flipped ({} replayed{}, {cells_moved} cells moved): {} — PVs moved {:?}{}",
                    resolved.len(),
                    if with_elim { ", ties re-solved" } else { ", cone" },
                    if bad.is_empty() { "SAT" } else if c.roots.len() > 1 { "UNSAT (other roots held — not a refutation)" } else { "UNSAT" },
                    moved,
                    if bad.is_empty() { String::new() } else { format!(" — first violations (constraint, row) {bad:?}") }
                );
                if bad.is_empty() {
                    match census.materialize(&rep) {
                        Some((m, pv)) => println!("  flag {k}: independent p3 check_constraints on the full repaired trace: {}", if p3check(m, pv) { "SAT" } else { "UNSAT" }),
                        None => println!("  flag {k}: windowed census — the full-trace p3 check is the box run's"),
                    }
                }
                census.restore(snap);
                break 'cells;
            }
        }
        census.set_scope(None);
    }
}

/// Lab #758 R14 — P3's digest-bound and bank-bound copies probed directly:
/// under the CR premise with two **holes** (nk on the first absorbing row of
/// `ARKM′` and of `ARKM″`, left undetermined), pin one hole, flip it by one,
/// replay its forward cone, and print the first violations named. A tie
/// shows as a violation on the binding window (third bank / bind bank);
/// SAT, or violations only elsewhere, is a stop. Then each bank-bound copy
/// (ρ@ACM, ρ@ACMF, output ρ, nf1@ARHO) with both holes pinned: determined
/// (its tie solved) or probed the same way.
#[allow(clippy::too_many_arguments)]
fn probe_bindings<A>(air: &A, trace: RowMajorMatrix<Val>, pvs: &[Val], program: Program, manifest: &[ManifestEntry], bits: Vec<u32>, pv_inputs: &[usize])
where
    A: BaseAir<Val> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>> + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    use qlab_air::l2::{ROLE_ACM, ROLE_ACMF, ROLE_ACMOUT, ROLE_ARHO, ROLE_ARKM};
    use qlab_air::l2p::ROLE_ARKM2;
    let w = <A as BaseAir<Val>>::width(air);
    let h = trace.values.len() / w;
    let rpp = program.rows_per_perm;
    let reads = qlab_air::l2p::audit_copy_reads();
    // The first absorbing row of the k-th perm of `role` under `gate`.
    let nth_row = |role: u32, gate: usize, k: usize| -> Option<usize> {
        let mut perms = Vec::new();
        for row in 0..h {
            if program.role_of_row(row) == role && trace.values[row * w + gate] != Val::ZERO {
                let p = row / rpp;
                if perms.last() != Some(&p) {
                    perms.push(p);
                    if perms.len() == k + 1 {
                        return Some(row);
                    }
                }
            }
        }
        None
    };
    let (nk_gate, nk_cols) = (reads[0].1, reads[0].2.clone());
    let (Some(r1), Some(r2)) = (nth_row(ROLE_ARKM2, nk_gate, 0), nth_row(ROLE_ARKM2, nk_gate, 1)) else {
        println!("🔴 PROBE DEFECT: no ARKM′/ARKM″ absorbing rows found");
        return;
    };
    // Every target row, found before the census takes the trace.
    // (nk@ARKM: bank 1 — input 0's, and the fee chain's, the third ARKM.)
    let targets: Vec<(Option<usize>, usize, &str)> = [
        (0usize, ROLE_ARKM, 0usize, "nk@ARKM (input 0, bank 1)"),
        (0, ROLE_ARKM, 2, "nk@ARKM (fee chain, bank 1)"),
        (1, ROLE_ACM, 0, "ρ@ACM"),
        (2, ROLE_ACMF, 0, "ρ@ACMF"),
        (3, ROLE_ACMOUT, 0, "output ρ@ACMOUT"),
        (4, ROLE_ARHO, 0, "nf1@ARHO"),
    ]
    .into_iter()
    .map(|(idx, role, k, name)| (nth_row(role, reads[idx].1, k), reads[idx].2[0], name))
    .collect();
    let h1 = Var::Cell { row: r1 as u32, col: nk_cols[0] as u32 };
    let h2 = Var::Cell { row: r2 as u32, col: nk_cols[0] as u32 };
    println!("# probe: holes nk@ARKM′ row {r1} (perm {}), nk@ARKM″ row {r2} (perm {})", r1 / rpp, r2 / rpp);
    let mut census = Census::run_with_holes(air, trace, pvs, program, manifest, h, Some(bits), pv_inputs, &[h1, h2]);
    let show = |census: &Census<Val>, label: &str, bad: &[(usize, usize)], moved: usize| {
        if bad.is_empty() {
            println!("  🔴 {label}: SAT — no violation ({moved} cells moved): NOT TIED");
        } else {
            println!("  {label}: {} cells moved; first violations:", moved);
            for (c, row) in bad {
                let d = census.describe_constraint(*c);
                println!("    constraint {c} row {row} (role {}): {}", census.role_of_row(*row), d.chars().take(200).collect::<String>());
            }
        }
    };
    let probe = |census: &mut Census<Val>, label: &str, pre: &[Var], cell: Var| {
        let snap = census.snapshot();
        for p in pre {
            census.pin_cells_with(&[*p], false);
        }
        if census.is_determined(cell) {
            println!("  {label}: determined with the holes pinned (its tie solved)");
            census.restore(snap);
            return;
        }
        let cone = census.pin_cells_with(&[cell], false);
        let rep = census.repair(&[cell], |v| v + Val::ONE, &cone);
        let bad = census.violations(&rep, 6);
        let moved = rep.overlay.iter().filter(|(i, x)| **x != census.value(**i)).count();
        show(census, &format!("{label} (cone {})", cone.len()), &bad, moved);
        census.restore(snap);
    };
    probe(&mut census, "nk@ARKM′ +1", &[], h1);
    probe(&mut census, "nk@ARKM″ +1", &[h1], h2);
    for (row, col, name) in targets {
        match row {
            Some(r) => probe(&mut census, &format!("{name} row {r} +1"), &[h1, h2], Var::Cell { row: r as u32, col: col as u32 }),
            None => println!("  🔴 PROBE DEFECT: no absorbing row for {name}"),
        }
    }
}

/// P3's `vPublic` block split by field (lab #758 R10): which of each balance
/// row's redeem / amount chunks / asset id the census left undetermined.
fn print_vpublic_split(undetermined: &[u32]) {
    use qlab_air::l2p::{PV_VP1, PV_VP2};
    for (k, base) in [PV_VP1, PV_VP2].into_iter().enumerate() {
        let und = |i: usize| undetermined.contains(&(i as u32));
        let chunks: Vec<usize> = (0..4).filter(|j| und(base + 1 + j)).collect();
        println!(
            "  vPublic row {}: redeem {} | amount chunks undetermined {:?} of 0..4 | vpa {}",
            k + 1,
            if und(base) { "UNDETERMINED" } else { "determined" },
            chunks,
            if und(base + 5) { "UNDETERMINED" } else { "determined" }
        );
    }
}

/// The enumeration's log (lab #758 R11): every group it decided that bears
/// on a public value — unique (determined) or ambiguous (≥ 2: a candidate
/// freedom of those equations, shown loudly).
fn print_enum_log(census: &Census<Val>) {
    let log = &census.enum_log;
    let decided: Vec<_> = log.iter().filter(|g| g.undecided.is_none()).collect();
    let amb: Vec<_> = decided.iter().filter(|g| g.solutions != 1).collect();
    println!("  enumeration: {} groups bearing on PVs, {} ambiguous, {} undecided (logged)", decided.len(), amb.len(), log.len() - decided.len());
    for g in decided.iter().filter(|g| g.solutions == 1).take(12) {
        println!("    unique: row {} ({} eqs, {} bools) PVs {:?}", g.row, g.eqs, g.bools, g.pvs);
    }
    for g in amb.iter().take(24) {
        if g.solutions == 0 {
            println!("    🔴 NO SOLUTION (probe defect): row {} ({} eqs, {} bools) PVs {:?}", g.row, g.eqs, g.bools, g.pvs);
        } else {
            let show = |x: &Option<u32>| x.map_or("free".to_string(), |v| v.to_string());
            let agreeing: Vec<String> = g
                .pv_values
                .iter()
                .filter(|(i, _)| !g.pvs_free.contains(i))
                .map(|(i, vals)| format!("{i}={}", vals.first().map_or("?".to_string(), show)))
                .collect();
            println!(
                "    AMBIGUOUS: row {} ({} eqs, {} bools): {} in-range solutions — PVs differing across solutions: {:?}; agreeing: [{}]",
                g.row, g.eqs, g.bools, g.solutions, g.pvs_free, agreeing.join(", ")
            );
            for (i, vals) in g.pv_values.iter().filter(|(i, _)| g.pvs_free.contains(i)) {
                println!("      PV {i} per solution: [{}]", vals.iter().map(show).collect::<Vec<_>>().join(", "));
            }
        }
    }
    for g in log.iter().filter(|g| g.undecided.is_some()).take(12) {
        println!("    undecided: row {} ({} eqs, {} bools) PVs {:?}: {}", g.row, g.eqs, g.bools, g.pvs, g.undecided.as_deref().unwrap_or(""));
    }
}

/// p3's own `check_constraints` (it panics on a violation), as a verdict.
fn p3_sat<A>(air: &A, m: &RowMajorMatrix<Val>, pv: &[Val]) -> bool
where
    A: for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>> + BaseAir<Val>,
{
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| p3_air::check_constraints(air, m, &pv.to_vec()))).is_ok();
    std::panic::set_hook(hook);
    ok
}

fn print_bindings(probes: &[qlab_air::detaudit::BindingProbe]) {
    println!("## L2b binding census: {} probes", probes.len());
    for p in probes {
        println!(
            "  {} @ role{} col{} row {}: {} — PVs moved {:?}{}",
            p.field,
            p.role,
            p.col,
            p.row,
            if p.violations.is_empty() { "UNTIED (SAT)" } else { "tied (UNSAT)" },
            p.pvs_moved,
            if p.violations.is_empty() { String::new() } else { format!(" — refused at (constraint, row) {:?}", p.violations) }
        );
    }
}

pub(crate) fn run_detaudit(args: &[String]) {
    let flag = |f: &str| args.iter().any(|a| a == f);
    let opt = |f: &str| args.iter().position(|a| a == f).and_then(|i| args.get(i + 1)).cloned();
    let confirm = flag("--confirm");
    let t = std::time::Instant::now();
    // Lab #758: every public value is a 16-bit chunk by the verifier's own
    // construction (`pv_chunks`/`pv_vec`); `--no-pv-range` drops the premise.
    let no_range = flag("--no-pv-range");
    if flag("--toy") && (flag("--sign-top") || flag("--sign-wrap")) {
        // Lab #758 R11: the enumeration's control — the signed chain with its
        // top chunk (one solution) and without (the wrap: two).
        use qlab_air::detaudit::toy::{sign_manifest, sign_program, sign_trace, SignRig, SIGN_HEIGHT, SIGN_WIDTH};
        let top = flag("--sign-top");
        let (m, pv) = sign_trace::<Val>();
        let air = SignRig { top };
        println!("# detaudit --toy {} (expect {} in-range solution{})", if top { "--sign-top" } else { "--sign-wrap" }, if top { 1 } else { 2 }, if top { "" } else { "s" });
        let census = Census::run(&air, m, &pv, sign_program(), &sign_manifest(), SIGN_HEIGHT, Some(vec![1, 16, 16]));
        print_enum_log(&census);
        let mut census = census;
        let rep = census.report(&[]);
        print_report(&rep, SIGN_WIDTH);
        println!("elapsed {:.2} s", t.elapsed().as_secs_f64());
        return;
    }
    if flag("--toy") {
        use qlab_air::detaudit::toy::{self, Rig};
        let fixed = flag("--fixed");
        let copy_as_input = flag("--copy-as-input");
        let air = Rig { fixed, mixed: flag("--mixed") };
        let (trace, pvs) = toy::trace::<Val>();
        let manifest = toy::manifest(copy_as_input);
        let pv_bits = (!no_range).then(|| vec![16; 5]);
        println!("# detaudit --toy{}{}{}", if fixed { " --fixed" } else { "" }, if copy_as_input { " --copy-as-input" } else { "" }, if no_range { " --no-pv-range" } else { "" });
        if flag("--vacuous") {
            let c = Census::run(&air, trace, &pvs, toy::program(), &manifest, toy::HEIGHT, pv_bits);
            let v = c.vacuous_constraints(&(0..toy::HEIGHT).collect::<Vec<_>>(), &manifest);
            println!("vacuous: {} constraints", v.len());
            let offs: Vec<usize> = (0..toy::HEIGHT).collect();
            for i in &v {
                println!("  [{}] {}", if c.is_live_somewhere(*i, &offs) { "implied" } else { "inert" }, c.describe_constraint(*i));
            }
            let gated = c.constraints_reading_exactly(&[toy::T, toy::U, toy::Z]);
            println!("control: gated read {:?} vacuous = {}", gated, if gated.iter().all(|i| v.contains(i)) { "yes" } else { "no — PROBE DEFECT" });
        } else if flag("--l1") {
            let mut c = Census::for_l1(&air, trace, &pvs, toy::program());
            let flags = c.l1_rows(&manifest, &(0..toy::HEIGHT).collect::<Vec<_>>());
            println!("L1: {} flags", flags.len());
            for f in &flags {
                println!("  col{}@role{} (row {}) — reader {}", f.col, f.role, f.row, c.describe_constraint(f.reader as usize));
            }
        } else {
            let mut census = Census::run(&air, trace, &pvs, toy::program(), &manifest, toy::HEIGHT, pv_bits);
            let rep = census.report(&[]);
            print_report(&rep, toy::WIDTH);
            rank_and_confirm(&mut census, &rep, true, None, &|m, pv| p3_sat(&air, &m, &pv));
        }
        println!("elapsed {:.2} s", t.elapsed().as_secs_f64());
        return;
    }
    let air_name = opt("--air").unwrap_or_else(|| {
        eprintln!("detaudit: `--toy` or `--air claim|narrow` is required");
        std::process::exit(2);
    });
    let perms: Option<usize> = opt("--perms").map(|p| p.parse().expect("--perms takes a perm count"));
    let confirm_pv: Option<usize> = opt("--confirm-pv").map(|p| p.parse().expect("--confirm-pv takes a PV index"));
    let mode = Mode { l1: flag("--l1"), l2b: flag("--l2b"), confirm: confirm || confirm_pv.is_some(), confirm_pv, perms, no_range, floor: flag("--floor") };
    let fixture = opt("--fixture").unwrap_or_else(|| "house".to_string());
    macro_rules! run {
        ($name:expr, $air:expr, $pvs:expr, $program:expr, $manifest:expr, $bits:expr, $regions:expr, $pvin:expr) => {{
            let air = $air;
            let trace = air.generate_trace::<Val>(0);
            println!("## fixture `{fixture}`");
            // The fixture's own SAT gate: a fixture that is not a satisfying
            // trace stops here — its census output would be meaningless.
            let sat = p3_sat(air, &trace, &$pvs);
            println!("fixture {fixture}: p3 {}", if sat { "SAT" } else { "UNSAT — STOP (this fixture's runs are void)" });
            if !sat {
                return;
            }
            if flag("--probe-arkm2") {
                probe_bindings(air, trace, &$pvs, $program, &$manifest, $bits, &$pvin);
            } else if flag("--vacuous") {
                // Vacuity needs the census (what it leaned on), not L1.
                let height = trace.values.len() / <_ as BaseAir<Val>>::width(air);
                let c = Census::run_with_pv_inputs(air, trace, &$pvs, $program, &$manifest, height, Some($bits), &$pvin);
                let offsets: Vec<usize> = [0usize, 1, 23].iter().flat_map(|q| (128 * q)..(128 * (q + 1))).collect();
                let v = c.vacuous_constraints(&offsets, &$manifest);
                if $name == "narrow" {
                    let pin = c.constraints_reading_exactly(&qlab_air::narrow::audit_dv_value_pin_reads());
                    let on = pin.iter().all(|i| v.contains(i)) && !pin.is_empty();
                    println!("control: #219 pin {:?} vacuous on {fixture} = {}", pin, if on { "yes" } else { "no" });
                    let nf = c.constraints_reading_exactly(&qlab_air::narrow::audit_nf_pbit_pin_reads());
                    let on = nf.iter().any(|i| v.contains(i)) || nf.is_empty();
                    println!("control: NF pbit pin {:?} vacuous on {fixture} = {}", nf, if on { "yes — PROBE DEFECT" } else { "no" });
                }
                println!("# detaudit --vacuous --air {} --fixture {fixture}: {} constraints vacuous on this trace", $name, v.len());
                for i in &v {
                    println!("  [{}] {}", if c.is_live_somewhere(*i, &offsets) { "implied" } else { "inert" }, c.describe_constraint(*i));
                }
            } else {
                census_air($name, air, trace, &$pvs, $program, &$manifest, $bits, &mode, $regions, $pvin);
            }
        }};
    }
    match (air_name.as_str(), fixture.as_str()) {
        ("claim", f) => {
            let inst = claim_fixture(f);
            let pvs = qlab_l2::public_values(&inst.pvs);
            run!("claim", &inst.air, pvs, qlab_air::claim::audit_program(&inst.air), qlab_air::claim::witness_manifest(), qlab_air::claim::audit_pv_bits(), qlab_air::claim::audit_col_regions(), Vec::new());
        }
        ("narrow", f) => {
            let inst = narrow_fixture(f);
            let pvs: Vec<Val> = inst.pvs.iter().map(|v| Val::from_u32(*v)).collect();
            run!("narrow", &inst.air, pvs, qlab_air::narrow::audit_program(&inst.air), qlab_air::narrow::witness_manifest(), qlab_air::narrow::audit_pv_bits(), qlab_air::narrow::audit_col_regions(), Vec::new());
        }
        ("s3", f) => {
            let inst = match f {
                "house" => qlab_l2::fixture::shape_s(),
                "merge" => qlab_l2::fixture::shape_s3_merge_at(qlab_l2::LOG_HEIGHT_S),
                other => bad_fixture("s3", other),
            };
            let pvs = qlab_l2::public_values(&inst.pvs);
            run!("s3", &inst.air, pvs, qlab_air::l2::audit_program(&inst.air), qlab_air::l2::witness_manifest(), qlab_air::l2::audit_pv_bits(), qlab_air::l2::audit_col_regions(), Vec::new());
        }
        ("p3", f) => {
            let inst = match f {
                "house" => qlab_l2::fixture::shape_p(),
                "merge" => qlab_l2::fixture::shape_p3_merge_at(qlab_l2::LOG_HEIGHT_P),
                // Lab #758: the q = 1 summed chain carrying a nonzero vPublic₁.
                "merge-mint" => qlab_l2::fixture::shape_p3_merge_vp_at(qlab_l2::LOG_HEIGHT_P, 120_000, qlab_air::l2p::VPublic::mint(70_000)),
                "merge-redeem" => qlab_l2::fixture::shape_p3_merge_vp_at(qlab_l2::LOG_HEIGHT_P, 30_000, qlab_air::l2p::VPublic::redeem(20_000)),
                // Lab #758: the balance with a nonzero vPublic, both signs —
                // 70,000 spans two 16-bit chunks (4,464 + 1·2^16).
                "mint" => qlab_l2::fixture::shape_p_asset7_at(qlab_l2::LOG_HEIGHT_P, 30_000, 100_000, qlab_air::l2p::VPublic::mint(70_000)),
                "redeem" => qlab_l2::fixture::shape_p_asset7_at(qlab_l2::LOG_HEIGHT_P, 100_000, 30_000, qlab_air::l2p::VPublic::redeem(70_000)),
                other => bad_fixture("p3", other),
            };
            let pvs = qlab_l2::public_values(&inst.pvs);
            let mut manifest = qlab_air::l2p::witness_manifest();
            if flag("--cr-premise") || flag("--probe-arkm2") {
                println!("  premise (collision resistance): input.nk @ ARKM′/″ declared a source — bound only through its output (l2p::audit_cr_premise)");
                manifest.extend(qlab_air::l2p::audit_cr_premise());
            }
            if flag("--pin-sel2") {
                println!("  ⚠️ --pin-sel2: o1a/o2a declared sources — a DIAGNOSTIC premise (the q = 1 accounting freedom), not for a verdict");
                manifest.push(qlab_air::l2p::audit_sel2_accounting());
            }
            if flag("--pin-cmp") {
                println!("  ⚠️ --pin-cmp: the compare's cells declared sources — a DIAGNOSTIC premise, not for a verdict");
                manifest.push(qlab_air::l2p::audit_cmp_cells());
            }
            run!("p3", &inst.air, pvs, qlab_air::l2p::audit_program(&inst.air), manifest, qlab_air::l2p::audit_pv_bits(), qlab_air::l2p::audit_col_regions(), if flag("--no-pv-inputs") { Vec::new() } else { qlab_air::l2p::audit_pv_inputs(&inst.pvs) });
        }
        ("r", f) => {
            let inst = match f {
                "house" | "update" => qlab_l2::fixture::shape_r(),
                "register" => r_registration(),
                other => bad_fixture("r", other),
            };
            let pvs = qlab_l2::public_values(&inst.pvs);
            run!("r", &inst.air, pvs, qlab_air::l2r::audit_program(&inst.air), qlab_air::l2r::witness_manifest(), qlab_air::l2r::audit_pv_bits(), qlab_air::l2r::audit_col_regions(), Vec::new());
        }
        (other, _) => {
            eprintln!("detaudit: unknown --air `{other}`; expected claim|narrow|s3|p3|r");
            std::process::exit(2);
        }
    }
    println!("elapsed {:.2} s", t.elapsed().as_secs_f64());
}

struct Mode {
    l1: bool,
    l2b: bool,
    confirm: bool,
    /// Confirm only the flags reaching this public value (implies `--confirm`).
    confirm_pv: Option<usize>,
    perms: Option<usize>,
    no_range: bool,
    /// Run with every witness copy taken as an input — the floor to diff a
    /// normal run against: a flag present only without `--floor` is either a
    /// freedom a copy would mask, or an unsolved tie.
    floor: bool,
}

/// One AIR through the census: L1 (`--l1`), or L2 (+ L3 with `--confirm`,
/// + L2b with `--l2b`) over the first `--perms` perms or the whole trace.
#[allow(clippy::too_many_arguments)]
fn census_air<A>(name: &str, air: &A, trace: RowMajorMatrix<Val>, pvs: &[Val], program: Program, manifest: &[ManifestEntry], pv_bits: Vec<u32>, mode: &Mode, regions: Vec<(&'static str, usize)>, pv_inputs: Vec<usize>)
where
    A: BaseAir<Val> + Air<p3_air::symbolic::SymbolicAirBuilder<Val>> + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    let rpp = program.rows_per_perm;
    let height = trace.values.len() / <A as BaseAir<Val>>::width(air);
    if mode.l1 {
        let mut c = Census::for_l1(air, trace, pvs, program);
        let (flags, (roles, consumed, defined)) = c.l1_with_stats(manifest);
        println!("# detaudit --l1 --air {name}: {} flags ({roles} roles sampled; (col, role) pairs consumed {consumed}, defined {defined})", flags.len());
        for f in &flags {
            println!("  col{}@role{} (row {}) — reader {}", f.col, f.role, f.row, c.describe_constraint(f.reader as usize));
        }
        return;
    }
    let rows = mode.perms.map_or(height, |p| p * rpp);
    let floor_manifest: Vec<ManifestEntry> = manifest.iter().cloned().map(|mut m| {
        m.copy = false;
        m
    }).collect();
    let manifest = if mode.floor { &floor_manifest[..] } else { manifest };
    if !pv_inputs.is_empty() {
        println!("  verifier-supplied PVs (premise): {pv_inputs:?}");
    }
    let mut census = Census::run_with_pv_inputs(air, trace, pvs, program, manifest, rows, (!mode.no_range).then_some(pv_bits), &pv_inputs);
    print_enum_log(&census);
    let rep = census.report(&[qlab_air::detaudit::warmup_allowance(rpp)]);
    println!("# detaudit --air {name} (rows 0..{rows} of {height}){}", if mode.floor { " --floor (copies as inputs)" } else { "" });
    print_report_named(&rep, census.width(), &regions);
    if name == "p3" {
        print_vpublic_split(&rep.pvs_undetermined);
        for (field, gate, cols) in qlab_air::l2p::audit_copy_reads() {
            let pass_end = census.rows_per_perm() * qlab_air::l2p::PROGRAM_SLOTS;
            for (role, (cells, und, perms)) in census.undetermined_at_gate(gate, &cols) {
                let where_ = if perms.is_empty() {
                    String::new()
                } else {
                    let p2 = perms.iter().all(|p| p * census.rows_per_perm() >= pass_end);
                    format!(" — in perms {perms:?}{}", if p2 { " (all in the ep = 0 second pass)" } else { "" })
                };
                println!("  copy read: {field} @ role{role}: {und} of {cells} cells undetermined on the absorbing rows{where_}");
            }
        }
    }
    rank_and_confirm(&mut census, &rep, mode.confirm, mode.confirm_pv, &|m, pv| p3_sat(air, &m, &pv));
    if mode.l2b {
        let probes = census.binding_census_budget(manifest, std::time::Duration::from_secs(300), &mut |m| println!("  {m}"));
        print_bindings(&probes);
    }
}

fn bad_fixture(air: &str, f: &str) -> ! {
    eprintln!("detaudit: unknown --fixture `{f}` for --air {air}");
    std::process::exit(2);
}

/// The narrow fixtures (witness-mode coverage, lab #758): `house` — the
/// bench's seeded 2×2 (two real inputs, fee 1,000, leaves at tree positions
/// 0/1 — path bit 1 only at input 2's level 0); `dummy1` — slot 1 a dummy
/// (`dv = 1`, value 0, an off-tree path: the #219 mode).
fn narrow_fixture(f: &str) -> qlab_air::narrow::BucketInstance {
    use qlab_air::narrow::{build_bucket_dummy1, derive_input, fabricated_single_tree, off_tree_witness, TxInput, TxOutput};
    match f {
        "house" => crate::m4gaterec::bucket_instance_seeded(0xfeed_face_cafe_beef).0,
        "dummy1" => {
            let real = TxInput { sk: [0x11, 0x12, 0x13, 0x14], value: 80_000, rho: [0x21, 0x22, 0x23, 0x24], rseed: [0x31, 0x32, 0x33, 0x34], d: [5, 6] };
            let dummy = TxInput { sk: [0x41, 0x42, 0x43, 0x44], value: 0, rho: [0x51, 0x52, 0x53, 0x54], rseed: [0x61, 0x62, 0x63, 0x64], d: [0, 0] };
            let (_, _, cm) = derive_input(&real);
            let (w, anchor) = fabricated_single_tree(&cm);
            let outputs = [
                TxOutput { value: 60_000, rkm: [0x71; 4], rho: [0; 4], rseed: [0x72; 4] },
                TxOutput { value: 19_000, rkm: [0x73; 4], rho: [0; 4], rseed: [0x74; 4] },
            ];
            build_bucket_dummy1(qlab_consensus::LOG_HEIGHT, &real, &w, &dummy, &off_tree_witness(), &outputs, 1_000, anchor)
        }
        other => bad_fixture("narrow", other),
    }
}

/// The claim fixtures: `house` (all path bits 0, fee 4); `pathbits` (a
/// random path: the Merkle mux's swapped branch); `fee0`; `feeall` (a
/// 0-value credit).
fn claim_fixture(f: &str) -> qlab_air::claim::ClaimInstance {
    use qlab_air::claim::{build_claim, build_claim_with_witness, l1_cm, rkm_burn, BurnNote, ClaimCredit};
    use qlab_air::narrow::{MerkleWitness, MERKLE_DEPTH};
    let log = qlab_l2::claim::LOG_HEIGHT_CLAIM;
    let note = BurnNote { value: 250_000, rkm: rkm_burn(1), rho: [0xa1, 0xa2, 0xa3, 0xa4], rseed: [0xb1, 0xb2, 0xb3, 0xb4] };
    let credit = ClaimCredit { rkm: [0xc1, 0xc2, 0xc3, 0xc4], rseed: [0xd1, 0xd2, 0xd3, 0xd4] };
    let r_v = [0xe1, 0xe2, 0xe3, 0xe4];
    match f {
        "house" => qlab_l2::fixture::claim(),
        "fee0" => build_claim(log, 1, &note, &r_v, &credit, 0),
        "feeall" => build_claim(log, 1, &note, &r_v, &credit, note.value),
        "pathbits" => {
            let mut x = 0x0758_9a7b_u64;
            let mut rnd = || {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x
            };
            let mut w = MerkleWitness { siblings: [[0; 4]; MERKLE_DEPTH], path_bits: [false; MERKLE_DEPTH] };
            for l in 0..MERKLE_DEPTH {
                w.siblings[l] = [rnd(), rnd(), rnd(), rnd()];
                w.path_bits[l] = rnd() & 1 == 1;
            }
            let cm = l1_cm(note.value, &note.rkm, &note.rho, &note.rseed);
            let anchor = w.fold_root(&cm);
            build_claim_with_witness(log, &rkm_burn(1), &note, &w, anchor, &r_v, &credit, 4)
        }
        other => bad_fixture("claim", other),
    }
}

/// Shape R's registration mode (the house fixture is an update): asset 9
/// registered Cloaked into its empty slot.
fn r_registration() -> qlab_air::l2r::L2ShapeRInstance {
    use qlab_air::l2::{L2TxInput, L2TxOutput, RegistryLeaf};
    use qlab_air::l2r::{build_shape_r, registry_opening, RegistryWrite, SeedOutput};
    let fee = qlab_l2::FEE_TIER_R_PLACEHOLDER;
    let input = L2TxInput { sk: [0x5a1, 0x5a2, 0x5a3, 0x5a4], value: 50_000, asset: 0, rho: [0x6b1, 0x6b2, 0x6b3, 0x6b4], rseed: [0x7c1, 0x7c2, 0x7c3, 0x7c4], d: [0x8d1, 0x8d2] };
    let output = L2TxOutput { value: 50_000 - fee, asset: 0, rkm: [0x9e1, 0x9e2, 0x9e3, 0x9e4], rho: [0; 4], rseed: [0xaf1, 0xaf2, 0xaf3, 0xaf4] };
    let registry = qlab_l2::fixture::shape_r_registry();
    let write = RegistryWrite { isk: [0xdead, 0xbeef, 0xf00d, 0xcafe], old_leaf: None, new_leaf: RegistryLeaf::cloaked(9), opening: registry_opening(&registry, 9).0 };
    let seed = SeedOutput { rkm: [0xb01, 0xb02, 0xb03, 0xb04], rseed: [0xc01, 0xc02, 0xc03, 0xc04] };
    build_shape_r(qlab_l2::LOG_HEIGHT_R, &input, &output, fee, &write, &seed)
}

#[cfg(test)]
mod lane_guard {
    //! Lab #758's resident guard: the census's **counts** on every consensus
    //! AIR, pinned — never cells, never readers (those stay private until
    //! reviewed). L1 on the five AIRs' house fixtures; L2 on claim. A change
    //! in any count fails here and must be re-classified in the report's
    //! "L1 (static) counts per AIR" before the pin moves.
    use super::*;

    /// L1 flags on one AIR's house fixture, as `detaudit --l1 --air <name>`.
    macro_rules! l1_flags {
        ($air:expr, $pvs:expr, $program:expr, $manifest:expr) => {{
            let air = $air;
            let trace = air.generate_trace::<Val>(0);
            let mut c = Census::for_l1(air, trace, &$pvs, $program);
            c.l1_with_stats(&$manifest).0.len()
        }};
    }

    /// The five AIRs' L1 counts (R19 at the audit's head; each flag
    /// classified in the report: S3's four are the output-row selectors,
    /// P3's 315 the compare rows' W lanes and LT flags, the remotely pinned
    /// `RG₀` and the selectors, R's one the `[mode = Regulated]` indicator).
    #[test]
    fn detaudit_lane_guard_l1_counts() {
        let narrow = narrow_fixture("house");
        let n_pvs: Vec<Val> = narrow.pvs.iter().map(|v| Val::from_u32(*v)).collect();
        let claim = claim_fixture("house");
        let s3 = qlab_l2::fixture::shape_s();
        let p3 = qlab_l2::fixture::shape_p();
        let r = qlab_l2::fixture::shape_r();
        let counts = [
            l1_flags!(&narrow.air, n_pvs, qlab_air::narrow::audit_program(&narrow.air), qlab_air::narrow::witness_manifest()),
            l1_flags!(&claim.air, qlab_l2::public_values(&claim.pvs), qlab_air::claim::audit_program(&claim.air), qlab_air::claim::witness_manifest()),
            l1_flags!(&s3.air, qlab_l2::public_values(&s3.pvs), qlab_air::l2::audit_program(&s3.air), qlab_air::l2::witness_manifest()),
            l1_flags!(&p3.air, qlab_l2::public_values(&p3.pvs), qlab_air::l2p::audit_program(&p3.air), qlab_air::l2p::witness_manifest()),
            l1_flags!(&r.air, qlab_l2::public_values(&r.pvs), qlab_air::l2r::audit_program(&r.air), qlab_air::l2r::witness_manifest()),
        ];
        assert_eq!(counts, [0, 0, 4, 315, 1], "L1 flags [narrow, claim, S3, P3, R] moved — re-classify before re-pinning");
    }

    /// Claim's full L2 census (no confirm): nothing undetermined reaches a
    /// public value, and nothing is flagged outside the warm-up allowance.
    #[test]
    fn detaudit_lane_guard_claim_l2() {
        let inst = claim_fixture("house");
        let pvs = qlab_l2::public_values(&inst.pvs);
        let program = qlab_air::claim::audit_program(&inst.air);
        let rpp = program.rows_per_perm;
        let trace = inst.air.generate_trace::<Val>(0);
        let height = trace.values.len() / <_ as BaseAir<Val>>::width(&inst.air);
        let mut census = Census::run(&inst.air, trace, &pvs, program, &qlab_air::claim::witness_manifest(), height, Some(qlab_air::claim::audit_pv_bits()));
        let rep = census.report(&[qlab_air::detaudit::warmup_allowance(rpp)]);
        assert_eq!((rep.flags().count(), rep.pvs_undetermined.len()), (0, 0), "claim's L2 census flagged something — review privately before any detail is published");
    }
}
