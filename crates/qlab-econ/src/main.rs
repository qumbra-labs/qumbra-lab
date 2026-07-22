//! Regenerates `docs/econ-sweep.md` — the candidate trade-space table.
//!
//! `cargo run -p qlab-econ --release` writes the file and echoes a summary. The
//! report content is pure `qlab_econ::report::render()`; this just persists it.

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let md = qlab_econ::report::render();

    // Locate docs/ relative to this crate's manifest (crates/qlab-econ) so the
    // path is correct regardless of the invoking cwd.
    let mut docs = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    docs.push("../../docs");
    let docs = docs.canonicalize().unwrap_or(docs);
    let out = docs.join("econ-sweep.md");

    std::fs::write(&out, &md)?;
    eprintln!(
        "wrote {} ({} bytes, {} candidates)",
        out.display(),
        md.len(),
        qlab_econ::sweep::candidates().len()
    );
    Ok(())
}
