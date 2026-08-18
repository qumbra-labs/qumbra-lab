//! `qumbra-pool` — CLI glue. Testable logic lives in the library.

fn main() {
    eprintln!(
        "qumbra-pool — T2 pool listener (lab #482 stage 1)\n\n\
         USAGE:\n  \
         qumbra-pool check --config FILE   validate config; bind nothing\n  \
         qumbra-pool run --config FILE     listen for stratum TCP\n"
    );
    std::process::exit(2);
}
