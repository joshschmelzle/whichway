//! whichway library surface. The binary at `src/main.rs` uses these modules
//! directly via `mod`; we also re-export them through `lib.rs` so the parser
//! tests in `tests/` can pull them in without running any commands.

pub mod attribute;
pub mod collect;
pub mod exec;
pub mod model;
