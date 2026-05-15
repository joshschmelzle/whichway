## Build discipline

After every meaningful change, run these and fix what they report. Do not
return work as complete until all pass on a clean run:

  cargo check --all-targets --locked
  cargo clippy --all-targets --locked -- -D warnings
  cargo fmt --check
  cargo test --locked

Rules a linter cannot enforce:

- Never delete, skip, `#[ignore]`, or weaken a failing test to make the
  suite green. Fix the code or fix the test, whichever is actually wrong.
- Never leave `todo!()` or `unimplemented!()` in delivered code.
- When `#[allow(lint_name)]` is genuinely needed, include
  `reason = "..."` explaining why the code is correct as written.
- If a borrow-checker or lifetime error has resisted two attempts, stop
  and reconsider the design. `.clone()`, `Arc<Mutex<_>>`, and
  `Box<dyn Any>` reached for to dodge an error are signals that the
  shape is wrong, not that the compiler is wrong.
- Before adding any dependency, verify the crate exists on crates.io
  and is actively maintained. Do not invent crate names.
- Run `cargo audit` before declaring work done if the dependency tree
  changed; resolve or document any advisories.

Lint configuration lives in `Cargo.toml` under `[lints.*]`. Do not
disable lints by adding `#[allow]` attributes scattered through code;
adjust the central config with a comment explaining why, or fix the
underlying issue.
