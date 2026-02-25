# Starfish Project Instructions

## Pre-commit / Pre-push Checklist

Before committing (and especially before pushing), run the following checks that mirror CI:

```bash
# Formatting (must use nightly)
cargo +nightly fmt --check

# Dependency sorting
cargo sort --check --workspace

# Linting (must match CI: --no-deps, no --all-targets)
cargo clippy --all-features --no-deps -- -D warnings
cargo clippy --all-features --tests --no-deps -- -D warnings

# Spelling/typos
typos

# Build and doc check
cargo check --all-features
cargo doc --no-deps --all-features
```

If any check fails, fix the issue before committing. Do not use `--no-verify` or skip hooks.
