# Contributing to Flodar

## Development setup

```bash
git clone https://github.com/RohitKochhar/flodar
cd flodar
cargo build
cargo test
```

## Testing

```bash
cargo test                     # all tests
cargo test -p flodar           # flodar crate only
cargo test -p flowgen          # flowgen crate only
```

End-to-end smoke test:

```bash
./target/release/flodar &
./target/release/flowgen --target 127.0.0.1:2055 --flows 5
# Should see 5 "flow" log lines in flodar output
```

## Code style

- `cargo fmt` before every commit
- `cargo clippy -- -D warnings` must pass — zero warnings
- No `unwrap()` or `expect()` in production code paths (`src/`, outside `#[cfg(test)]`)
- Every new detection rule needs at minimum three unit tests: fires above threshold, does not fire below threshold, partial match returns None

## Submitting a pull request

- One PR per change
- Tests required for new functionality
- Add a line to `CHANGELOG.md` under `[Unreleased]`
- CI must pass before review

## Where contributions are welcome

- New detection rules — see `docs/architecture.md` for the step-by-step guide
- Additional flow protocol support — sFlow is the next planned protocol
- Custom storage backends via the `FlowStore` / `AlertStore` traits
- Grafana dashboard improvements
- Documentation fixes and improvements
