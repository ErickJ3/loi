# loi

> A modern, structured syscall tracer for Linux

`loi` is a syscall tracer for Linux that fixes what `strace` got wrong: confusing flags, plain text output, and no native JSON. Built in Rust.

## Status

Pre-alpha. Under active development. Not ready for use yet.

## Goals

- Structured output: JSON-lines as a first-class citizen
- Ergonomic filters: `--syscall 'open*'`, `--fail`, `--path '*.conf'`
- Robust follow-fork
- Container/namespace aware
- Sane defaults, colored output

## Building

```bash
cargo build --release
```

## Development

```bash
cargo ci          # fmt check + clippy -D warnings + tests
cargo lint        # clippy only
cargo xtask test  # tests only
```

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
