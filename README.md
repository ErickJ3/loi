# loi

> A modern, structured syscall tracer for Linux

`loi` is a syscall tracer for Linux that fixes what `strace` got wrong: confusing flags, plain text output, and no native JSON. Built in Rust.

## Status

0.1.0 (alpha). Usable for `read` / `write` / `openat` tracing on Linux x86_64 and aarch64. Filter DSL is minimal (`--syscall` glob, `--fail`). Expect breaking changes before 1.0.

## Supported syscalls

`openat`, `read`, and `write` are decoded with named arguments and pretty / JSON output. Other syscalls pass through with a `syscall_<nr>` placeholder name and raw register values.

## Install

Pre-built binaries are published on the [Releases page](https://github.com/ErickJ3/loi/releases).

Pick the tarball matching your platform:

- `loi-v0.1.0-x86_64-unknown-linux-gnu.tar.gz` (most x86_64 Linux distros, glibc)
- `loi-v0.1.0-aarch64-unknown-linux-gnu.tar.gz` (Linux on ARM64, glibc)
- `loi-v0.1.0-x86_64-unknown-linux-musl.tar.gz` (static build, Alpine, scratch images)

```sh
TAG=v0.1.0
TARGET=x86_64-unknown-linux-gnu
curl -L "https://github.com/ErickJ3/loi/releases/download/${TAG}/loi-${TAG}-${TARGET}.tar.gz" | tar -xz
sudo mv "loi-${TAG}-${TARGET}/loi" /usr/local/bin/loi
```

Verify the download against `SHA256SUMS` from the same release page:

```sh
curl -LO "https://github.com/ErickJ3/loi/releases/download/v0.1.0/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
```

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

## Changelog

`CHANGELOG.md` is generated from git history by [git-cliff](https://git-cliff.org/) using `cliff.toml`.

```bash
cargo install git-cliff               # one-time
cargo xtask changelog-unreleased      # preview unreleased section
cargo xtask changelog                 # rewrite CHANGELOG.md
```

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.
