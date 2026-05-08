use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use xshell::{Shell, cmd};

#[derive(Parser)]
#[command(name = "xtask", about = "Project automation tasks")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run full CI suite locally (fmt + clippy + test + doc test)
    Ci,
    /// Run formatter check (or fix)
    Fmt {
        #[arg(long)]
        fix: bool,
    },
    /// Run clippy with project lints
    Lint,
    /// Run all tests (unit + integration)
    Test,
    /// Run documentation tests
    DocTest,
    /// Generate code coverage report (requires cargo-llvm-cov)
    Coverage,
    /// Build release binary with optimizations
    Dist,
    /// Update insta snapshots (requires cargo-insta)
    Snapshots,
}

fn main() -> Result<()> {
    let sh = Shell::new()?;
    match Cli::parse().cmd {
        Cmd::Ci => {
            cmd!(sh, "cargo fmt --all -- --check")
                .run()
                .context("formatter check failed")?;
            cmd!(
                sh,
                "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"
            )
            .run()
            .context("clippy failed")?;
            cmd!(sh, "cargo test --workspace --all-features")
                .run()
                .context("tests failed")?;
            cmd!(sh, "cargo test --workspace --all-features --doc")
                .run()
                .context("doc tests failed")?;
        }
        Cmd::Fmt { fix } => {
            if fix {
                cmd!(sh, "cargo fmt --all").run()?;
            } else {
                cmd!(sh, "cargo fmt --all -- --check").run()?;
            }
        }
        Cmd::Lint => {
            cmd!(
                sh,
                "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings"
            )
            .run()
            .context("clippy failed")?;
        }
        Cmd::Test => {
            cmd!(sh, "cargo test --workspace --all-features")
                .run()
                .context("tests failed")?;
        }
        Cmd::DocTest => {
            cmd!(sh, "cargo test --workspace --all-features --doc")
                .run()
                .context("doc tests failed")?;
        }
        Cmd::Coverage => {
            cmd!(sh, "cargo llvm-cov --workspace --html")
                .run()
                .context("coverage failed; install with: cargo install cargo-llvm-cov")?;
        }
        Cmd::Dist => {
            cmd!(sh, "cargo build --release --bin loi")
                .run()
                .context("release build failed")?;
        }
        Cmd::Snapshots => {
            cmd!(sh, "cargo insta test --review")
                .run()
                .context("snapshots failed; install with: cargo install cargo-insta")?;
        }
    }
    Ok(())
}
