use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "loi",
    version,
    about = "A modern, structured syscall tracer for Linux",
    long_about = None,
)]
struct Cli {
    /// Command to trace
    #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
    command: Vec<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
    output: OutputFormat,

    /// Filter syscalls (glob pattern, e.g. "open*,read,write")
    #[arg(short, long)]
    syscall: Option<String>,

    /// Only show syscalls that returned an error
    #[arg(long)]
    fail: bool,

    /// Follow forked/cloned children
    #[arg(short = 'f', long)]
    follow_forks: bool,
}

#[derive(clap::ValueEnum, Copy, Clone, Debug)]
enum OutputFormat {
    Pretty,
    Json,
    Raw,
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "main returns Result so future tracer code can use ?"
)]
fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    tracing::debug!(?cli, "starting loi");

    println!("loi: would trace {:?}", cli.command);

    Ok(())
}
