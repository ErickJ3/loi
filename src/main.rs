use std::io::{self, BufWriter, IsTerminal, StdoutLock, Write as IoWrite};

use anyhow::{Context, Result};
use clap::Parser;
use loi_core::{SyscallEvent, Tracer};
use loi_filter::Filter;
use loi_output::{PrettyConfig, json, pretty};
use loi_syscalls::{DecodeCtx, DecodedArg, DecodedCall, Registry};

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

    /// Filter to syscalls touching a path matching this glob (comma-separated,
    /// e.g. "/etc/*,/tmp/*"). Syscalls with no path argument are dropped.
    #[arg(long)]
    path: Option<String>,

    /// Follow forked/cloned children
    #[arg(short = 'f', long)]
    follow_forks: bool,
}

#[derive(clap::ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum OutputFormat {
    Pretty,
    Json,
    Raw,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    tracing::debug!(?cli, "starting loi");

    if cli.output == OutputFormat::Raw {
        anyhow::bail!("--output raw is not implemented in 0.1; use pretty or json");
    }

    let filter = Filter::parse(cli.syscall.as_deref(), cli.fail, cli.path.as_deref())
        .context("invalid filter pattern")?;

    let registry = Registry::with_default_decoders();

    let tracer = Tracer::spawn(&cli.command).context("spawn failed")?;
    let tracer = tracer.with_follow_forks(cli.follow_forks);

    let stdout = io::stdout();
    let cfg = PrettyConfig::new(cli.output == OutputFormat::Pretty && stdout.is_terminal());

    let mut state = SinkState {
        out: BufWriter::new(stdout.lock()),
        format: cli.output,
        cfg,
        registry: &registry,
        filter: &filter,
        first_err: None,
        closed: false,
    };

    tracer.run(|ev| state.handle(ev)).context("trace failed")?;

    state.finish().context("write failed")
}

struct SinkState<'a> {
    out: BufWriter<StdoutLock<'a>>,
    format: OutputFormat,
    cfg: PrettyConfig,
    registry: &'a Registry,
    filter: &'a Filter,
    first_err: Option<io::Error>,
    closed: bool,
}

impl SinkState<'_> {
    fn handle(&mut self, ev: &SyscallEvent) {
        if self.closed || self.first_err.is_some() {
            return;
        }
        if !self.filter.matches_event(ev) {
            return;
        }
        let decoded = self.decode(ev);
        if self.filter.needs_decode() && !self.filter.matches_decoded(&decoded) {
            return;
        }
        let res = match self.format {
            OutputFormat::Pretty => pretty::write_event(&mut self.out, ev, &decoded, &self.cfg),
            OutputFormat::Json => json::write_event(&mut self.out, ev, &decoded),
            OutputFormat::Raw => unreachable!("--output raw bails before SinkState is built"),
        };
        if let Err(e) = res {
            self.record(e);
        }
    }

    fn decode(&self, ev: &SyscallEvent) -> DecodedCall {
        let ctx = DecodeCtx {
            pid: ev.pid,
            args: ev.args,
            ret: ev.ret,
        };
        if let Some(d) = self.registry.decoder(ev.syscall_nr) {
            match d.decode(&ctx) {
                Ok(decoded) => return decoded,
                Err(e) => tracing::trace!(nr = ev.syscall_nr, error = %e, "decode failed"),
            }
        }
        fallback_decoded(ev)
    }

    fn record(&mut self, e: io::Error) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            self.closed = true;
        } else if self.first_err.is_none() {
            self.first_err = Some(e);
        }
    }

    fn finish(mut self) -> io::Result<()> {
        if let Err(e) = self.out.flush() {
            self.record(e);
        }
        match self.first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

fn fallback_decoded(ev: &SyscallEvent) -> DecodedCall {
    DecodedCall {
        args: vec![
            ("arg0", DecodedArg::Uint(ev.args[0])),
            ("arg1", DecodedArg::Uint(ev.args[1])),
            ("arg2", DecodedArg::Uint(ev.args[2])),
            ("arg3", DecodedArg::Uint(ev.args[3])),
            ("arg4", DecodedArg::Uint(ev.args[4])),
            ("arg5", DecodedArg::Uint(ev.args[5])),
        ],
        ret: ev.ret,
    }
}
