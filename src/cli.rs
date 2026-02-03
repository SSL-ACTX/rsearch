use clap::Parser;

#[derive(Parser)]
#[command(author = "Seuriin", version, about = "A high-performance, entropy-based secret scanner.", long_about = None)]
pub struct Cli {
    /// Target files, directories, or URLs
    #[arg(short, long)]
    pub target: Vec<String>,

    /// Keywords to find (supports multiple: -k token -k secret)
    #[arg(short, long)]
    pub keyword: Vec<String>,

    /// Enable Entropy Scanning (finds hidden keys/secrets automatically)
    #[arg(short, long)]
    pub entropy: bool,

    /// Minimum entropy threshold (0.0 - 8.0). Default 4.5 is good for base64 keys.
    #[arg(long, default_value_t = 4.5)]
    pub threshold: f64,

    /// Context window size
    #[arg(short, long, default_value_t = 80)]
    pub context: usize,

    /// Number of threads to use (0 = auto-detect logical cores)
    #[arg(short = 'j', long, default_value_t = 0)]
    pub threads: usize,

    /// Emit machine-readable JSON output
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to a file
    #[arg(long)]
    pub output: Option<String>,

    /// Disable colorized output
    #[arg(long = "no-color")]
    pub no_color: bool,

    /// Output format: single | ndjson | per-file
    #[arg(long, default_value_t = String::from("single"))]
    pub output_format: String,

    /// Exclude glob patterns (repeatable), e.g. --exclude "target/**"
    #[arg(short = 'x', long)]
    pub exclude: Vec<String>,

    /// Emit tag records (comma-separated), e.g. --emit-tags "url"
    #[arg(long)]
    pub emit_tags: Option<String>,

    /// Enable deep scan story mode (extra context, counts, and call-site analysis)
    #[arg(long)]
    pub deep_scan: bool,

    /// Enable flow-scan heuristics (control-flow context without AST)
    #[arg(long)]
    pub flow_scan: bool,

    /// Emit request trace context for secrets and run standalone HTTP request tracing
    #[arg(long)]
    pub request_trace: bool,

    /// Load suppression rules from a file (one rule per line)
    #[arg(long)]
    pub suppress: Option<String>,

    /// Write suppression hints to a file (appends)
    #[arg(long)]
    pub suppress_out: Option<String>,

    /// Scan only added lines in git diff
    #[arg(long)]
    pub diff: bool,

    /// Git diff base (e.g., HEAD, main, origin/main)
    #[arg(long, default_value_t = String::from("HEAD"))]
    pub diff_base: String,
}
