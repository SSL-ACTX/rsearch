use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use log::{error, info};

use crate::cli::Cli;

#[derive(Debug, Serialize, Clone)]
pub struct MatchRecord {
    pub source: String,
    pub kind: String,
    pub matched: String,
    pub line: usize,
    pub col: usize,
    pub entropy: Option<f64>,
    pub context: String,
    pub identifier: Option<String>,
}

#[derive(Clone)]
pub enum OutputMode {
    None,
    Single(Arc<Mutex<Vec<MatchRecord>>>),
    Ndjson(Arc<Mutex<File>>),
    PerFile(PathBuf),
}

pub fn build_output_mode(cli: &Cli) -> OutputMode {
    if let Some(path) = &cli.output {
        match cli.output_format.as_str() {
            "ndjson" => match OpenOptions::new().create(true).append(true).open(path) {
                Ok(f) => OutputMode::Ndjson(Arc::new(Mutex::new(f))),
                Err(e) => {
                    error!("Failed to open NDJSON output {}: {}", path, e);
                    OutputMode::None
                }
            },
            "per-file" => {
                let dir = PathBuf::from(path);
                if let Err(e) = fs::create_dir_all(&dir) {
                    error!("Failed to create output directory {}: {}", path, e);
                    OutputMode::None
                } else {
                    OutputMode::PerFile(dir)
                }
            }
            _ => OutputMode::Single(Arc::new(Mutex::new(Vec::new()))),
        }
    } else {
        OutputMode::None
    }
}

pub fn handle_output(
    output_mode: &OutputMode,
    cli: &Cli,
    out: &str,
    recs: Vec<MatchRecord>,
    source_path: Option<&Path>,
    source_label: &str,
) {
    match output_mode {
        OutputMode::Single(col) => {
            if !recs.is_empty() {
                if let Ok(mut guard) = col.lock() {
                    guard.extend(recs.into_iter());
                }
            }
        }
        OutputMode::Ndjson(file) => {
            if !recs.is_empty() {
                if let Ok(mut guard) = file.lock() {
                    for rec in recs {
                        if let Ok(line) = serde_json::to_string(&rec) {
                            let _ = guard.write_all(line.as_bytes());
                            let _ = guard.write_all(b"\n");
                        }
                    }
                }
            }
        }
        OutputMode::PerFile(dir) => {
            if !recs.is_empty() {
                let outpath = per_file_path(dir, source_path, source_label);
                if let Ok(mut f) = File::create(&outpath) {
                    if let Ok(j) = serde_json::to_string_pretty(&recs) {
                        let _ = f.write_all(j.as_bytes());
                    }
                }
            }
        }
        OutputMode::None => {
            if cli.json {
                if !recs.is_empty() {
                    match serde_json::to_string_pretty(&recs) {
                        Ok(j) => println!("{}", j),
                        Err(e) => error!("Failed to serialize JSON output: {}", e),
                    }
                }
            } else if !out.is_empty() {
                println!("{}", out);
            }
        }
    }
}

pub fn finalize_output(output_mode: &OutputMode, cli: &Cli) {
    if let Some(path) = &cli.output {
        match output_mode {
            OutputMode::Single(col) => match col.lock() {
                Ok(guard) => {
                    if guard.is_empty() {
                        info!("No matches found; not writing output file {}", path);
                    } else {
                        match serde_json::to_string_pretty(&*guard) {
                            Ok(j) => match fs::write(path, j) {
                                Ok(()) => info!("Wrote JSON output to {}", path),
                                Err(e) => error!("Failed to write JSON to {}: {}", path, e),
                            },
                            Err(e) => error!("Failed to serialize JSON output: {}", e),
                        }
                    }
                }
                Err(e) => error!("Failed to acquire lock to write output file: {}", e),
            },
            OutputMode::Ndjson(_) => {
                info!("NDJSON output written incrementally to {}", path);
            }
            OutputMode::PerFile(_) => {
                info!("Per-file JSON output written to directory {}", path);
            }
            OutputMode::None => {}
        }
    }
}

fn per_file_path(dir: &Path, source_path: Option<&Path>, source_label: &str) -> PathBuf {
    let mut outpath = dir.to_path_buf();
    if let Some(path) = source_path {
        if let Some(name) = path.file_name() {
            outpath.push(name);
            outpath.set_extension("json");
            return outpath;
        }
    }

    if let Some(name) = Path::new(source_label).file_name() {
        outpath.push(name);
        outpath.set_extension("json");
    } else {
        outpath.push("output.json");
    }
    outpath
}
