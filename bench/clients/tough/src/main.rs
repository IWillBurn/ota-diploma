//! tuf-conformance client CLI (third_party/tuf-conformance/CLIENT-CLI.md) on top of tough,
//! the TUF client library of AWS Bottlerocket. Library defaults everywhere (transport,
//! limits, expiration enforcement): the bench tests the library as an integrator gets it.
//!
//!   tough --metadata-dir D init ROOT
//!   tough --metadata-dir D --metadata-url U refresh
//!   tough --metadata-dir D --metadata-url U --target-name N [--target-name N2 ...]
//!         --target-base-url T --target-dir O download
//!
//! tough keeps root.json, timestamp.json, snapshot.json and targets.json (non-versioned
//! names, as the protocol requires) in its datastore, which is METADATA_DIR here.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use tough::{IntoVec, RepositoryLoader, TargetName};
use url::Url;

#[derive(Default)]
struct Args {
    metadata_dir: Option<PathBuf>,
    metadata_url: Option<String>,
    target_names: Vec<String>,
    target_base_url: Option<String>,
    target_dir: Option<PathBuf>,
    positional: Vec<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |name: &str| it.next().ok_or(format!("{name} needs a value"));
        match arg.as_str() {
            "--metadata-dir" => a.metadata_dir = Some(val("--metadata-dir")?.into()),
            "--metadata-url" => a.metadata_url = Some(val("--metadata-url")?),
            "--target-name" => a.target_names.push(val("--target-name")?),
            "--target-base-url" => a.target_base_url = Some(val("--target-base-url")?),
            "--target-dir" => a.target_dir = Some(val("--target-dir")?.into()),
            _ if arg.starts_with("--") => return Err(format!("unknown option {arg}")),
            _ => a.positional.push(arg),
        }
    }
    Ok(a)
}

/// tough joins relative paths to the base URL, so it must end with '/'.
fn dir_url(s: &str) -> Result<Url, String> {
    let s = if s.ends_with('/') { s.to_owned() } else { format!("{s}/") };
    Url::parse(&s).map_err(|e| format!("bad URL {s}: {e}"))
}

/// Same naming as the python-tuf client: the target path, percent-encoded into one file name.
fn local_name(target: &str) -> String {
    target
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn load(md_dir: &Path, md_url: &str, t_url: &str) -> Result<tough::Repository, String> {
    let root = std::fs::read(md_dir.join("root.json")).map_err(|e| format!("trusted root: {e}"))?;
    RepositoryLoader::new(&root, dir_url(md_url)?, dir_url(t_url)?)
        .datastore(md_dir)
        .load()
        .await
        .map_err(|e| format!("refresh failed: {e}"))
}

async fn run(a: Args) -> Result<(), String> {
    let md_dir = a.metadata_dir.clone().ok_or("--metadata-dir is required")?;
    let cmd = a.positional.first().map(String::as_str).ok_or("no command")?;
    match cmd {
        "init" => {
            let root = a.positional.get(1).ok_or("init needs TRUSTED_ROOT")?;
            std::fs::create_dir_all(&md_dir).map_err(|e| e.to_string())?;
            std::fs::copy(root, md_dir.join("root.json")).map_err(|e| e.to_string())?;
            Ok(())
        }
        "refresh" => {
            let url = a.metadata_url.as_deref().ok_or("--metadata-url is required")?;
            load(&md_dir, url, url).await.map(|_| ())
        }
        "download" => {
            let url = a.metadata_url.as_deref().ok_or("--metadata-url is required")?;
            let t_url = a.target_base_url.as_deref().ok_or("--target-base-url is required")?;
            let out = a.target_dir.clone().ok_or("--target-dir is required")?;
            let repo = load(&md_dir, url, t_url).await?;
            for name in &a.target_names {
                let tn = TargetName::new(name.as_str()).map_err(|e| format!("target name: {e}"))?;
                let stream = repo
                    .read_target(&tn)
                    .await
                    .map_err(|e| format!("{name}: {e}"))?
                    .ok_or(format!("{name}: no such target"))?;
                let data = stream.into_vec().await.map_err(|e| format!("{name}: {e}"))?;
                std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
                let dest = out.join(local_name(name));
                let tmp = out.join(format!(".{}.part", local_name(name)));
                std::fs::write(&tmp, &data).map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
        other => Err(format!("unknown command {other}")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match parse() {
        Err(e) => {
            eprintln!("usage error: {e}");
            ExitCode::from(1)
        }
        Ok(a) => match run(a).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
        },
    }
}
