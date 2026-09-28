//! The session audit log: one JSON line per event, hash-chained with
//! `sigilant-audit`, so removing, editing or reordering any line is detectable
//! with `GET /api/audit` (or Sigilant's own verifier).
//!
//! TODO(production): anchor the head (sign it, write it to object-locked
//! storage) as Sigilant's sync service does; until then the chain proves
//! internal consistency, not that the tail was never truncated.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sigilant_audit::chain::{hex, parse_hex};
use sigilant_audit::{Broken, GENESIS, Head, Link, Unhashed, verify};
use sigilant_token::Timestamp;

/// Records from one log file share a spool; `spool_seq` equals `seq`.
const SPOOL_ID: &str = "assist-audit-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub seq: u64,
    pub broker_id: String,
    pub spool_id: String,
    pub spool_seq: u64,
    pub received_at: u64,
    pub record: String,
    pub prev_hash: String,
    pub hash: String,
}

impl Row {
    fn from_link(link: &Link) -> Self {
        Self {
            seq: link.seq,
            broker_id: link.gateway_id.clone(),
            spool_id: link.spool_id.clone(),
            spool_seq: link.spool_seq,
            received_at: link.received_at.unix_secs(),
            record: link.record.clone(),
            prev_hash: hex(&link.prev_hash),
            hash: hex(&link.hash),
        }
    }

    fn to_link(&self) -> Result<Link> {
        Ok(Link {
            seq: self.seq,
            gateway_id: self.broker_id.clone(),
            spool_id: self.spool_id.clone(),
            spool_seq: self.spool_seq,
            received_at: Timestamp::from_unix_secs(self.received_at),
            record: self.record.clone(),
            prev_hash: parse_hex(&self.prev_hash)
                .ok_or_else(|| anyhow!("bad prev_hash at {}", self.seq))?,
            hash: parse_hex(&self.hash).ok_or_else(|| anyhow!("bad hash at {}", self.seq))?,
        })
    }
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    head: Head,
    broker_id: String,
}

impl AuditLog {
    /// Opens (or creates) the log and refuses to continue a chain that does
    /// not verify: appending to a broken chain would launder it.
    pub fn open(path: &Path, broker_id: &str) -> Result<Self> {
        let head = if path.exists() {
            let rows = read_rows(path)?;
            let links = rows.iter().map(Row::to_link).collect::<Result<Vec<_>>>()?;
            verify(&links, vec![])
                .map_err(|e| anyhow!("audit log {} is broken: {e}", path.display()))?
        } else {
            Head {
                seq: 0,
                hash: GENESIS,
            }
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        Ok(Self {
            path: path.to_owned(),
            file,
            head,
            broker_id: broker_id.to_owned(),
        })
    }

    pub fn append(&mut self, now: u64, record: &serde_json::Value) -> Result<()> {
        let record = record.to_string();
        let seq = self.head.seq + 1;
        let link = Unhashed {
            seq,
            gateway_id: &self.broker_id,
            spool_id: SPOOL_ID,
            spool_seq: seq,
            received_at: Timestamp::from_unix_secs(now),
            record: &record,
            prev_hash: &self.head.hash,
        }
        .link();
        let mut line = serde_json::to_string(&Row::from_link(&link))?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.head = Head {
            seq,
            hash: link.hash,
        };
        Ok(())
    }

    /// Every row, and whether the chain they form verifies.
    pub fn read(&self) -> Result<(Vec<Row>, std::result::Result<Head, Broken>)> {
        let rows = read_rows(&self.path)?;
        let links = rows.iter().map(Row::to_link).collect::<Result<Vec<_>>>()?;
        let verdict = verify(&links, vec![]);
        Ok((rows, verdict))
    }
}

fn read_rows(path: &Path) -> Result<Vec<Row>> {
    let file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .filter(|l| l.as_ref().map(|l| !l.trim().is_empty()).unwrap_or(true))
        .enumerate()
        .map(|(i, line)| {
            let line = line?;
            serde_json::from_str(&line)
                .with_context(|| format!("line {} of {}", i + 1, path.display()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("assist-audit-{name}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn appends_reopens_and_verifies() {
        let path = temp_path("ok");
        let mut log = AuditLog::open(&path, "b1").unwrap();
        log.append(10, &serde_json::json!({"event": "a"})).unwrap();
        log.append(11, &serde_json::json!({"event": "b"})).unwrap();
        drop(log);

        let mut log = AuditLog::open(&path, "b1").unwrap();
        log.append(12, &serde_json::json!({"event": "c"})).unwrap();
        let (rows, verdict) = log.read().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(verdict.unwrap().seq, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_an_edited_record() {
        let path = temp_path("tamper");
        let mut log = AuditLog::open(&path, "b1").unwrap();
        log.append(10, &serde_json::json!({"event": "control_granted"}))
            .unwrap();
        log.append(11, &serde_json::json!({"event": "session_ended"}))
            .unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("control_granted", "control_denied")).unwrap();
        assert!(AuditLog::open(&path, "b1").is_err());
        let _ = std::fs::remove_file(&path);
    }
}
