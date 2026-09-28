//! The session audit log: one JSON line per event, SHA-256 hash-chained, so
//! removing, editing or reordering any line is detectable with `GET /api/audit`.
//!
//! Each link's hash covers its sequence number, the previous link's hash, its
//! timestamp and the record bytes; every field is length-prefixed or
//! fixed-width so no two different links hash the same bytes. Self-contained —
//! no dependency on any other CyberDoc platform.
//!
//! TODO(production): anchor the head (sign it, write it to object-locked
//! storage) so truncation of the tail is detectable too; today the chain proves
//! internal consistency only.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation: these bytes are a CyberDoc Assist audit link and nothing else.
const DOMAIN: &[u8] = b"cyberdoc.assist.audit.link.v1\0";

type Hash = [u8; 32];

/// What comes before the first link.
const GENESIS: Hash = [0u8; 32];

/// Where the chain stood: the latest link's number and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: Hash,
}

/// Computes a link's hash from its fields and the previous hash.
fn link_hash(seq: u64, received_at: u64, record: &str, prev_hash: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(seq.to_be_bytes());
    h.update(received_at.to_be_bytes());
    h.update((record.len() as u64).to_be_bytes());
    h.update(record.as_bytes());
    h.update(prev_hash);
    h.finalize().into()
}

pub fn hex(bytes: &Hash) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex(text: &str) -> Option<Hash> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// One record on disk: the record plus the chain fields, hashes hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub seq: u64,
    pub received_at: u64,
    pub record: String,
    pub prev_hash: String,
    pub hash: String,
}

/// Verifies a whole chain: contiguous sequence from 1, each `prev_hash` links
/// to the one before, and each `hash` recomputes. Returns the head.
fn verify(rows: &[Row]) -> Result<Head> {
    let mut head = Head {
        seq: 0,
        hash: GENESIS,
    };
    for row in rows {
        if row.seq != head.seq + 1 {
            return Err(anyhow!(
                "gap in chain: expected seq {}, found {}",
                head.seq + 1,
                row.seq
            ));
        }
        let prev =
            parse_hex(&row.prev_hash).ok_or_else(|| anyhow!("bad prev_hash at seq {}", row.seq))?;
        if prev != head.hash {
            return Err(anyhow!("broken link at seq {}", row.seq));
        }
        let hash = parse_hex(&row.hash).ok_or_else(|| anyhow!("bad hash at seq {}", row.seq))?;
        if link_hash(row.seq, row.received_at, &row.record, &prev) != hash {
            return Err(anyhow!(
                "hash mismatch at seq {} (record altered?)",
                row.seq
            ));
        }
        head = Head { seq: row.seq, hash };
    }
    Ok(head)
}

pub struct AuditLog {
    path: PathBuf,
    file: File,
    head: Head,
}

impl AuditLog {
    /// Opens (or creates) the log, refusing to continue a chain that does not
    /// verify — appending to a broken chain would launder it.
    pub fn open(path: &Path) -> Result<Self> {
        let head = if path.exists() {
            verify(&read_rows(path)?)
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
        })
    }

    pub fn append(&mut self, now: u64, record: &serde_json::Value) -> Result<()> {
        let record = record.to_string();
        let seq = self.head.seq + 1;
        let hash = link_hash(seq, now, &record, &self.head.hash);
        let row = Row {
            seq,
            received_at: now,
            record,
            prev_hash: hex(&self.head.hash),
            hash: hex(&hash),
        };
        let mut line = serde_json::to_string(&row)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.head = Head { seq, hash };
        Ok(())
    }

    /// Every row, and whether the chain they form verifies (with the head).
    pub fn read(&self) -> Result<(Vec<Row>, std::result::Result<Head, String>)> {
        let rows = read_rows(&self.path)?;
        let verdict = verify(&rows).map_err(|e| e.to_string());
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
        let mut log = AuditLog::open(&path).unwrap();
        log.append(10, &serde_json::json!({"event": "a"})).unwrap();
        log.append(11, &serde_json::json!({"event": "b"})).unwrap();
        drop(log);

        let mut log = AuditLog::open(&path).unwrap();
        log.append(12, &serde_json::json!({"event": "c"})).unwrap();
        let (rows, verdict) = log.read().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(verdict.unwrap().seq, 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detects_an_edited_record() {
        let path = temp_path("tamper");
        let mut log = AuditLog::open(&path).unwrap();
        log.append(10, &serde_json::json!({"event": "control_granted"}))
            .unwrap();
        log.append(11, &serde_json::json!({"event": "session_ended"}))
            .unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("control_granted", "control_denied")).unwrap();
        assert!(AuditLog::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
