//! The person at the computer decides. Every session starts with a prompt to
//! allow viewing, and control requires a second, separate yes.
//!
//! This POC asks on the terminal. A shipped agent would show a native dialog
//! and a persistent "CyberDoc is viewing your screen" banner with an end
//! button — the consent surface matters more than anything else here, because
//! this is exactly the capability tech-support scammers abuse.

use std::io::{Write, stdin, stdout};

/// Asks a yes/no question on the terminal. Defaults to **no** on empty input
/// or any read error: consent is never assumed.
pub fn ask(question: &str) -> bool {
    print!("\n>>> {question} [y/N]: ");
    let _ = stdout().flush();
    let mut line = String::new();
    match stdin().read_line(&mut line) {
        Ok(_) => matches!(line.trim(), "y" | "Y" | "yes" | "YES"),
        Err(_) => false,
    }
}
