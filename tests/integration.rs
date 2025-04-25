use std::fs;
use std::process::Command;
use std::env;
use std::sync::Once;
use argon2::{Argon2, password_hash::{ PasswordHasher}};

type EntryRow = (i64, String, Option<String>, Option<String>, String, Option<String>, i64);

macro_rules! debug_println {
    ($($arg:tt)*) => {
        if std::env::var("JOURNALER_DEBUG").ok().as_deref() == Some("1") {
            println!($($arg)*);
        }
    };
}

static INIT: Once = Once::new();
static CLEANUP: Once = Once::new();

fn setup_db() {
    INIT.call_once(|| {
        let _ = fs::remove_file("test_journal.db");
        // Remove session file if it exists
        let session_path = std::env::current_dir().unwrap().join("journaler_session.json");
        let _ = fs::remove_file(&session_path);
        let conn = rusqlite::Connection::open("test_journal.db").expect("Failed to open test DB");
        let _ = conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )", []);
        // Use a fixed SaltString for deterministic test login
        let salt = argon2::password_hash::SaltString::from_b64("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let argon2 = Argon2::default();
        let password = "testpass";
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        let _ = conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, salt) VALUES (?1, ?2, ?3)",
            ["testuser", &hash, salt.as_str()],
        );
        // Print salt and hash for debugging
        debug_println!("TEST USER salt: {}", salt.as_str());
        debug_println!("TEST USER hash: {}", hash);
    });
}

fn cleanup_db() {
    CLEANUP.call_once(|| {
        let _ = fs::remove_file("test_journal.db");
        static mut ORIGINAL_JOURNAL_DB: Option<String> = None;
        unsafe {
            if let Some(ref val) = ORIGINAL_JOURNAL_DB {
                env::set_var("JOURNAL_DB", val);
            } else {
                env::remove_var("JOURNAL_DB");
            }
        }
    });
}

fn save_original_env() {
    static mut SAVED: bool = false;
    static mut ORIGINAL_JOURNAL_DB: Option<String> = None;
    unsafe {
        if !SAVED {
            ORIGINAL_JOURNAL_DB = env::var("JOURNAL_DB").ok();
            SAVED = true;
        }
    }
}

fn run_journaler(args: &[&str]) -> String {
    save_original_env();
    let mut all_args = vec!["--no-interactive", "--debug"];
    all_args.extend_from_slice(args);
    let db_path = std::fs::canonicalize("test_journal.db").unwrap();
    // Use test directory as config home for session file consistency
    let config_dir = std::env::current_dir().unwrap();
    let output = Command::new("target/debug/journaler")
        .args(&all_args)
        .env("JOURNAL_DB", db_path.to_str().unwrap())
        .env("JOURNALER_USERNAME", "testuser")
        .env("JOURNALER_PASSWORD", "testpass")
        .env("XDG_CONFIG_HOME", config_dir.to_str().unwrap())
        .output()
        .expect("Failed to run journaler");
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    combined
}

#[test]
fn test_add_and_list_entry() {
    setup_db();
    // Print all users in the DB before running commands
    let conn = rusqlite::Connection::open("test_journal.db").unwrap();
    let mut stmt = conn.prepare("SELECT id, username FROM users").unwrap();
    let users: Vec<(i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    debug_println!("USERS BEFORE: {:?}", users);

    let out = run_journaler(&["add", "Test entry 1", "--tags", "work", "--due", "2025-05-01", "--status", "In Progress"]);
    debug_println!("ADD OUTPUT: {}", out);
    // Print all journal entries after add
    let mut stmt = conn.prepare("SELECT id, content, due_date, status, created_at, updated_at, user_id FROM journal").unwrap();
    let entries: Vec<EntryRow> = stmt
        .query_map([], |row| Ok((
            row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?
        )))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    debug_println!("JOURNAL ENTRIES AFTER ADD: {:?}", entries);
    assert!(out.contains("Entry added"));
    let out = run_journaler(&["list"]);
    debug_println!("LIST OUTPUT: {}", out);
    assert!(out.contains("Test entry 1"));
    assert!(out.contains("work"));
    assert!(out.contains("In Progress"));

    // Print all users in the DB after running commands
    let mut stmt = conn.prepare("SELECT id, username FROM users").unwrap();
    let users: Vec<(i64, String)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    debug_println!("USERS AFTER: {:?}", users);
}

#[test]
fn test_update_entry_and_remove_tag() {
    setup_db();
    run_journaler(&["add", "Test entry 2", "--tags", "urgent", "--status", "Open"]);
    let out = run_journaler(&["update", "1", "--remove-tag", "urgent", "--status", "Done"]);
    assert!(out.contains("Entry updated"));
    let out = run_journaler(&["view", "1"]);
    assert!(!out.contains("urgent"));
    assert!(out.contains("Done"));
}

#[test]
fn test_search() {
    setup_db();
    run_journaler(&["add", "Project meeting notes", "--tags", "meeting", "--status", "Open"]);
    let out = run_journaler(&["search", "meeting"]);
    debug_println!("SEARCH OUTPUT: {}", out);
    assert!(out.contains("Project meeting notes"));
    assert!(out.contains("meeting"));
}

#[test]
fn test_tags_listing_and_counts() {
    setup_db();
    run_journaler(&["add", "Entry with tag1", "--tags", "tag1"]);
    run_journaler(&["add", "Entry with tag1 again", "--tags", "tag1"]);
    run_journaler(&["add", "Entry with tag2", "--tags", "tag2"]);
    let out = run_journaler(&["tags"]);
    debug_println!("TAGS OUTPUT: {}", out);
    assert!(out.contains("tag1 (2)"));
    assert!(out.contains("tag2 (1)"));
}

#[test]
fn test_export_csv() {
    setup_db();
    run_journaler(&["add", "Export test", "--tags", "exp", "--status", "Test"]);
    let out = run_journaler(&["export", "--format", "csv"]);
    assert!(out.contains(",exp,"));
    assert!(out.contains("Export test"));
    assert!(out.contains("Test"));
}

#[test]
fn test_export_md_and_txt() {
    setup_db();
    run_journaler(&["add", "Markdown test", "--tags", "md", "--status", "Test"]);
    let md = run_journaler(&["export", "--format", "md"]);
    assert!(md.contains("Markdown test"));
    assert!(md.contains("md"));
    let txt = run_journaler(&["export", "--format", "txt"]);
    assert!(txt.contains("Markdown test"));
    assert!(txt.contains("md"));
}

#[cfg(test)]
mod cleanup {
    // use super::*;
    #[test]
    fn cleanup_after_tests() {
        super::cleanup_db();
    }
}
