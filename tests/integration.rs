use std::fs;
use std::process::Command;
use std::env;
use std::sync::Once;
use std::path::Path;

static INIT: Once = Once::new();
static CLEANUP: Once = Once::new();

fn setup_db() {
    INIT.call_once(|| {
        let _ = fs::remove_file("test_journal.db");
    });
}

fn cleanup_db() {
    CLEANUP.call_once(|| {
        let _ = fs::remove_file("test_journal.db");
        static mut ORIGINAL_JOURNAL_DB: Option<String> = None;
        unsafe {
            if let Some(val) = &ORIGINAL_JOURNAL_DB {
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
    let mut all_args = vec!["--no-interactive"];
    all_args.extend_from_slice(args);
    let output = Command::new("target/debug/journaler")
        .args(&all_args)
        .env("JOURNAL_DB", "test_journal.db")
        .output()
        .expect("Failed to run journaler");
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_add_and_list_entry() {
    setup_db();
    let out = run_journaler(&["add", "Test entry 1", "--tags", "work", "--due", "2025-05-01", "--status", "In Progress"]);
    assert!(out.contains("Entry added"));
    let out = run_journaler(&["list"]);
    assert!(out.contains("Test entry 1"));
    assert!(out.contains("work"));
    assert!(out.contains("In Progress"));
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
    use super::*;
    #[test]
    fn cleanup_after_tests() {
        super::cleanup_db();
    }
}
