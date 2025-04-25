// main.rs - Main CLI logic for Journaler
// Handles user interaction, command parsing, session management, and output formatting.
// - Defines CLI commands (add, update, delete, list, tags, recycle bin, audit log, admin reset, etc.)
// - Manages user authentication/session, prompts, and guides
// - Calls db.rs for all persistent operations and encryption

#[macro_use]
mod macros;

mod db;
use clap::{Parser, Subcommand, ArgAction};
use strsim::normalized_levenshtein;
use std::io::{self, Write};
use csv;
use dialoguer::{Confirm, Input, Password};
use rusqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use dirs;

#[derive(Serialize, Deserialize)]
struct UserSession {
    user_id: i64,
    username: String,
    key: [u8; 32],
    last_active: u64, // unix timestamp (seconds)
}

/// Returns the path to the session JSON file in the user's config directory.
fn session_path() -> PathBuf {
    let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("journaler_session.json");
    // debug_println!("Session path: {}", path.display());
    path
}

/// Loads the current session from disk if it exists and is valid.
fn load_session() -> Option<UserSession> {
    let path = session_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(mut session) = serde_json::from_str::<UserSession>(&data) {
            let now = now_ts();
            if now - session.last_active <= session_timeout_secs() {
                session.last_active = now;
                let _ = fs::write(&path, serde_json::to_string(&session).unwrap());
                return Some(session);
            }
        }
    }
    None
}

/// Saves the current session to disk as JSON.
fn save_session(user: &db::AuthenticatedUser) {
    let session = UserSession {
        user_id: user.id,
        username: user.username.clone(),
        key: user.key,
        last_active: now_ts(),
    };
    let _ = fs::write(session_path(), serde_json::to_string(&session).unwrap());
}

/// Clears the session file from disk.
fn clear_session() {
    let _ = fs::remove_file(session_path());
}

/// Returns the current Unix timestamp in seconds.
fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// Returns the session timeout in seconds.
fn session_timeout_secs() -> u64 {
    std::env::var("JOURNALER_SESSION_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1800)
}

/// Prompts for login and creates a session if authentication succeeds.
fn require_auth() -> db::AuthenticatedUser {
    if let Some(session) = load_session() {
        debug_println!("Loaded session: user_id={}, username={}", session.user_id, session.username);
        return db::AuthenticatedUser { id: session.user_id, username: session.username, key: session.key };
    }
    let conn = Connection::open(db::db_path()).expect("Failed to open DB");
    // Check for non-interactive CLI authentication
    let username_env = std::env::var("JOURNALER_USERNAME").ok();
    let password_env = std::env::var("JOURNALER_PASSWORD").ok();
    if let (Some(username), Some(password)) = (username_env, password_env) {
        match db::login_user(&conn, &username, &password) {
            Ok(Some(user)) => {
                debug_println!("Authenticated user: id={}, username={}", user.id, user.username);
                save_session(&user);
                return user;
            },
            _ => {
                println!("Invalid username or password from env vars.");
                std::process::exit(1);
            }
        }
    }
    // Check if any users exist
    if !db::users_exist(&conn).expect("Failed to check users existence") {
        println!("No users found. Let's create a new account.");
        let username: String = Input::new().with_prompt("Choose a username").interact_text().unwrap();
        let password: String = Password::new().with_prompt("Choose a password").interact().unwrap();
        let user = db::register_user(&conn, &username, &password).expect("Failed to register user");
        debug_println!("Registered new user: id={}, username={}", user.id, user.username);
        save_session(&user);
        return user;
    }
    let username: String = Input::new().with_prompt("Username").interact_text().unwrap();
    let password: String = Password::new().with_prompt("Password").interact().unwrap();
    match db::login_user(&conn, &username, &password) {
        Ok(Some(user)) => {
            debug_println!("Authenticated user: id={}, username={}", user.id, user.username);
            save_session(&user);
            user
        },
        Ok(None) => {
            println!("Invalid username or password.");
            std::process::exit(1);
        },
        Err(e) => {
            println!("Failed to authenticate: {}", e);
            std::process::exit(1);
        }
    }
}

/// Formats a status string with color.
fn color_status(status: &str) -> String {
    match status.to_lowercase().as_str() {
        "in progress" => format!("\x1b[32m{}\x1b[0m", status), // green
        "done" => format!("\x1b[34m{}\x1b[0m", status),       // blue
        "late" => format!("\x1b[31m{}\x1b[0m", status),       // red
        _ => status.to_string(),
    }
}

/// Prompts the user to choose a similar tag if one exists.
fn prompt_for_similar_tag(new_tag: &str, existing_tags: &[String], no_interactive: bool) -> Option<String> {
    let matches: Vec<&String> = existing_tags.iter()
        .filter(|t|
            t.eq_ignore_ascii_case(new_tag)
            || t.to_lowercase().contains(&new_tag.to_lowercase())
            || new_tag.to_lowercase().contains(&t.to_lowercase())
            || normalized_levenshtein(&t.to_lowercase(), &new_tag.to_lowercase()) > 0.7
        )
        .collect();
    if matches.is_empty() {
        return None;
    }
    if no_interactive {
        // Always add as new tag in test mode
        return None;
    }
    println!("A similar tag already exists:");
    println!("  [0] Add '{}' as a new tag", new_tag);
    for (i, t) in matches.iter().enumerate() {
        println!("  [{}] {}", i + 1, t);
    }
    let prompt = format!("Enter the number of the tag to use for '{}': ", new_tag);
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            if let Ok(idx) = input.trim().parse::<usize>() {
                if idx == 0 {
                    return None;
                } else if idx <= matches.len() {
                    return Some(matches[idx - 1].clone());
                }
            }
        }
        println!("Invalid selection. Please enter a valid number.");
    }
}

/// Prints the CLI user guide.
fn print_help() {
    println!(r#"\
USAGE:
    journaler <COMMAND> [OPTIONS]

COMMANDS:
    add             Add a new journal entry (requires authentication)
    list            List your journal entries (requires authentication)
    update          Update an entry (requires authentication)
    view            View a specific entry (requires authentication)
    delete          Delete an entry (moves to recycle bin, requires authentication)
    tags            List your tags and usage counts (requires authentication)
    search          Search your entries (requires authentication)
    recycle-bin     List your recycle bin (requires authentication)
    recover         Recover an entry from the recycle bin (requires authentication)
    purge-recyclebin Purge entries older than 30 days from recycle bin (requires authentication)
    register-user   Register a new user
    clean-legacy    Remove all legacy/unowned data from the database
    change-password Change your password and re-encrypt your data
    logout          Log out and clear your session
    audit-log       View the audit log for the current user
    admin-reset     Admin: Reset a user's password (deletes all their data)

OPTIONS:
    --guide         Show this user guide
    --no-interactive  Do not prompt for interactive confirmations
    --session-timeout Set session timeout in seconds (default: 1800)
    --debug         Show internal debug output for troubleshooting

DEBUGGING:
    - Use the --debug flag to show detailed debug output for CLI commands.
    - For integration tests, set JOURNALER_DEBUG=1 to show debug logs from test helpers.

SECURITY:
    - All data is encrypted per user and only accessible after authentication.
    - Passwords are hashed and salted using Argon2.
    - Each user can only access their own entries, tags, and recycle bin.
    - Password changes re-encrypt all your data with your new password.
    - Use 'clean-legacy' to remove all data not owned by a user.
"#);
}

/// Entry point: parses CLI args, manages session, and dispatches commands.
fn main() {
    db::init().expect("Failed to initialize database");
    let cli = Cli::parse();
    if cli.guide {
        print_help();
        return;
    }
    let no_interactive = cli.no_interactive;
    let _session_timeout = std::env::var("JOURNALER_SESSION_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(cli.session_timeout);
    unsafe { DEBUG_ENABLED = cli.debug; }
    match cli.command {
        Some(Commands::RegisterUser) => {
            let conn = Connection::open(db::db_path()).expect("Failed to open DB");
            let username: String = Input::new().with_prompt("Username").interact_text().unwrap();
            let password: String = Password::new().with_prompt("Password").with_confirmation("Confirm password", "Passwords do not match").interact().unwrap();
            match db::register_user(&conn, &username, &password) {
                Ok(_) => println!("User '{}' registered successfully.", username),
                Err(e) => println!("Failed to register user: {}", e),
            }
            return;
        }
        Some(Commands::CleanLegacy) => {
            db::clean_legacy_data().expect("Failed to clean legacy data");
            println!("Legacy data cleaned: only per-user data remains.");
            return;
        }
        Some(Commands::ChangePassword) => {
            let user = require_auth();
            let old_password: String = Password::new().with_prompt("Current password").interact().unwrap();
            let new_password: String = Password::new().with_prompt("New password").with_confirmation("Confirm new password", "Passwords do not match").interact().unwrap();
            match db::change_password(&user, &old_password, &new_password) {
                Ok(_) => {
                    db::log_action(&user, "change_password", None).ok();
                    println!("Password changed and all your data re-encrypted.");
                },
                Err(_) => println!("Password change failed. Did you enter your current password correctly?"),
            }
            return;
        }
        Some(Commands::Logout) => {
            let user = require_auth();
            db::log_action(&user, "logout", None).ok();
            clear_session();
            println!("Logged out.");
            return;
        }
        Some(Commands::AdminReset { username, new_password }) => {
            if !Confirm::new().with_prompt(&format!("This will delete ALL data for user '{}'. Continue?", username)).default(false).interact().unwrap() {
                println!("Aborted.");
                return;
            }
            match db::admin_reset_user(&username, &new_password) {
                Ok(_) => println!("User '{}' reset. All previous data deleted.", username),
                Err(e) => println!("Admin reset failed: {}", e),
            }
            return;
        }
        _ => {}
    }
    let user = require_auth();
    match cli.command {
        Some(cmd) => match cmd {
            Commands::Add { content, tags, due, status } => {
                let mut tags_vec = Vec::new();
                let all_tags = db::list_tags(&user).expect("Failed to list tags");
                for tag in tags {
                    if let Some(existing) = prompt_for_similar_tag(&tag, &all_tags, no_interactive) {
                        tags_vec.push(existing);
                    } else {
                        tags_vec.push(tag);
                    }
                }
                let tags_vec = if tags_vec.is_empty() { None } else { Some(tags_vec) };
                db::add_entry(&user, &content, tags_vec, due, status).expect("Add failed");
                db::log_action(&user, "add_entry", Some(&content)).ok();
                println!("Entry added.");
            }
            Commands::Update { id, content, tags, remove_tag, due, status } => {
                let mut tags_vec = Vec::new();
                let all_tags = db::list_tags(&user).expect("Failed to list tags");
                for tag in tags {
                    if let Some(existing) = prompt_for_similar_tag(&tag, &all_tags, no_interactive) {
                        tags_vec.push(existing);
                    } else {
                        tags_vec.push(tag);
                    }
                }
                let tags_vec = if tags_vec.is_empty() { None } else { Some(tags_vec) };
                let remove_tags_vec = if remove_tag.is_empty() { None } else { Some(remove_tag.clone()) };
                db::update_entry(&user, id, content.clone(), tags_vec, remove_tags_vec, due, status).expect("Update failed");
                db::log_action(&user, "update_entry", Some(&format!("id={}, content={:?}", id, content))).ok();
                println!("Entry updated.");
            }
            Commands::View { id } => {
                if let Some(e) = db::get_entry(&user, id).expect("View failed") {
                    println!("{}: {} [tags: {}] [due: {:?}] [status: {}] [created: {}] [updated: {:?}]", e.id, e.content, e.tags.join(", "), e.due_date, e.status, e.created_at, e.updated_at);
                } else {
                    println!("Entry not found.");
                }
            }
            Commands::Tags => {
                let tags_with_counts = db::list_tags_with_counts(&user).expect("Tags failed");
                if tags_with_counts.is_empty() {
                    println!("No tags found.");
                } else {
                    println!("Available tags:");
                    for (tag, count) in tags_with_counts {
                        println!("- {} ({})", tag, count);
                    }
                }
            }
            Commands::Search { query } => {
                let entries = db::list_entries(&user, None, None).expect("List failed");
                let q = query.to_lowercase();
                let filtered: Vec<_> = entries.into_iter().filter(|e|
                    e.content.to_lowercase().contains(&q)
                    || e.status.to_lowercase().contains(&q)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&q))
                ).collect();
                if filtered.is_empty() {
                    println!("No entries found matching '{}'.", query);
                } else {
                    for e in filtered {
                        let tag_str = if !e.tags.is_empty() {
                            format!("[tags: {}] ", e.tags.join(", "))
                        } else { String::new() };
                        let due_str = e.due_date.as_ref().map(|d| format!("[due: {}] ", d)).unwrap_or_default();
                        let status_str = format!("[status: {}] ", e.status);
                        let created_str = format!("[created: {}]", e.created_at);
                        let updated_str = match e.updated_at {
                            Some(ref u) => format!("[updated: {}]", u),
                            None => String::from("[updated: -]"),
                        };
                        println!("{}: {} {}{}{}{} {}", e.id, e.content, tag_str, due_str, status_str, created_str, updated_str);
                    }
                }
            }
            Commands::Export { format, output } => {
                let entries = db::list_entries(&user, None, None).expect("Export failed");
                let fmt = format.to_lowercase();
                let data = match fmt.as_str() {
                    "csv" => {
                        let mut wtr = csv::Writer::from_writer(vec![]);
                        wtr.write_record(["id", "content", "tags", "due_date", "status", "created_at", "updated_at"]).unwrap();
                        for e in &entries {
                            wtr.write_record([
                                e.id.to_string(),
                                e.content.clone(),
                                e.tags.join(", "),
                                e.due_date.as_deref().unwrap_or("").to_string(),
                                e.status.clone(),
                                e.created_at.clone(),
                                e.updated_at.as_deref().unwrap_or("").to_string()
                            ]).unwrap();
                        }
                        String::from_utf8(wtr.into_inner().unwrap()).unwrap()
                    },
                    "md" | "markdown" => {
                        let mut s = String::new();
                        for e in &entries {
                            s.push_str(&format!("## {}\n\n- **Tags:** {}\n- **Due:** {}\n- **Status:** {}\n- **Created:** {}\n- **Updated:** {}\n\n{}\n\n---\n\n",
                                e.id,
                                if e.tags.is_empty() { "-".to_string() } else { e.tags.join(", ") },
                                e.due_date.as_deref().unwrap_or("-"),
                                e.status,
                                e.created_at,
                                e.updated_at.as_deref().unwrap_or("-"),
                                e.content
                            ));
                        }
                        s
                    },
                    "txt" | "text" => {
                        let mut s = String::new();
                        for e in &entries {
                            s.push_str(&format!("#{} | {} | [{}] | Due: {} | Status: {} | Created: {} | Updated: {}\n{}\n\n",
                                e.id,
                                e.content,
                                if e.tags.is_empty() { "".to_string() } else { e.tags.join(", ") },
                                e.due_date.as_deref().unwrap_or("-"),
                                e.status,
                                e.created_at,
                                e.updated_at.as_deref().unwrap_or("-"),
                                e.content
                            ));
                        }
                        s
                    },
                    _ => {
                        eprintln!("Unknown export format: {}. Use csv, md, or txt.", format);
                        return;
                    }
                };
                if let Some(path) = output {
                    std::fs::write(&path, data).expect("Failed to write export file");
                    println!("Exported to {}", path);
                } else {
                    println!("{}", data);
                }
            }
            Commands::Delete { id } => {
                let entry = db::get_entry(&user, id).expect("Failed to get entry");
                if entry.is_none() {
                    println!("Entry not found.");
                    return;
                }
                let entry = entry.unwrap();
                println!("You are about to delete entry #{}: {}", entry.id, entry.content);
                if cli.no_interactive || Confirm::new().with_prompt("Are you sure you want to delete this entry? It will be moved to the recycle bin for 30 days.").default(false).interact().unwrap() {
                    db::delete_entry(&user, id).expect("Delete failed");
                    db::log_action(&user, "delete_entry", Some(&format!("id={}", id))).ok();
                    println!("Entry {} moved to recycle bin.", id);
                } else {
                    println!("Aborted. Entry not deleted.");
                }
            }
            Commands::RecycleBin => {
                let entries = db::list_recycle_bin(&user).expect("Failed to list recycle bin");
                if entries.is_empty() {
                    println!("Recycle bin is empty.");
                } else {
                    println!("Entries in recycle bin (recoverable for up to 30 days):");
                    for e in entries {
                        println!("#{}: {} [tags: {}] [due: {}] [status: {}] [deleted: {}]", e.id, e.content, e.tags.join(", "), e.due_date.as_deref().unwrap_or("-"), e.status, e.deleted_at);
                    }
                }
            }
            Commands::Recover { id } => {
                let entries = db::list_recycle_bin(&user).expect("Failed to list recycle bin");
                if !entries.iter().any(|e| e.id == id) {
                    println!("Entry not found in recycle bin.");
                    return;
                }
                db::recover_from_recycle_bin(&user, id).expect("Recover failed");
                db::log_action(&user, "recover_entry", Some(&format!("id={}", id))).ok();
                println!("Entry {} recovered from recycle bin.", id);
            }
            Commands::PurgeRecycleBin => {
                db::purge_expired_recycle_bin(&user).expect("Purge failed");
                db::log_action(&user, "purge_recycle_bin", None).ok();
                println!("Expired entries purged from recycle bin.");
            }
            Commands::AuditLog => {
                let log = db::list_audit_log(&user).expect("Failed to list audit log");
                for entry in log {
                    println!("[{}] {}: {}", entry.timestamp, entry.action, entry.details.unwrap_or_default());
                }
            }
            Commands::List { tag, status } => {
                let entries = db::list_entries(&user, tag.clone(), status.clone()).expect("List failed");
                debug_println!("[DEBUG] List command: loaded {} entries from DB", entries.len());
                for (i, e) in entries.iter().enumerate() {
                    debug_println!("[DEBUG] Entry {}: id={}, content='{}', tags={:?}, due_date={:?}, status='{}', created_at={}, updated_at={:?}, user_id={}",
                        i, e.id, e.content, e.tags, e.due_date, e.status, e.created_at, e.updated_at, e.user_id);
                }
                if entries.is_empty() {
                    println!("No entries found.");
                } else {
                    for e in entries {
                        let tags = if e.tags.is_empty() { String::new() } else { format!("[tags: {}]", e.tags.join(", ")) };
                        let due = e.due_date.as_ref().map(|d| format!("[due: {}]", d)).unwrap_or_default();
                        println!("{}: {} {} {} [status: {}] [created: {}] [updated: {}]", e.id, e.content, tags, due, e.status, e.created_at, e.updated_at.as_deref().unwrap_or("-"));
                    }
                }
            }
            Commands::AdminReset { username, new_password } => {
                if !Confirm::new().with_prompt(&format!("This will delete ALL data for user '{}'. Continue?", username)).default(false).interact().unwrap() {
                    println!("Aborted.");
                    return;
                }
                match db::admin_reset_user(&username, &new_password) {
                    Ok(_) => println!("User '{}' reset. All previous data deleted.", username),
                    Err(e) => println!("Admin reset failed: {}", e),
                }
                return;
            }
            _ => {}
        },
        None => {
            print_help();
        }
    }
}

#[derive(Parser)]
#[command(name = "journaler")]
#[command(about = "A CLI journal app", long_about = None)]
pub struct Cli {
    /// Show the user guide
    #[arg(long, action = ArgAction::SetTrue)]
    guide: bool,
    /// Disable interactive prompts (for automated tests)
    #[arg(long, hide = true, action = ArgAction::SetTrue)]
    no_interactive: bool,
    #[arg(long, default_value_t = 1800)]
    session_timeout: u64,
    #[command(subcommand)]
    command: Option<Commands>,
    /// Enable debug output
    #[arg(long, action = ArgAction::SetTrue)]
    debug: bool,
}

static mut DEBUG_ENABLED: bool = false;

#[derive(Subcommand)]
enum Commands {
    /// Add a new journal entry
    Add {
        content: String,
        #[arg(short, long, action = ArgAction::Append)]
        tags: Vec<String>,
        #[arg(short, long)]
        due: Option<String>,
        #[arg(short, long)]
        status: Option<String>,
    },
    /// List all entries
    List {
        #[arg(short, long)]
        tag: Option<String>,
        #[arg(short, long)]
        status: Option<String>,
    },
    /// Update an entry by id
    Update {
        id: i64,
        #[arg(short, long)]
        content: Option<String>,
        #[arg(short, long, action = ArgAction::Append)]
        tags: Vec<String>,
        #[arg(long, action = ArgAction::Append)]
        remove_tag: Vec<String>,
        #[arg(short, long)]
        due: Option<String>,
        #[arg(short, long)]
        status: Option<String>,
    },
    /// View a specific entry
    View {
        id: i64,
    },
    /// List all tags
    Tags,
    /// Full text search entries
    Search {
        /// Search query
        query: String,
    },
    /// Export entries
    Export {
        /// Format: csv, md, or txt
        #[arg(long)]
        format: String,
        /// Output file (optional; prints to stdout if not specified)
        #[arg(long)]
        output: Option<String>,
    },
    /// Delete a journal entry
    Delete {
        /// Entry ID to delete
        id: i64,
    },
    /// List recycle bin entries
    RecycleBin,
    /// Recover an entry from the recycle bin
    Recover {
        id: i64,
    },
    /// Purge recycle bin (delete expired)
    PurgeRecycleBin,
    /// Register a new user
    RegisterUser,
    /// Clean up legacy data
    CleanLegacy,
    /// Change your password
    ChangePassword,
    /// Log out and clear your session
    Logout,
    /// View the audit log
    AuditLog,
    /// Admin: Reset a user's password (deletes all their data)
    AdminReset {
        /// Username to reset
        username: String,
        /// New password
        new_password: String,
    },
}
