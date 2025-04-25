// MIT License
// Copyright (c) 2025 balain
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// db.rs - Database and encryption logic for Journaler CLI app
// Handles all persistent storage, encryption, and user/session management.
// - Defines data models (Entry, AuthenticatedUser, AuditLog, etc.)
// - Provides functions for CRUD operations, authentication, tag management, recycle bin, audit logging, encryption, and admin reset.

use rusqlite::{params, Connection, Result, ToSql};
use chrono::Local;
use std::env;
use argon2::{Argon2, password_hash::{SaltString, PasswordHash, PasswordHasher as _, PasswordVerifier as _}};
use rand::{RngCore, rngs::OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::{Aead};
use base64::{engine::general_purpose, Engine as _};
#[allow(unused_imports)]
use crate::DEBUG_ENABLED;

/// Entry struct represents a journal entry in the database.
#[allow(dead_code)]
pub struct Entry {
    /// Unique entry ID.
    pub id: i64,
    /// Entry content.
    pub content: String,
    /// List of tags associated with the entry.
    pub tags: Vec<String>,
    /// Due date for the entry (optional).
    pub due_date: Option<String>,
    /// Status of the entry (e.g., "todo", "done").
    pub status: String,
    /// Timestamp when the entry was created.
    pub created_at: String,
    /// Timestamp when the entry was last updated (optional).
    pub updated_at: Option<String>,
    /// ID of the user who owns the entry.
    pub user_id: i64,
}

/// `SearchResult` struct for search query results.
#[allow(dead_code)]
pub struct SearchResult {
    /// Unique entry ID.
    pub id: i64,
    /// Entry content.
    pub content: String,
    /// List of tags associated with the entry.
    pub tags: Vec<String>,
    /// Due date for the entry (optional).
    pub due_date: Option<String>,
    /// Status of the entry (e.g., "todo", "done").
    pub status: String,
    /// Timestamp when the entry was created.
    pub created_at: String,
    /// Timestamp when the entry was last updated (optional).
    pub updated_at: Option<String>,
}

/// `AuthenticatedUser` contains user id, username, and encryption key for session.
#[allow(dead_code)]
pub struct AuthenticatedUser {
    /// Unique user ID.
    pub id: i64,
    /// Username chosen by the user.
    pub username: String,
    /// AES-256 encryption key for the user's session.
    pub key: [u8; 32],
}

/// `AuditLog` struct represents an audit log entry (action, details, timestamp).
#[allow(dead_code)]
pub struct AuditLog {
    /// Unique audit log entry ID.
    pub id: i64,
    /// ID of the user who performed the action.
    pub user_id: i64,
    /// Action performed (e.g., "added entry", "updated entry").
    pub action: String,
    /// Additional details about the action (optional).
    pub details: Option<String>,
    /// Timestamp when the action was performed.
    pub timestamp: String,
}

/// `RecycleBinEntry` struct represents an entry in the recycle bin.
#[allow(dead_code)]
pub struct RecycleBinEntry {
    /// Unique entry ID.
    pub id: i64,
    /// Entry content.
    pub content: String,
    /// List of tags associated with the entry.
    pub tags: Vec<String>,
    /// Due date for the entry (optional).
    pub due_date: Option<String>,
    /// Status of the entry (e.g., "todo", "done").
    pub status: String,
    /// Timestamp when the entry was created.
    pub created_at: String,
    /// Timestamp when the entry was last updated (optional).
    pub updated_at: Option<String>,
    /// Timestamp when the entry was deleted.
    pub deleted_at: String,
    /// ID of the user who owns the entry.
    pub user_id: i64,
}

/// Returns the path to the `SQLite` DB file (from env or default).
pub fn db_path() -> String {
    env::var("JOURNAL_DB").unwrap_or_else(|_| "journal.db".to_string())
}

/// Initializes all DB tables if missing (users, journal, tags, recycle bin, audit log).
pub fn init() -> Result<()> {
    let conn = Connection::open(db_path())?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS journal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            due_date TEXT,
            status TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            user_id INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS entry_tags (
            entry_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(entry_id) REFERENCES journal(id) ON DELETE CASCADE,
            FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY(entry_id, tag_id, user_id)
        )",
        [],
    )?;
    create_users_table(&conn)?;
    migrate_recycle_bin(&conn)?;
    migrate_all(&conn);
    init_audit_log(&conn)?;
    Ok(())
}

/// Creates the users table if it does not exist.
pub fn create_users_table(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Registers a new user with the given username and password.
pub fn register_user(conn: &Connection, username: &str, password: &str) -> Result<AuthenticatedUser> {
    init()?; // Ensure all tables exist
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
    let salt_b64 = salt.as_str();
    conn.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?1, ?2, ?3)",
        params![username, hash, salt_b64],
    )?;
    let id = conn.last_insert_rowid();
    let key = derive_key(password, salt_b64);
    Ok(AuthenticatedUser { id, username: username.to_string(), key })
}

/// Logs in a user with the given username and password.
pub fn login_user(conn: &Connection, username: &str, password: &str) -> Result<Option<AuthenticatedUser>> {
    init()?; // Ensure all tables exist
    let mut stmt = conn.prepare("SELECT id, password_hash, salt FROM users WHERE username = ?1")?;
    let mut rows = stmt.query(params![username])?;
    if let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let hash: String = row.get(1)?;
        let salt_b64: String = row.get(2)?;
        let parsed_hash = PasswordHash::new(&hash).unwrap();
        if Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok() {
            let key = derive_key(password, &salt_b64);
            return Ok(Some(AuthenticatedUser { id, username: username.to_string(), key }));
        }
    }
    Ok(None)
}

/// Derives the encryption key for a user from their password and salt.
fn derive_key(password: &str, salt_b64: &str) -> [u8; 32] {
    let salt = SaltString::from_b64(salt_b64).unwrap();
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt.as_ref().as_bytes(), &mut key)
        .unwrap();
    key
}

/// Adds a new journal entry for a user, with optional tags, due date, and status.
pub fn add_entry(user: &AuthenticatedUser, content: &str, tags: Option<Vec<String>>, due: Option<&String>, status: Option<&String>) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    let now = Local::now().naive_local().to_string();
    let enc_content = encrypt_field(&user.key, content);
    let enc_due = due.as_ref().map(|d| encrypt_field(&user.key, d));
    let enc_status = status.as_ref().map(|s| encrypt_field(&user.key, s));
    conn.execute(
        "INSERT INTO journal (content, due_date, status, created_at, user_id) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![enc_content, enc_due, enc_status, now, user.id],
    )?;
    let entry_id = conn.last_insert_rowid();
    if let Some(tags) = tags {
        for tag in tags {
            let enc_tag = encrypt_field(&user.key, &tag);
            let tag_id = get_or_create_tag(&conn, &enc_tag)?;
            conn.execute(
                "INSERT INTO entry_tags (entry_id, tag_id, user_id) VALUES (?1, ?2, ?3)",
                params![entry_id, tag_id, user.id],
            )?;
        }
    }
    log_action(user, "Added new entry", Some(content))?;
    Ok(())
}

/// Gets or creates a tag with the given name.
fn get_or_create_tag(conn: &Connection, tag: &str) -> Result<i64> {
    let mut stmt = conn.prepare("SELECT id FROM tags WHERE name = ?1")?;
    let mut rows = stmt.query(params![tag])?;
    if let Some(row) = rows.next()? {
        Ok(row.get(0)?)
    } else {
        conn.execute("INSERT INTO tags (name) VALUES (?1)", params![tag])?;
        Ok(conn.last_insert_rowid())
    }
}

/// Lists all journal entries for a user, optionally filtering by tag/status.
pub fn list_entries(user: &AuthenticatedUser, tag: Option<&String>, status: Option<&String>) -> Result<Vec<Entry>> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    let mut query = "SELECT j.id, j.content, j.due_date, j.status, j.created_at, j.updated_at, j.user_id FROM journal j".to_string();
    let mut wheres = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(ref tag_val) = tag {
        query.push_str(" JOIN entry_tags et ON j.id = et.entry_id JOIN tags t ON et.tag_id = t.id");
        wheres.push("t.name = ?");
        params.push(Box::new(tag_val));
    }
    if let Some(ref status_val) = status {
        wheres.push("j.status = ?");
        params.push(Box::new(status_val));
    }
    wheres.push("j.user_id = ?");
    params.push(Box::new(user.id));
    if !wheres.is_empty() {
        query.push_str(&format!(" WHERE {}", wheres.join(" AND ")));
    }
    query.push_str(" ORDER BY j.id DESC");
    let mut stmt = conn.prepare(&query)?;
    let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref() as &dyn ToSql).collect();
    let mut entries = Vec::new();
    let mut rows = stmt.query(param_refs.as_slice())?;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let enc_content: String = row.get(1)?;
        let content = decrypt_field(&user.key, &enc_content).unwrap_or_default();
        let due = row.get::<_, Option<String>>(2)?.and_then(|d| decrypt_field(&user.key, &d));
        let status = row.get::<_, Option<String>>(3)?.and_then(|s| decrypt_field(&user.key, &s)).unwrap_or_default();
        let tags = list_tags_for_entry(&conn, user, id)?;
        entries.push(Entry {
            id,
            content,
            tags,
            due_date: due,
            status,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            user_id: row.get(6)?,
        });
    }
    Ok(entries)
}

/// Lists all tags associated with an entry.
fn list_tags_for_entry(conn: &Connection, user: &AuthenticatedUser, entry_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT t.name FROM tags t JOIN entry_tags et ON t.id = et.tag_id WHERE et.entry_id = ?1 AND et.user_id = ?2")?;
    let tag_iter = stmt.query_map(params![entry_id, user.id], |row| {
        let enc_tag: String = row.get(0)?;
        Ok(decrypt_field(&user.key, &enc_tag).unwrap_or_default())
    })?;
    Ok(tag_iter.filter_map(Result::ok).collect())
}

/// Updates an existing journal entry for a user.
pub fn update_entry(user: &AuthenticatedUser, id: i64, content: Option<String>, tags: Option<Vec<String>>, remove_tags: Option<Vec<String>>, due: Option<String>, status: Option<String>) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    let now = Local::now().naive_local().to_string();
    let mut set = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(c) = content {
        let enc_content = encrypt_field(&user.key, &c);
        set.push("content = ?"); params.push(Box::new(enc_content));
    }
    if let Some(d) = due {
        let enc_due = encrypt_field(&user.key, &d);
        set.push("due_date = ?"); params.push(Box::new(enc_due));
    }
    if let Some(s) = status {
        let enc_status = encrypt_field(&user.key, &s);
        set.push("status = ?"); params.push(Box::new(enc_status));
    }
    set.push("updated_at = ?"); params.push(Box::new(now));
    if !set.is_empty() {
        let sql = format!("UPDATE journal SET {} WHERE id = ? AND user_id = ?", set.join(", "));
        params.push(Box::new(id));
        params.push(Box::new(user.id));
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref() as &dyn ToSql).collect();
        conn.execute(&sql, param_refs.as_slice())?;
    }
    if let Some(tags) = tags {
        let existing_tags = list_tags_for_entry(&conn, user, id)?;
        for tag in tags {
            if !existing_tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                let enc_tag = encrypt_field(&user.key, &tag);
                let tag_id = get_or_create_tag(&conn, &enc_tag)?;
                conn.execute(
                    "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id, user_id) VALUES (?1, ?2, ?3)",
                    params![id, tag_id, user.id],
                )?;
            }
        }
    }
    if let Some(remove_tags) = remove_tags {
        for tag in remove_tags {
            let enc_tag = encrypt_field(&user.key, &tag);
            let mut stmt = conn.prepare("SELECT id FROM tags WHERE name = ?1")?;
            let mut rows = stmt.query(params![enc_tag])?;
            if let Some(row) = rows.next()? {
                let tag_id: i64 = row.get(0)?;
                conn.execute(
                    "DELETE FROM entry_tags WHERE entry_id = ?1 AND tag_id = ?2 AND user_id = ?3",
                    params![id, tag_id, user.id],
                )?;
            }
        }
    }
    let _ = log_action(user, "Updated entry", Some(&format!("ID: {id}")));
    Ok(())
}

/// Gets a single journal entry by ID for a user.
pub fn get_entry(user: &AuthenticatedUser, id: i64) -> Result<Option<Entry>> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    let mut stmt = conn.prepare("SELECT id, content, due_date, status, created_at, updated_at, user_id FROM journal WHERE id = ?1 AND user_id = ?2")?;
    let mut rows = stmt.query(params![id, user.id])?;
    if let Some(row) = rows.next()? {
        let enc_content: String = row.get(1)?;
        let content = decrypt_field(&user.key, &enc_content).unwrap_or_default();
        let due = row.get::<_, Option<String>>(2)?.and_then(|d| decrypt_field(&user.key, &d));
        let status = row.get::<_, Option<String>>(3)?.and_then(|s| decrypt_field(&user.key, &s)).unwrap_or_default();
        let tags = list_tags_for_entry(&conn, user, id)?;
        Ok(Some(Entry {
            id: row.get(0)?,
            content,
            tags,
            due_date: due,
            status,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            user_id: row.get(6)?,
        }))
    } else {
        Ok(None)
    }
}

/// Deletes a journal entry and moves it to the recycle bin.
pub fn delete_entry(user: &AuthenticatedUser, id: i64) -> Result<()> {
    move_to_recycle_bin(user, id)
}

/// Migrates the recycle bin table.
pub fn migrate_recycle_bin(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS recycle_bin (
            id INTEGER PRIMARY KEY,
            content TEXT NOT NULL,
            due_date TEXT,
            status TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            deleted_at TEXT NOT NULL,
            user_id INTEGER NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS recycle_bin_tags (
            entry_id INTEGER,
            tag TEXT,
            user_id INTEGER NOT NULL,
            FOREIGN KEY(entry_id) REFERENCES recycle_bin(id)
        )",
        [],
    )?;
    Ok(())
}

/// Migrates all tables to the latest schema.
pub fn migrate_all(conn: &Connection) {
    conn.execute("ALTER TABLE journal ADD COLUMN user_id INTEGER", []).ok();
    conn.execute("ALTER TABLE recycle_bin ADD COLUMN user_id INTEGER", []).ok();
    conn.execute("ALTER TABLE entry_tags ADD COLUMN user_id INTEGER", []).ok();
    conn.execute("ALTER TABLE recycle_bin_tags ADD COLUMN user_id INTEGER", []).ok();
}

/// Moves an entry to the recycle bin.
pub fn move_to_recycle_bin(user: &AuthenticatedUser, id: i64) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    migrate_recycle_bin(&conn)?;
    let mut entry_stmt = conn.prepare("SELECT id, content, due_date, status, created_at, updated_at FROM journal WHERE id = ?1 AND user_id = ?2")?;
    let mut rows = entry_stmt.query(params![id, user.id])?;
    if let Some(row) = rows.next()? {
        let now = chrono::Local::now().naive_local().to_string();
        conn.execute(
            "INSERT INTO recycle_bin (id, content, due_date, status, created_at, updated_at, deleted_at, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                now,
                user.id
            ],
        )?;
        // Copy tags
        let mut tag_stmt = conn.prepare("SELECT t.name FROM tags t INNER JOIN entry_tags et ON t.id = et.tag_id WHERE et.entry_id = ?1 AND et.user_id = ?2")?;
        let tag_iter = tag_stmt.query_map(params![id, user.id], |row| row.get::<_, String>(0))?;
        for tag in tag_iter.filter_map(Result::ok) {
            conn.execute(
                "INSERT INTO recycle_bin_tags (entry_id, tag, user_id) VALUES (?1, ?2, ?3)",
                params![id, tag, user.id],
            )?;
        }
        // Remove from main tables
        conn.execute("DELETE FROM entry_tags WHERE entry_id = ?1 AND user_id = ?2", params![id, user.id])?;
        conn.execute("DELETE FROM journal WHERE id = ?1 AND user_id = ?2", params![id, user.id])?;
    }
    let _ = log_action(user, "Moved entry to recycle bin", Some(&format!("ID: {id}")));
    Ok(())
}

/// Recovers an entry from the recycle bin.
pub fn recover_from_recycle_bin(user: &AuthenticatedUser, id: i64) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    migrate_recycle_bin(&conn)?;
    let mut entry_stmt = conn.prepare("SELECT content, due_date, status, created_at, updated_at FROM recycle_bin WHERE id = ?1 AND user_id = ?2")?;
    let mut rows = entry_stmt.query(params![id, user.id])?;
    if let Some(row) = rows.next()? {
        conn.execute(
            "INSERT INTO journal (content, due_date, status, created_at, updated_at, user_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                user.id
            ],
        )?;
        let new_id = conn.last_insert_rowid();
        // Restore tags
        let mut tag_stmt = conn.prepare("SELECT tag FROM recycle_bin_tags WHERE entry_id = ?1 AND user_id = ?2")?;
        let tag_iter = tag_stmt.query_map(params![id, user.id], |row| row.get::<_, String>(0))?;
        for tag in tag_iter.filter_map(Result::ok) {
            let tag_id = get_or_create_tag(&conn, &tag)?;
            conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id, user_id) VALUES (?1, ?2, ?3)",
                params![new_id, tag_id, user.id],
            )?;
        }
        // Remove from recycle bin
        conn.execute("DELETE FROM recycle_bin_tags WHERE entry_id = ?1 AND user_id = ?2", params![id, user.id])?;
        conn.execute("DELETE FROM recycle_bin WHERE id = ?1 AND user_id = ?2", params![id, user.id])?;
    }
    let _ = log_action(user, "Recovered entry from recycle bin", Some(&format!("ID: {id}")));
    Ok(())
}

/// Purges expired entries from the recycle bin.
pub fn purge_expired_recycle_bin(user: &AuthenticatedUser) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    migrate_recycle_bin(&conn)?;
    let thirty_days_ago = chrono::Local::now().naive_local() - chrono::Duration::days(30);
    let cutoff = thirty_days_ago.to_string();
    // Remove tags first
    conn.execute(
        "DELETE FROM recycle_bin_tags WHERE entry_id IN (SELECT id FROM recycle_bin WHERE deleted_at < ?1 AND user_id = ?2)",
        params![cutoff, user.id],
    )?;
    conn.execute(
        "DELETE FROM recycle_bin WHERE deleted_at < ?1 AND user_id = ?2",
        params![cutoff, user.id],
    )?;
    log_action(user, "Purged expired recycle bin entries", None)?;
    Ok(())
}

/// Lists all entries in the recycle bin for a user.
pub fn list_recycle_bin(user: &AuthenticatedUser) -> Result<Vec<RecycleBinEntry>> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    migrate_recycle_bin(&conn)?;
    let mut stmt = conn.prepare(
        "SELECT id, content, due_date, status, created_at, updated_at, deleted_at FROM recycle_bin WHERE user_id = ?1 ORDER BY deleted_at DESC"
    )?;
    let entry_iter = stmt.query_map(params![user.id], |row| {
        let id: i64 = row.get(0)?;
        let mut tag_stmt = conn.prepare("SELECT tag FROM recycle_bin_tags WHERE entry_id = ?1 AND user_id = ?2")?;
        let tag_iter = tag_stmt.query_map(params![id, user.id], |row| row.get::<_, String>(0))?;
        let tags = tag_iter.filter_map(Result::ok).collect();
        Ok(RecycleBinEntry {
            id,
            content: row.get(1)?,
            due_date: row.get(2)?,
            status: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
            deleted_at: row.get(6)?,
            user_id: user.id,
            tags,
        })
    })?;
    Ok(entry_iter.filter_map(Result::ok).collect())
}

/// Cleans up legacy data in the database.
pub fn clean_legacy_data() -> Result<()> {
    let conn = Connection::open(db_path())?;
    // Remove orphaned entries
    conn.execute("DELETE FROM journal WHERE user_id IS NULL OR user_id NOT IN (SELECT id FROM users)", [])?;
    conn.execute("DELETE FROM recycle_bin WHERE user_id IS NULL OR user_id NOT IN (SELECT id FROM users)", [])?;
    conn.execute("DELETE FROM entry_tags WHERE user_id IS NULL OR user_id NOT IN (SELECT id FROM users)", [])?;
    conn.execute("DELETE FROM recycle_bin_tags WHERE user_id IS NULL OR user_id NOT IN (SELECT id FROM users)", [])?;
    // Remove orphaned tags (not referenced by any entry_tags)
    conn.execute("DELETE FROM tags WHERE id NOT IN (SELECT tag_id FROM entry_tags)", [])?;
    Ok(())
}

/// Changes the password for a user, re-encrypting all their data.
pub fn change_password(user: &AuthenticatedUser, old_password: &str, new_password: &str) -> Result<()> {
    let conn = Connection::open(db_path())?;
    // Verify old password
    let mut stmt = conn.prepare("SELECT password_hash, salt FROM users WHERE id = ?1")?;
    let (hash, _salt_b64): (String, String) = stmt.query_row(params![user.id], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let parsed_hash = argon2::password_hash::PasswordHash::new(&hash).unwrap();
    if Argon2::default().verify_password(old_password.as_bytes(), &parsed_hash).is_err() {
        return Err(rusqlite::Error::InvalidQuery); // Use a better error in real code
    }
    // Generate new salt/hash/key
    let new_salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
    let new_hash = Argon2::default().hash_password(new_password.as_bytes(), &new_salt).unwrap().to_string();
    let new_key = {
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(new_password.as_bytes(), new_salt.as_ref().as_bytes(), &mut key).unwrap();
        key
    };
    // Decrypt all user data with old key, re-encrypt with new key
    let old_key = user.key;
    // Journal entries
    let mut stmt = conn.prepare("SELECT id, content, due_date, status FROM journal WHERE user_id = ?1")?;
    let mut rows = stmt.query(params![user.id])?;
    let mut updates = vec![];
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let content: String = row.get(1)?;
        let due: Option<String> = row.get(2)?;
        let status: Option<String> = row.get(3)?;
        let dec_content = decrypt_field(&old_key, &content).unwrap_or_default();
        let enc_content = encrypt_field(&new_key, &dec_content);
        let enc_due = due.and_then(|d| decrypt_field(&old_key, &d)).map(|d| encrypt_field(&new_key, &d));
        let enc_status = status.and_then(|s| decrypt_field(&old_key, &s)).map(|s| encrypt_field(&new_key, &s));
        updates.push((id, enc_content, enc_due, enc_status));
    }
    for (id, content, due, status) in updates {
        conn.execute("UPDATE journal SET content = ?1, due_date = ?2, status = ?3 WHERE id = ?4", params![content, due, status, id])?;
    }
    // Tags
    let mut stmt = conn.prepare("SELECT id, name FROM tags")?;
    let mut rows = stmt.query([])?;
    let mut tag_updates = vec![];
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        if let Some(dec_tag) = decrypt_field(&old_key, &name) {
            let enc_tag = encrypt_field(&new_key, &dec_tag);
            tag_updates.push((id, enc_tag));
        }
    }
    for (id, name) in tag_updates {
        conn.execute("UPDATE tags SET name = ?1 WHERE id = ?2", params![name, id])?;
    }
    // Recycle bin
    let mut stmt = conn.prepare("SELECT id, content, due_date, status FROM recycle_bin WHERE user_id = ?1")?;
    let mut rows = stmt.query(params![user.id])?;
    let mut bin_updates = vec![];
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let content: String = row.get(1)?;
        let due: Option<String> = row.get(2)?;
        let status: Option<String> = row.get(3)?;
        let dec_content = decrypt_field(&old_key, &content).unwrap_or_default();
        let enc_content = encrypt_field(&new_key, &dec_content);
        let enc_due = due.and_then(|d| decrypt_field(&old_key, &d)).map(|d| encrypt_field(&new_key, &d));
        let enc_status = status.and_then(|s| decrypt_field(&old_key, &s)).map(|s| encrypt_field(&new_key, &s));
        bin_updates.push((id, enc_content, enc_due, enc_status));
    }
    for (id, content, due, status) in bin_updates {
        conn.execute("UPDATE recycle_bin SET content = ?1, due_date = ?2, status = ?3 WHERE id = ?4", params![content, due, status, id])?;
    }
    // Tags in recycle bin
    let mut stmt = conn.prepare("SELECT entry_id, tag FROM recycle_bin_tags WHERE user_id = ?1")?;
    let mut rows = stmt.query(params![user.id])?;
    let mut rbt_updates = vec![];
    while let Some(row) = rows.next()? {
        let entry_id: i64 = row.get(0)?;
        let tag: String = row.get(1)?;
        if let Some(dec_tag) = decrypt_field(&old_key, &tag) {
            let enc_tag = encrypt_field(&new_key, &dec_tag);
            rbt_updates.push((entry_id, enc_tag));
        }
    }
    for (entry_id, tag) in rbt_updates {
        conn.execute("UPDATE recycle_bin_tags SET tag = ?1 WHERE entry_id = ?2", params![tag, entry_id])?;
    }
    // Update user password hash and salt
    conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
        params![new_hash, new_salt.as_str(), user.id],
    )?;
    Ok(())
}

/// Initializes the audit log table.
pub fn init_audit_log(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Logs an action to the audit log for a user.
pub fn log_action(user: &AuthenticatedUser, action: &str, details: Option<&str>) -> Result<()> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    init_audit_log(&conn)?;
    let now = chrono::Local::now().naive_local().to_string();
    // Encrypt details field if present
    let enc_details = details.map(|d| encrypt_field(&user.key, d));
    let enc_action = encrypt_field(&user.key, action);
    conn.execute(
        "INSERT INTO audit_log (user_id, action, details, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![user.id, enc_action, enc_details, now],
    )?;
    Ok(())
}

/// Lists all audit log entries for a user.
pub fn list_audit_log(user: &AuthenticatedUser) -> Result<Vec<AuditLog>> {
    let conn = Connection::open(db_path())?;
    migrate_all(&conn);
    init_audit_log(&conn)?;
    let mut stmt = conn.prepare("SELECT id, user_id, action, details, timestamp FROM audit_log WHERE user_id = ?1 ORDER BY timestamp DESC")?;
    let log_iter = stmt.query_map(params![user.id], |row| {
        let action_enc: String = row.get(2)?;
        let details_enc: Option<String> = row.get(3)?;
        Ok(AuditLog {
            id: row.get(0)?,
            user_id: row.get(1)?,
            action: decrypt_field(&user.key, &action_enc).unwrap_or_default(),
            details: details_enc.and_then(|d| decrypt_field(&user.key, &d)),
            timestamp: row.get(4)?,
        })
    })?;
    Ok(log_iter.filter_map(Result::ok).collect())
}

/// Encrypts a plaintext field with the given key using AES-256-GCM.
pub fn encrypt_field(key: &[u8; 32], plaintext: &str) -> String {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    general_purpose::STANDARD.encode(&result)
}

/// Decrypts an encrypted field with the given key using AES-256-GCM.
pub fn decrypt_field(key: &[u8; 32], ciphertext: &str) -> Option<String> {
    let decoded = general_purpose::STANDARD.decode(ciphertext).ok()?;
    if decoded.len() < 12 {
        debug_println!("[DEBUG] Decrypt failed: decoded len < 12 for ciphertext: {:?}", ciphertext);
        return None;
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    match cipher.decrypt(nonce, ciphertext) {
        Ok(pt) => match String::from_utf8(pt) {
            Ok(s) => Some(s),
            Err(e) => {
                debug_println!("[DEBUG] Decrypt failed: invalid UTF-8: {}", e);
                None
            }
        },
        Err(e) => {
            debug_println!("[DEBUG] Decrypt failed: {} for ciphertext: {:?}", e, ciphertext);
            None
        }
    }
}

/// Lists all tags for a user.
pub fn list_tags(user: &AuthenticatedUser) -> Result<Vec<String>> {
    let conn = Connection::open(db_path())?;
    let mut stmt = conn.prepare("SELECT name FROM tags t JOIN entry_tags et ON t.id = et.tag_id WHERE et.user_id = ?1 GROUP BY t.id ORDER BY name COLLATE NOCASE ASC")?;
    let tag_iter = stmt.query_map(params![user.id], |row| {
        let enc_tag: String = row.get(0)?;
        Ok(decrypt_field(&user.key, &enc_tag).unwrap_or_default())
    })?;
    Ok(tag_iter.filter_map(Result::ok).collect())
}

/// Lists all tags with their usage counts for a user.
pub fn list_tags_with_counts(user: &AuthenticatedUser) -> Result<Vec<(String, u32)>> {
    let conn = Connection::open(db_path())?;
    let mut stmt = conn.prepare(
        "SELECT t.name, COUNT(et.entry_id) as usage_count \
         FROM tags t \
         JOIN entry_tags et ON t.id = et.tag_id \
         WHERE et.user_id = ?1 \
         GROUP BY t.id \
         ORDER BY t.name COLLATE NOCASE ASC"
    )?;
    let tag_iter = stmt.query_map(params![user.id], |row| {
        let enc_tag: String = row.get(0)?;
        let count: u32 = row.get(1)?;
        Ok((decrypt_field(&user.key, &enc_tag).unwrap_or_default(), count))
    })?;
    // Aggregate counts for tags with the same name
    let mut tag_map = std::collections::BTreeMap::new();
    for result in tag_iter.filter_map(Result::ok) {
        let (tag, count) = result;
        *tag_map.entry(tag).or_insert(0) += count;
    }
    Ok(tag_map.into_iter().collect())
}

/// Admin: Deletes all data for a user and resets their password.
pub fn admin_reset_user(username: &str, new_password: &str) -> Result<()> {
    let conn = Connection::open(db_path())?;
    // Find user id
    let mut stmt = conn.prepare("SELECT id FROM users WHERE username = ?1")?;
    let user_id: i64 = stmt.query_row(params![username], |row| row.get(0))?;
    // Delete all user data (journal, tags, recycle bin, audit log)
    conn.execute("DELETE FROM journal WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM entry_tags WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM recycle_bin WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM recycle_bin_tags WHERE user_id = ?1", params![user_id])?;
    conn.execute("DELETE FROM audit_log WHERE user_id = ?1", params![user_id])?;
    // Set new password hash and salt
    let salt = argon2::password_hash::SaltString::generate(&mut rand::rngs::OsRng);
    let hash = Argon2::default().hash_password(new_password.as_bytes(), &salt).unwrap().to_string();
    conn.execute(
        "UPDATE users SET password_hash = ?1, salt = ?2 WHERE id = ?3",
        params![hash, salt.as_str(), user_id],
    )?;
    // Log the admin reset in the audit log (for the affected user)
    let now = chrono::Local::now().naive_local().to_string();
    let action = encrypt_field(&[0u8; 32], "admin_reset");
    let details = encrypt_field(&[0u8; 32], "Admin reset performed. All data deleted and password reset.");
    conn.execute(
        "INSERT INTO audit_log (user_id, action, details, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![user_id, action, details, now],
    )?;
    Ok(())
}

/// Returns true if any users exist in the database.
pub fn users_exist(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("SELECT EXISTS(SELECT 1 FROM users LIMIT 1)")?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        let exists: i64 = row.get(0)?;
        Ok(exists == 1)
    } else {
        Ok(false)
    }
}
