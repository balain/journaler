use rusqlite::{params, Connection, Result, ToSql};
use chrono::Local;

pub struct Entry {
    pub id: i64,
    pub content: String,
    pub tags: Vec<String>,
    pub due_date: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: Option<String>,
}

pub fn init() -> Result<()> {
    let conn = Connection::open("journal.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS journal (
            id INTEGER PRIMARY KEY,
            content TEXT NOT NULL,
            due_date TEXT,
            status TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT
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
            FOREIGN KEY(entry_id) REFERENCES journal(id) ON DELETE CASCADE,
            FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY(entry_id, tag_id)
        )",
        [],
    )?;
    Ok(())
}

pub fn add_entry(content: &str, tags: Option<Vec<String>>, due: Option<String>, status: Option<String>) -> Result<()> {
    let conn = Connection::open("journal.db")?;
    let now = Local::now().naive_local().to_string();
    conn.execute(
        "INSERT INTO journal (content, due_date, status, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            content,
            due,
            status.unwrap_or_else(|| "open".to_string()),
            now,
        ],
    )?;
    let entry_id = conn.last_insert_rowid();
    if let Some(tags) = tags {
        for tag in tags {
            let tag_id = get_or_create_tag(&conn, &tag)?;
            conn.execute(
                "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
                params![entry_id, tag_id],
            )?;
        }
    }
    Ok(())
}

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

pub fn list_entries(tag: Option<String>, status: Option<String>) -> Result<Vec<Entry>> {
    let conn = Connection::open("journal.db")?;
    let mut query = "SELECT j.id, j.content, j.due_date, j.status, j.created_at, j.updated_at FROM journal j".to_string();
    let mut wheres = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    if tag.is_some() {
        query.push_str(" JOIN entry_tags et ON j.id = et.entry_id JOIN tags t ON et.tag_id = t.id");
        wheres.push("t.name = ?");
        params.push(Box::new(tag.unwrap()));
    }
    if status.is_some() {
        wheres.push("j.status = ?");
        params.push(Box::new(status.unwrap()));
    }
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
        let tags = get_tags_for_entry(&conn, id)?;
        entries.push(Entry {
            id,
            content: row.get(1)?,
            tags,
            due_date: row.get(2)?,
            status: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?
        });
    }
    Ok(entries)
}

fn get_tags_for_entry(conn: &Connection, entry_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT t.name FROM tags t JOIN entry_tags et ON t.id = et.tag_id WHERE et.entry_id = ?1")?;
    let tag_iter = stmt.query_map(params![entry_id], |row| row.get(0))?;
    Ok(tag_iter.filter_map(Result::ok).collect())
}

pub fn update_entry(id: i64, content: Option<String>, tags: Option<Vec<String>>, remove_tags: Option<Vec<String>>, due: Option<String>, status: Option<String>) -> Result<()> {
    let conn = Connection::open("journal.db")?;
    let now = Local::now().naive_local().to_string();
    let mut set = Vec::new();
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();
    if let Some(c) = content {
        set.push("content = ?"); params.push(Box::new(c));
    }
    if let Some(d) = due {
        set.push("due_date = ?"); params.push(Box::new(d));
    }
    if let Some(s) = status {
        set.push("status = ?"); params.push(Box::new(s));
    }
    set.push("updated_at = ?"); params.push(Box::new(now));
    if !set.is_empty() {
        let sql = format!("UPDATE journal SET {} WHERE id = ?", set.join(", "));
        params.push(Box::new(id));
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref() as &dyn ToSql).collect();
        conn.execute(&sql, param_refs.as_slice())?;
    }
    if let Some(tags) = tags {
        let existing_tags = get_tags_for_entry(&conn, id)?;
        for tag in tags {
            if !existing_tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                let tag_id = get_or_create_tag(&conn, &tag)?;
                conn.execute(
                    "INSERT OR IGNORE INTO entry_tags (entry_id, tag_id) VALUES (?1, ?2)",
                    params![id, tag_id],
                )?;
            }
        }
    }
    if let Some(remove_tags) = remove_tags {
        for tag in remove_tags {
            let mut stmt = conn.prepare("SELECT id FROM tags WHERE name = ?1")?;
            let mut rows = stmt.query(params![tag])?;
            if let Some(row) = rows.next()? {
                let tag_id: i64 = row.get(0)?;
                conn.execute(
                    "DELETE FROM entry_tags WHERE entry_id = ?1 AND tag_id = ?2",
                    params![id, tag_id],
                )?;
            }
        }
    }
    Ok(())
}

pub fn get_entry(id: i64) -> Result<Option<Entry>> {
    let conn = Connection::open("journal.db")?;
    let mut stmt = conn.prepare("SELECT id, content, due_date, status, created_at, updated_at FROM journal WHERE id = ?1")?;
    let mut rows = stmt.query(params![id])?;
    if let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let tags = get_tags_for_entry(&conn, id)?;
        Ok(Some(Entry {
            id,
            content: row.get(1)?,
            tags,
            due_date: row.get(2)?,
            status: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?
        }))
    } else {
        Ok(None)
    }
}

pub fn list_tags() -> Result<Vec<String>> {
    let conn = Connection::open("journal.db")?;
    let mut stmt = conn.prepare("SELECT name FROM tags ORDER BY name COLLATE NOCASE ASC")?;
    let tag_iter = stmt.query_map([], |row| row.get(0))?;
    Ok(tag_iter.filter_map(Result::ok).collect())
}

pub fn list_tags_with_counts() -> Result<Vec<(String, u32)>> {
    let conn = Connection::open("journal.db")?;
    let mut stmt = conn.prepare(
        "SELECT t.name, COUNT(et.entry_id) as usage_count \
         FROM tags t \
         LEFT JOIN entry_tags et ON t.id = et.tag_id \
         GROUP BY t.id \
         ORDER BY t.name COLLATE NOCASE ASC"
    )?;
    let tag_iter = stmt.query_map([], |row| {
        let name: String = row.get(0)?;
        let count: u32 = row.get(1)?;
        Ok((name, count))
    })?;
    Ok(tag_iter.filter_map(Result::ok).collect())
}
