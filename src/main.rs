mod db;
use clap::{Parser, Subcommand, ArgAction};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone};
use strsim::normalized_levenshtein;
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "journaler")]
#[command(about = "A CLI journal app", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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
}

fn color_status(status: &str) -> String {
    match status.to_lowercase().as_str() {
        "in progress" => format!("\x1b[32m{}\x1b[0m", status), // green
        "done" => format!("\x1b[34m{}\x1b[0m", status),       // blue
        "late" => format!("\x1b[31m{}\x1b[0m", status),       // red
        _ => status.to_string(),
    }
}

fn prompt_for_similar_tag(new_tag: &str, existing_tags: &[String]) -> Option<String> {
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

fn main() {
    let cli = Cli::parse();
    db::init().expect("Failed to initialize database");
    match cli.command {
        Commands::Add { content, tags, due, status } => {
            let mut tags_vec = Vec::new();
            let all_tags = db::list_tags().expect("Failed to list tags");
            for tag in tags {
                if let Some(existing) = prompt_for_similar_tag(&tag, &all_tags) {
                    tags_vec.push(existing);
                } else {
                    tags_vec.push(tag);
                }
            }
            let tags_vec = if tags_vec.is_empty() { None } else { Some(tags_vec) };
            db::add_entry(&content, tags_vec, due, status).expect("Add failed");
            println!("Entry added.");
        }
        Commands::List { tag, status } => {
            let entries = db::list_entries(tag, status).expect("List failed");
            let now = Local::now();
            for e in entries {
                let created_disp = {
                    let created = &e.created_at;
                    if let Ok(ndt) = NaiveDateTime::parse_from_str(created, "%Y-%m-%d %H:%M:%S%.f") {
                        let dt: DateTime<Local> = Local.from_local_datetime(&ndt).unwrap();
                        let diff = now.signed_duration_since(dt);
                        if diff.num_minutes() < 120 && diff.num_seconds() >= 0 {
                            if diff.num_minutes() < 1 {
                                format!("just now")
                            } else if diff.num_minutes() == 1 {
                                format!("1 minute ago")
                            } else if diff.num_minutes() < 60 {
                                format!("{} minutes ago", diff.num_minutes())
                            } else {
                                let h = diff.num_minutes() / 60;
                                let m = diff.num_minutes() % 60;
                                if m == 0 {
                                    format!("{} hour{} ago", h, if h == 1 { "" } else { "s" })
                                } else {
                                    format!("{} hour{} {} min ago", h, if h == 1 { "" } else { "s" }, m)
                                }
                            }
                        } else {
                            created.clone()
                        }
                    } else {
                        created.clone()
                    }
                };
                let last_mod_disp = if let Some(updated) = &e.updated_at {
                    if let Ok(ndt) = NaiveDateTime::parse_from_str(updated, "%Y-%m-%d %H:%M:%S%.f") {
                        let dt: DateTime<Local> = Local.from_local_datetime(&ndt).unwrap();
                        let diff = now.signed_duration_since(dt);
                        if diff.num_minutes() < 120 && diff.num_seconds() >= 0 {
                            if diff.num_minutes() < 1 {
                                format!("just now")
                            } else if diff.num_minutes() == 1 {
                                format!("1 minute ago")
                            } else if diff.num_minutes() < 60 {
                                format!("{} minutes ago", diff.num_minutes())
                            } else {
                                let h = diff.num_minutes() / 60;
                                let m = diff.num_minutes() % 60;
                                if m == 0 {
                                    format!("{} hour{} ago", h, if h == 1 { "" } else { "s" })
                                } else {
                                    format!("{} hour{} {} min ago", h, if h == 1 { "" } else { "s" }, m)
                                }
                            }
                        } else {
                            updated.clone()
                        }
                    } else {
                        updated.clone()
                    }
                } else {
                    "-".to_string()
                };
                let status_colored = color_status(&e.status);
                let mut fields = vec![
                    format!("{}: {}", e.id, e.content),
                    format!("[status: {}]", status_colored),
                    format!("[created: {}]", created_disp),
                    format!("[last modified: {}]", last_mod_disp),
                ];
                if !e.tags.is_empty() {
                    fields.insert(1, format!("[tags: {}]", e.tags.join(", ")));
                }
                if let Some(due) = &e.due_date {
                    if !due.trim().is_empty() {
                        let idx = if !e.tags.is_empty() { 2 } else { 1 };
                        fields.insert(idx, format!("[due: {}]", due));
                    }
                }
                println!("{}", fields.join(" "));
            }
        }
        Commands::Update { id, content, tags, remove_tag, due, status } => {
            let mut tags_vec = Vec::new();
            let all_tags = db::list_tags().expect("Failed to list tags");
            for tag in tags {
                if let Some(existing) = prompt_for_similar_tag(&tag, &all_tags) {
                    tags_vec.push(existing);
                } else {
                    tags_vec.push(tag);
                }
            }
            let tags_vec = if tags_vec.is_empty() { None } else { Some(tags_vec) };
            let remove_tags_vec = if remove_tag.is_empty() { None } else { Some(remove_tag.clone()) };
            db::update_entry(id, content, tags_vec, remove_tags_vec, due, status).expect("Update failed");
            println!("Entry updated.");
        }
        Commands::View { id } => {
            if let Some(e) = db::get_entry(id).expect("View failed") {
                println!("{}: {} [tags: {}] [due: {:?}] [status: {}] [created: {}] [updated: {:?}]", e.id, e.content, e.tags.join(", "), e.due_date, e.status, e.created_at, e.updated_at);
            } else {
                println!("Entry not found.");
            }
        }
        Commands::Tags => {
            let tags = db::list_tags_with_counts().expect("Failed to list tags");
            if tags.is_empty() {
                println!("No tags found.");
            } else {
                println!("Available tags:");
                for (t, count) in tags {
                    println!("- {} ({})", t, count);
                }
            }
        }
    }
}
