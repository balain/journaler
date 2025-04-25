# Journaler

A modern, feature-rich command-line journal application written in Rust. Journaler helps you capture, organize, and review your thoughts, todos, and project notes efficiently—right from your terminal.

---

## Features

- **Add, list, update, and view journal entries**
- **Tag management**: Assign, remove, and list tags; tags are stored in a normalized lookup table
- **Multiple tags per entry**
- **Status labels**: Track entry status (e.g., In Progress, Done, Late)
- **Due dates**: Optional due date per entry; supports natural language input
- **Relative time display**: Human-friendly timestamps (e.g., "30 minutes ago")
- **Tag similarity checks**: Prevents accidental duplicate/similar tags with interactive prompts
- **Fuzzy tag matching**: Uses fuzzy logic to suggest existing tags
- **Interactive CLI prompts** for tag selection
- **List all tags with usage counts**
- **Comprehensive user guide**: `--guide` flag shows help and examples

---

## Installation

### Prerequisites
- Rust toolchain (https://rustup.rs)
- SQLite3 (for the underlying database)

### Clone and Build
```sh
git clone https://github.com/yourusername/journaler.git
cd journaler
cargo build --release
```

### Run
```sh
# Add a new journal entry
cargo run --release -- add "My first journal entry" --tags personal --due 2025-05-01 --status "In Progress"

# List all entries
cargo run --release -- list

# Update an entry
cargo run --release -- update 1 --tags work --remove-tag personal --status Done

# View a specific entry
cargo run --release -- view 1

# List all tags with usage counts
cargo run --release -- tags

# Show the user guide
cargo run --release --guide
```

---

## Usage Overview

- **Entries**: Each entry can have content, tags, due date, and status.
- **Tags**: Tags are managed in a lookup table to avoid duplicates. When adding a tag similar to an existing one, you'll be prompted to confirm or re-use.
- **Statuses**: Any string (e.g., In Progress, Done, Late).
- **Due Dates**: Accepts `YYYY-MM-DD` or natural language (e.g., "tomorrow").
- **Interactive Prompts**: Tag selection is interactive if similar tags exist.

For a full guide and examples, run `cargo run --release --guide`.

---

## Potential Enhancements

- Full-text search and advanced filtering
- Interactive TUI (text user interface)
- Reminders/notifications for due dates
- Entry history and undo
- Export/import to Markdown, CSV, or JSON
- Configurable statuses and templates
- API or plugin system
- Bulk operations (batch edit/delete)
- Shell autocompletion scripts
- Backup/restore database
- Improved error handling and validation
- Unit and integration tests

---

## Contributing

Contributions and suggestions are welcome! Please open issues or pull requests to discuss improvements.

---

## License

MIT License
