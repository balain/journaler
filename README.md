# Journaler

A secure, feature-rich command-line journal application written in Rust. Journaler helps you capture, organize, and review your thoughts, todos, and project notes efficiently—right from your terminal. All data is encrypted per user and only accessible after authentication.

---

## Features

- **User authentication**: Register and log in with a username and password (Argon2 hashed, salted)
- **Per-user encryption**: All journal data is encrypted and only accessible to the authenticated user
- **Add, list, update, view, search, and delete journal entries** (all require authentication)
- **Tag management**: Assign, remove, and list tags (encrypted per user)
- **Multiple tags per entry**
- **Status labels**: Track entry status (e.g., In Progress, Done, Late)
- **Due dates**: Optional due date per entry; supports natural language input
- **Recycle bin**: Deleted entries are recoverable for 30 days (per user)
- **Tag similarity checks**: Prevents accidental duplicate/similar tags with interactive prompts
- **Fuzzy tag matching**: Uses fuzzy logic to suggest existing tags
- **Interactive CLI prompts** for tag selection and confirmations
- **List all tags with usage counts**
- **Password change**: Securely change your password and re-encrypt all your data
- **Clean legacy data**: Remove all data not associated with a user
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

---

## Usage Overview

All commands that access journal data require authentication. You will be prompted for your username and password at the start of your session.

### Common Commands

- `add`             Add a new journal entry (requires authentication)
- `list`            List your journal entries (requires authentication)
- `update`          Update an entry (requires authentication)
- `view`            View a specific entry (requires authentication)
- `delete`          Delete an entry (moves to recycle bin, requires authentication)
- `tags`            List your tags and usage counts (requires authentication)
- `search`          Search your entries (requires authentication)
- `recycle-bin`     List your recycle bin (requires authentication)
- `recover`         Recover an entry from the recycle bin (requires authentication)
- `purge-recyclebin` Purge entries older than 30 days from recycle bin (requires authentication)
- `register-user`   Register a new user
- `clean-legacy`    Remove all legacy/unowned data from the database
- `change-password` Change your password and re-encrypt your data

### Security
- All journal, tag, and recycle bin data is encrypted per user and only accessible after authentication.
- Passwords are hashed and salted using Argon2.
- Each user can only access their own entries, tags, and recycle bin.
- Password changes re-encrypt all your data with your new password.
- Use `clean-legacy` to remove all data not owned by a user.

### Examples
```sh
# Register a new user
cargo run --release -- register-user

# Add a new journal entry
cargo run --release -- add "My first journal entry" --tags personal --due 2025-05-01 --status "In Progress"

# List all entries
cargo run --release -- list

# Change your password
cargo run --release -- change-password

# Clean up legacy data
cargo run --release -- clean-legacy
```

---

## Contributing

Contributions and suggestions are welcome! Please open issues or pull requests to discuss improvements.

---

## License

MIT License
