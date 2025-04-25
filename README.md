# Journaler

A secure, user-authenticated CLI journal application with per-user encryption, session management, and robust data features.

## Features

- **User Authentication:** Register and log in with a username and password. Passwords are hashed and salted using Argon2.
- **Per-User Data Encryption:** All journal data is encrypted with a key derived from your password. Only you can access your data after authentication.
- **Session Management:**
  - Automatic session persists for 30 minutes of inactivity (configurable via `--session-timeout` or `JOURNALER_SESSION_TIMEOUT`).
  - No need to log in for each command within the timeout window.
  - `logout` command to clear your session.
- **Password Change:** Change your password securely; all your data is re-encrypted with the new key.
- **Legacy Data Cleanup:** Remove all legacy/unowned data from the database with `clean-legacy`.
- **Tag Management:**
  - Add, list, and search tags per user.
  - Tag usage counts and per-entry tag listing.
- **Entry Management:**
  - Add, update, delete, and search journal entries.
  - Entries support tags, due dates, and status fields.
  - Recycle bin for deleted entries with recovery and purge.
- **CLI User Guide:** Built-in help and usage guide.

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

## Usage

### Register a User
```
journaler register-user
```

### Log In (automatically handled for all commands)
```
journaler list-entries
```
If not logged in or session expired, you'll be prompted for credentials.

### Session Timeout
- Default: 30 minutes (1800 seconds).
- Override with:
  - CLI: `journaler --session-timeout 600 list-entries`
  - Env: `export JOURNALER_SESSION_TIMEOUT=600`

### Log Out
```
journaler logout
```

### Change Password
```
journaler change-password
```

### Clean Up Legacy Data
```
journaler clean-legacy
```

### Add, List, Update, Delete Entries
- See `journaler --guide` for all commands and options.

## Security
- All sensitive data is encrypted per user.
- Passwords are never stored in plaintext.
- Session file is stored in your config directory and expires after inactivity.

## Example Commands
```
journaler add-entry --content "My secret thoughts" --tags personal,private
journaler list-entries
journaler search-entries --query "secret"
journaler list-tags
journaler change-password
journaler logout
```

## Environment Variables
- `JOURNAL_DB`: Set the SQLite DB path (default: `journal.db`)
- `JOURNALER_SESSION_TIMEOUT`: Set session timeout in seconds (default: 1800)

## Dependencies
- `rusqlite`, `argon2`, `aes-gcm`, `serde`, `dirs`, `dialoguer`, `once_cell`, `chrono`, `csv`, `base64`, `rand`

---

For full details, run:
```
journaler --guide
```

## Contributing

Contributions and suggestions are welcome! Please open issues or pull requests to discuss improvements.

## License

MIT License
