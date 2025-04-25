# Journaler

A secure, user-authenticated CLI journal application with per-user encryption, session management, and robust data features.

## Features

- **User Authentication & Management:**
  - Register new users: `journaler register-user`
  - Log in automatically when running any command (prompted if session expired)
  - Change your password: `journaler change-password`
  - Session persists for a configurable timeout (default 30 minutes)
  - End session instantly: `journaler logout`
- **Per-User Data Encryption:**
  - All journal data (entries, tags, etc.) is encrypted with a key derived from your password using Argon2 and AES-256-GCM.
  - Only you can decrypt your data after login.
- **Session Management:**
  - Persistent session file stored securely in your OS config directory
  - Timeout configurable via `--session-timeout` or `JOURNALER_SESSION_TIMEOUT`
  - Session file is deleted on logout or after timeout
- **Entry Management:**
  - Add: `journaler add --content "..." [--tags ...] [--due ...] [--status ...]`
  - Update: `journaler update --id <ID> [--content ...] [--tags ...] [--remove-tag ...] [--due ...] [--status ...]`
  - Delete (moves to recycle bin): `journaler delete --id <ID>`
  - List: `journaler list`
  - View: `journaler view --id <ID>`
  - Search: `journaler search --query "..."`
  - Export: `journaler export --format csv|md|txt [--output <file>]`
- **Recycle Bin:**
  - Deleted entries go to a recycle bin for 30 days
  - Recover: `journaler recover --id <ID>`
  - Purge expired: `journaler purge-recycle-bin`
  - List recycle bin: `journaler recycle-bin`
- **Tag Management:**
  - Tags are per-user and encrypted
  - Add tags on entry creation/update
  - Remove tags from entries
  - List tags: `journaler tags`
  - Tag usage counts
- **Statistics:**
  - `journaler list` shows:
    - Total entries
    - Average age
    - Average time since last update
    - Number of unique users
    - Entries per user (by username)
    - Entry updates in the last hour, day, week, month
- **Legacy Data Cleanup:**
  - `journaler clean-legacy` removes legacy/unowned data
- **Help & Guide:**
  - `journaler --guide` or `journaler --help` for all commands and options

## Encryption & Security
- **Password Hashing:** Uses Argon2 with salt for secure password storage
- **Data Encryption:** AES-256-GCM; all journal content, tags, and sensitive user data are encrypted per user
- **Session Security:** Session file contains only encrypted user credentials and expires automatically
- **No Plaintext:** Passwords and sensitive data are never stored or transmitted in plaintext

## Installation

### Prerequisites
- Rust toolchain (https://rustup.rs)
- SQLite3 (for the underlying database)

### Clone and Build
```sh
git clone https://github.com/balain/journaler.git
cd journaler
cargo build --release
```

## Usage Examples

### Register a User
```
journaler register-user
```

### Add an Entry
```
journaler add --content "My encrypted journal entry" --tags personal,private
```

### Update an Entry
```
journaler update --id 3 --content "Updated text" --tags work --remove-tag oldtag --due "2025-05-01" --status completed
```

### Delete an Entry
```
journaler delete --id 3
```

### List Entries and Stats
```
journaler list
```

### Log Out (End Session)
```
journaler logout
```

### Recover Deleted Entry
```
journaler recover --id 3
```

### Change Password
```
journaler change-password
```

### Clean Up Legacy Data
```
journaler clean-legacy
```

### View Help/Guide
```
journaler --guide
```

## Debugging Output

Journaler supports detailed debugging output for troubleshooting and development.

### Enable Debug Output in the CLI

Add the `--debug` flag to any command to display internal debug messages:

```
$ ./journaler --debug list
```

### Enable Debug Output in Integration Tests

Set the `JOURNALER_DEBUG=1` environment variable when running tests to see debug output from test helpers and setup:

```
$ JOURNALER_DEBUG=1 cargo test -- --nocapture
```

Debug output is hidden by default and only shown when the flag or environment variable is set.

## Environment Variables
- `JOURNAL_DB`: Set the SQLite DB path (default: `journal.db`)
- `JOURNALER_SESSION_TIMEOUT`: Set session timeout in seconds (default: 1800)

---

For more details, see the built-in guide: `journaler --guide`
