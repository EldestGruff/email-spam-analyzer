# iCloud Email Spam Analyzer

Interactive terminal-based tool for reviewing and managing email spam in iCloud Mail accounts.

## Features

- **IMAP Connection**: Connects to iCloud Mail via IMAP
- **Spam Analysis**: Scores emails based on marketing indicators, suspicious domains, spam keywords, etc.
- **Interactive Review**: Review each email with spam score and reasoning
- **Body Preview**: See email content before making decisions
- **Smart Actions**:
  - Mark as spam (moves to Junk folder for iCloud to learn)
  - Unsubscribe + Delete (opens unsubscribe link in browser, then deletes)
  - Keep (leaves unread)
  - View full email body

## Setup

1. Generate an app-specific password for iCloud Mail
2. Store it in `~/.icloud_pass_temp`
3. Run: `python3 get_mail.py`

## Usage

```bash
python3 get_mail.py
```

Follow the prompts to:
1. Enter your iCloud email address (default: paf@fennerfam.com)
2. Review emails one by one
3. Choose an action: [S]pam, [U]nsubscribe+Delete, [K]eep, [V]iew full, [Q]uit

## Roadmap

- [ ] Multi-folder support (review emails from multiple folders)
- [ ] Multiple email address support
- [ ] Unread-only filtering
- [ ] Better spam detection rules
- [ ] Learning from user decisions

## Files

- `get_mail.py` - Main script
- `.icloud_pass_temp` - App-specific password (DO NOT COMMIT)
