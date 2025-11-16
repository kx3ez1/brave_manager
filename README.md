
# Brave Manager

Brave Manager is a command-line tool for securely managing multiple encrypted Brave browser profiles. Each profile is password-protected and stored in an encrypted format, allowing you to safely separate work, personal, and other browsing contexts.

## Features

- Create, launch, and manage multiple Brave browser profiles
- Each profile is encrypted with a password using strong AES-GCM encryption
- Profiles are stored as encrypted archives on disk
- Easily switch between profiles without mixing browsing data
- Change profile passwords, rename, or delete profiles
- Interactive and command-line modes for locking and managing profiles

## Installation

1. **Clone or copy the script** to your machine.
2. Install dependencies (preferably in a virtual environment):
	 ```bash
	 pip install -r requirements.txt
	 ```
3. Ensure Brave Browser is installed and the command in the script (`BRAVE_COMMAND`) matches your system. Default is `brave-browser-nightly` (edit if needed).

## Usage

Run the script with Python 3:

```bash
python brave-manager.py [OPTIONS]
```

### Common Commands

- **Launch or create a profile:**
	```bash
	python brave-manager.py -P work
	```
	(Creates or unlocks the 'work' profile)

- **List all profiles:**
	```bash
	python brave-manager.py -L
	```

- **Lock a running profile:**
	```bash
	python brave-manager.py -k work
	```
	(Or run with `-k` for an interactive menu)

- **Delete a profile:**
	```bash
	python brave-manager.py -D work
	```

- **Change a profile password:**
	```bash
	python brave-manager.py -U work
	```

- **Rename a profile:**
	```bash
	python brave-manager.py -R oldname newname
	```

- **Delete all profiles:**
	```bash
	python brave-manager.py --delete-all
	```

### Example

```bash
python brave-manager.py -P personal
```
This will prompt for a password and launch Brave with a new or existing encrypted profile called 'personal'.

## Security Notes

- All profile data is encrypted with your password. **If you forget your password, your profile cannot be recovered.**
- Passwords are never stored or logged.
- Temporary decrypted data is cleaned up after each session.

## Requirements

- Python 3.7+
- [cryptography](https://pypi.org/project/cryptography/)
- [psutil](https://pypi.org/project/psutil/) (optional, for some advanced features)
- Brave Browser installed and accessible via command line

## Troubleshooting

- If the script cannot find Brave, edit the `BRAVE_COMMAND` variable in `brave-manager.py` to match your system's Brave executable.
- If a profile is not cleaned up properly (e.g., after a crash), you may need to lock or clean it manually using the provided options.

## License

MIT License. See source code for details.

