# Password Generator

A cryptographically secure Python script to generate high-entropy passwords.

## Features

- **Cryptographically Secure**: Built with Python's `secrets` module (safe for sensitive accounts).
- **Customizable**: Control password length, character sets (uppercase, lowercase, digits, symbols), or provide your own custom character set.
- **Ambiguity Filter**: Option to omit easily confused characters (`l`, `1`, `I`, `O`, `0`).
- **Strength & Entropy Analysis**: Calculates Shannon entropy bits and rates the password strength.
- **Dual Mode**:
  - **Interactive Mode**: Guided prompt when run with no flags or with `-i`.
  - **CLI Flags Mode**: Fast, scriptable generation with command-line arguments.

---

## Usage

### 1. Interactive Mode
Run without any arguments to launch the guided wizard:
```bash
python password_generator.py
```

### 2. Command-Line Arguments
```bash
# Generate a single 20-character password
python password_generator.py -l 20

# Generate 5 passwords of length 16
python password_generator.py -l 16 -c 5

# Generate passwords excluding ambiguous characters
python password_generator.py -l 18 -a

# Generate alphanumeric password without special symbols
python password_generator.py -l 16 --no-symbols

# Output only the raw password (useful for shell scripting/piping)
python password_generator.py -l 24 -q
```

### 3. CLI Options Reference

| Option | Shorthand | Description | Default |
|---|---|---|---|
| `--length` | `-l` | Length of the password | `16` |
| `--count` | `-c` | Number of passwords to generate | `1` |
| `--no-upper` | | Exclude uppercase letters (`A-Z`) | `False` |
| `--no-lower` | | Exclude lowercase letters (`a-z`) | `False` |
| `--no-digits` | | Exclude numbers (`0-9`) | `False` |
| `--no-symbols` | | Exclude special characters (`!@#$...`) | `False` |
| `--exclude-ambiguous`| `-a` | Exclude `l`, `1`, `I`, `O`, `0` | `False` |
| `--custom` | | Provide a custom character pool | `""` |
| `--interactive` | `-i` | Force interactive prompt wizard | `False` |
| `--quiet` | `-q` | Output raw password string only | `False` |
