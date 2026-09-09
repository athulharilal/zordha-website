#!/usr/bin/env python3
"""
Secure Password Generator
-------------------------
A versatile and cryptographically secure password generation tool.
Supports custom length, character set filters, strength evaluation,
and both CLI argument and interactive modes.
"""

import argparse
import math
import secrets
import string
import sys


# Configure UTF-8 encoding for standard output if available
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# Character sets
UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
AMBIGUOUS_CHARS = "l1IO0o"


def calculate_entropy(password: str, charset_size: int) -> float:
    """Calculate Shannon entropy (bits of security) for the password."""
    if not password or charset_size <= 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def assess_strength(entropy: float) -> str:
    """Provide a human-readable strength rating based on entropy bits."""
    if entropy < 28:
        return "[Very Weak]"
    elif entropy < 36:
        return "[Weak]"
    elif entropy < 60:
        return "[Reasonable]"
    elif entropy < 128:
        return "[Strong]"
    else:
        return "[Very Strong / Cryptographic]"


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_chars: str = "",
) -> tuple[str, float]:
    """
    Generate a cryptographically secure random password.
    
    Guarantees at least one character from each selected set is included
    when length is sufficient.
    """
    if custom_chars:
        pool = custom_chars
        required_chars = []
    else:
        pool = ""
        required_chars = []

        upper_set = UPPERCASE
        lower_set = LOWERCASE
        digit_set = DIGITS
        symbol_set = SYMBOLS

        if exclude_ambiguous:
            upper_set = "".join(c for c in upper_set if c not in AMBIGUOUS_CHARS)
            lower_set = "".join(c for c in lower_set if c not in AMBIGUOUS_CHARS)
            digit_set = "".join(c for c in digit_set if c not in AMBIGUOUS_CHARS)
            symbol_set = "".join(c for c in symbol_set if c not in AMBIGUOUS_CHARS)

        if use_upper:
            pool += upper_set
            required_chars.append(secrets.choice(upper_set))
        if use_lower:
            pool += lower_set
            required_chars.append(secrets.choice(lower_set))
        if use_digits:
            pool += digit_set
            required_chars.append(secrets.choice(digit_set))
        if use_symbols:
            pool += symbol_set
            required_chars.append(secrets.choice(symbol_set))

    if not pool:
        raise ValueError("Error: Character pool is empty. Please enable at least one character category.")

    if length < len(required_chars):
        raise ValueError(f"Password length ({length}) is too short to include all selected character types ({len(required_chars)}).")

    # Fill remaining characters randomly from pool
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(pool) for _ in range(remaining_length)]

    # Cryptographically secure shuffle using Fisher-Yates
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    password = "".join(password_chars)
    entropy = calculate_entropy(password, len(set(pool)))
    return password, entropy


def interactive_mode():
    """Prompt the user interactively to configure password generation."""
    print("=" * 50)
    print("       🔐 SECURE PASSWORD GENERATOR 🔐")
    print("=" * 50)

    try:
        raw_len = input("Enter password length [default 16]: ").strip()
        length = int(raw_len) if raw_len else 16
        if length <= 0:
            print("Length must be positive. Defaulting to 16.")
            length = 16

        def ask_bool(prompt_text: str, default: bool = True) -> bool:
            hint = "[Y/n]" if default else "[y/N]"
            ans = input(f"{prompt_text} {hint}: ").strip().lower()
            if not ans:
                return default
            return ans in ("y", "yes", "1", "true")

        use_upper = ask_bool("Include uppercase letters (A-Z)?", True)
        use_lower = ask_bool("Include lowercase letters (a-z)?", True)
        use_digits = ask_bool("Include numbers (0-9)?", True)
        use_symbols = ask_bool("Include special symbols (!@#$...)?", True)
        exclude_ambiguous = ask_bool("Exclude ambiguous characters (l, 1, I, O, 0)?", False)

        raw_count = input("How many passwords to generate? [default 1]: ").strip()
        count = int(raw_count) if raw_count else 1
        count = max(1, count)

        print("\n" + "-" * 50)
        print("Generated Password(s):")
        print("-" * 50)

        for i in range(count):
            pwd, entropy = generate_password(
                length=length,
                use_upper=use_upper,
                use_lower=use_lower,
                use_digits=use_digits,
                use_symbols=use_symbols,
                exclude_ambiguous=exclude_ambiguous,
            )
            strength = assess_strength(entropy)
            if count > 1:
                print(f"[{i+1}] {pwd}")
                print(f"    Entropy: {entropy:.1f} bits | Strength: {strength}")
            else:
                print(f"Password : {pwd}")
                print(f"Entropy  : {entropy:.1f} bits")
                print(f"Strength : {strength}")
        print("=" * 50)

    except (ValueError, KeyboardInterrupt) as err:
        print(f"\n{err}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate cryptographically secure passwords with custom rules and entropy analysis."
    )
    parser.add_argument("-l", "--length", type=int, default=16, help="Length of the password (default: 16)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Exclude numbers")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude special symbols")
    parser.add_argument("-a", "--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (l, 1, I, O, 0)")
    parser.add_argument("--custom", type=str, default="", help="Use custom character pool only")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive wizard mode")
    parser.add_argument("-q", "--quiet", action="store_true", help="Only output raw passwords (useful for scripts)")

    args = parser.parse_args()

    # If user ran without args or explicitly requested interactive
    if len(sys.argv) == 1 or args.interactive:
        interactive_mode()
        return

    try:
        for i in range(args.count):
            pwd, entropy = generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_lower=not args.no_lower,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                exclude_ambiguous=args.exclude_ambiguous,
                custom_chars=args.custom,
            )
            if args.quiet:
                print(pwd)
            else:
                strength = assess_strength(entropy)
                if args.count > 1:
                    print(f"[{i+1}] {pwd}  (Entropy: {entropy:.1f} bits | {strength})")
                else:
                    print(f"Password : {pwd}")
                    print(f"Length   : {len(pwd)}")
                    print(f"Entropy  : {entropy:.1f} bits")
                    print(f"Strength : {strength}")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
