"""Create or update a teacher account for the activities application."""

import getpass
import hashlib
import json
import os
from pathlib import Path

TEACHERS_FILE = Path(__file__).with_name("teachers.json")
PASSWORD_HASH_ITERATIONS = 600_000


def main():
    username = input("Teacher username: ").strip()
    if not username:
        raise SystemExit("Username must not be empty.")

    password = getpass.getpass("Teacher password (at least 12 characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must be at least 12 characters long.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    if TEACHERS_FILE.exists():
        data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("teachers"), list):
            raise SystemExit("Existing teacher credentials file has an invalid format.")
    else:
        data = {"teachers": []}

    teachers = data["teachers"]
    existing = next(
        (teacher for teacher in teachers if teacher.get("username") == username),
        None,
    )
    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    new_teacher = {
        "username": username,
        "salt": salt.hex(),
        "password_hash": password_hash.hex(),
    }
    if existing:
        teachers[teachers.index(existing)] = new_teacher
    else:
        teachers.append(new_teacher)

    TEACHERS_FILE.write_text(
        json.dumps(data, indent=2) + "\n",
        encoding="utf-8",
    )
    TEACHERS_FILE.chmod(0o600)
    print(f"Teacher account '{username}' saved to {TEACHERS_FILE}.")


if __name__ == "__main__":
    main()
