import re
import secrets
import string


def check_password_strength(password):
    score = 0
    suggestions = []

    # Check length
    length = len(password)

    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
        suggestions.append("Use at least 12 characters.")
    else:
        suggestions.append("Password should be at least 12 characters long.")

    # Check lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    # Check uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    # Check numbers
    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    # Check special characters
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Add special characters such as @, #, $, or !.")

    # Check repeated characters
    if re.search(r"(.)\1\1", password):
        score -= 1
        suggestions.append("Avoid repeating the same character multiple times.")

    # Check common/weak passwords
    common_passwords = {
        "password",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "qwerty123",
        "admin",
        "admin123",
        "letmein",
        "welcome",
        "iloveyou"
    }

    if password.lower() in common_passwords:
        score = 0
        suggestions.append("Avoid common passwords.")

    # Check sequential characters
    sequences = [
        "123456",
        "abcdef",
        "qwerty",
        "987654",
        "654321"
    ]

    if any(sequence in password.lower() for sequence in sequences):
        score -= 1
        suggestions.append("Avoid predictable sequences such as 123456 or abcdef.")

    # Check uniqueness
    unique_characters = len(set(password))

    if length > 0 and unique_characters / length < 0.5:
        score -= 1
        suggestions.append("Use more different characters.")

    # Keep score within range
    score = max(0, min(score, 6))

    # Strength level
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return score, strength, suggestions


def generate_strong_password(length=16):
    if length < 12:
        length = 12

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    special = "!@#$%^&*"

    # Make sure the password contains every required type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(numbers),
        secrets.choice(special)
    ]

    all_characters = lowercase + uppercase + numbers + special

    for _ in range(length - 4):
        password.append(secrets.choice(all_characters))

    # Securely shuffle the password
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


def main():
    print("=" * 50)
    print("       PASSWORD STRENGTH ANALYZER")
    print("=" * 50)

    password = input("\nEnter your password: ")

    score, strength, suggestions = check_password_strength(password)

    print("\nPassword Analysis")
    print("-" * 30)
    print("Length       :", len(password))
    print("Score        :", score, "/ 6")
    print("Strength     :", strength)

    if strength == "WEAK":
        print("\nSuggestions:")
        for suggestion in suggestions:
            print("- " + suggestion)

        print("\nSuggested Strong Password:")
        print(generate_strong_password())

    elif strength == "MEDIUM":
        print("\nSuggestions:")
        for suggestion in suggestions:
            print("- " + suggestion)

        print("\nStronger Password Suggestion:")
        print(generate_strong_password())

    else:
        print("\nYour password is strong!")
        print("Keep it private and do not reuse it on multiple websites.")


if __name__ == "__main__":
    main()