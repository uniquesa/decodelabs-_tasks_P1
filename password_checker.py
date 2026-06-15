"""
DecodeLabs - Cyber Security Project 1
Password Strength Checker
Author: Nazar Sheikh | Batch 2026
"""

import re
import hmac


# Common/leaked passwords list (bonus feature as suggested in PDF)
COMMON_PASSWORDS = {
    "password", "123456", "password123", "12345678", "qwerty",
    "abc123", "111111", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess",
    "passw0rd", "iloveyou", "superman", "batman", "football"
}

SYMBOLS = set("!@#$%^&*()_+-=[]{}|;':\",./<>?")


def check_password_strength(password: str) -> dict:
    """
    Evaluates password strength based on DecodeLabs security policy.
    
    Returns:
        dict with keys: strength, score, feedback, checks
    """
    checks = {
        "length_ok":    len(password) >= 8,
        "has_upper":    any(c.isupper() for c in password),
        "has_lower":    any(c.islower() for c in password),
        "has_digit":    any(c.isdigit() for c in password),   # Pythonic: any() with short-circuit
        "has_symbol":   any(c in SYMBOLS for c in password),
        "not_common":   password.lower() not in COMMON_PASSWORDS,
        "length_strong": len(password) >= 12,
    }

    feedback = []

    # --- GATEKEEPER RULE: length < 8 = immediate fail ---
    if not checks["length_ok"]:
        return {
            "strength": "WEAK",
            "score": 0,
            "feedback": ["Password must be at least 8 characters (IMMEDIATE FAIL — brute force risk)"],
            "checks": checks
        }

    # --- Collect feedback for missing criteria ---
    if not checks["has_upper"]:
        feedback.append("Add uppercase letters [A-Z]")
    if not checks["has_lower"]:
        feedback.append("Add lowercase letters [a-z]")
    if not checks["has_digit"]:
        feedback.append("Add numbers [0-9]")
    if not checks["has_symbol"]:
        feedback.append("Add symbols [!@#$%^&*...]")
    if not checks["not_common"]:
        feedback.append("This is a commonly leaked password — change it immediately!")
    if not checks["length_strong"]:
        feedback.append("Use 12+ characters for stronger entropy")

    # --- Score calculation ---
    score = sum([
        checks["length_ok"],
        checks["has_upper"],
        checks["has_lower"],
        checks["has_digit"],
        checks["has_symbol"],
        checks["not_common"],
        checks["length_strong"],
    ])

    # --- Strength classification ---
    # STRONG: all core criteria met (length>=8, upper, lower, digit, symbol, not_common)
    core_passed = all([
        checks["length_ok"], checks["has_upper"], checks["has_lower"],
        checks["has_digit"], checks["has_symbol"], checks["not_common"]
    ])

    if not checks["not_common"] or score <= 2:
        strength = "WEAK"
    elif core_passed:
        strength = "STRONG"
    else:
        strength = "MEDIUM"

    if not feedback:
        feedback.append("All checks passed! Password is strong.")

    return {
        "strength": strength,
        "score": score,
        "feedback": feedback,
        "checks": checks
    }


def display_result(password: str, result: dict):
    """Displays the password strength report."""
    
    bar_colors = {
        "WEAK":   "🔴",
        "MEDIUM": "🟡",
        "STRONG": "🟢"
    }

    print("\n" + "=" * 50)
    print("  DecodeLabs | Password Strength Checker 🔐")
    print("=" * 50)
    print(f"  Strength : {bar_colors[result['strength']]} {result['strength']}")
    print(f"  Score    : {result['score']} / 7")
    print("-" * 50)
    print("  Security Checks:")
    checks = result["checks"]
    print(f"    {'✅' if checks['length_ok']     else '❌'} Length >= 8 chars")
    print(f"    {'✅' if checks['length_strong'] else '❌'} Length >= 12 chars (recommended)")
    print(f"    {'✅' if checks['has_upper']     else '❌'} Uppercase letters [A-Z]")
    print(f"    {'✅' if checks['has_lower']     else '❌'} Lowercase letters [a-z]")
    print(f"    {'✅' if checks['has_digit']     else '❌'} Digits [0-9]")
    print(f"    {'✅' if checks['has_symbol']    else '❌'} Symbols [!@#$%...]")
    print(f"    {'✅' if checks['not_common']    else '❌'} Not a common/leaked password")
    print("-" * 50)
    print("  Feedback:")
    for tip in result["feedback"]:
        print(f"    → {tip}")
    print("=" * 50 + "\n")


def main():
    print("\n🛡  DecodeLabs Cyber Security — Project 1")
    print("    Password Strength Checker | Batch 2026\n")

    while True:
        password = input("Enter password to check (or 'quit' to exit): ")

        if password.lower() == "quit":
            print("\n  Exiting... Stay secure! 🔐\n")
            break

        if not password:
            print("  ⚠  Please enter a password.\n")
            continue

        result = check_password_strength(password)
        display_result(password, result)


if __name__ == "__main__":
    main()
