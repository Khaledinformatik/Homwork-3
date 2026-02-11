#!/usr/bin/env python3
import hashlib
import base64
import time


def crack_password():
    # --- 1. Targeted Data Setup ---
    # The target hash provided in the assignment (Base64 format)
    target_b64 = "8yQ28QbbPQYfvpta2FBSgsZTGZlFdVYMhn7ePNbaKV8="

    # Decode Base64 to raw bytes for direct binary comparison (more efficient)
    try:
        target_hash = base64.b64decode(target_b64)
    except Exception as e:
        print(f"[!] Error decoding target Base64: {e}")
        return

    # Dictionary file name
    dictionary_file = "Dictionary.txt"

    attempts = 0
    found = False
    start_time = time.time()

    print(f"[*] Starting Offline Dictionary Attack...")
    print(f"[*] Target Hash: {target_b64}")
    print(f"[*] Algorithm: SHA3-256")
    print("-" * 50)

    # --- 2. Dictionary Search Loop ---
    try:
        # Open file with 'errors=ignore' to handle any non-UTF8 characters in the list
        with open(dictionary_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:

                password = line.strip()
                if not password:
                    continue

                attempts += 1

                # Step 1: Encode password string to UTF-8 bytes
                data = password.encode("utf-8")

                # Step 2: Compute SHA3-256 digest
                digest = hashlib.sha3_256(data).digest()

                # Step 3: Compare with the target hash
                if digest == target_hash:
                    elapsed_time = time.time() - start_time
                    print(f"[+] SUCCESS!")
                    print(f"[+] Password found: {password}")
                    print(f"[+] Total attempts: {attempts}")
                    print(f"[+] Time taken: {elapsed_time:.4f} seconds")
                    found = True
                    break

    except FileNotFoundError:
        print(f"[!] Error: The file '{dictionary_file}' was not found in the current directory.")
        return

    # --- 3. Result Reporting ---
    if not found:
        elapsed_time = time.time() - start_time
        print("[-] Failure: Password not found in the provided dictionary.")
        print(f"[-] Total attempts made: {attempts}")
        print(f"[-] Time spent: {elapsed_time:.4f} seconds")


if __name__ == "__main__":
    crack_password()