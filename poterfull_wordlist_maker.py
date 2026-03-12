import random

MAX_PASSWORDS = 1000000
MIN_LEN = 6
MAX_LEN = 19

logo = r"""
==========================================
        POWER WORDLIST GENERATOR
==========================================
 Generate custom password wordlists
 Python Tool
==========================================
"""

print(logo)


def get_input(text):
    value = input(text + " (press enter for none): ").strip()
    if value == "":
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


print("\nEnter information (use , for multiple words)\n")

v_name = get_input("Victim Name")
v_number = get_input("V.number")
v_dob = get_input("V.dob")
v_father = get_input("V.fathername")
v_mother = get_input("V.mothername")
v_sister = get_input("V.sistername")
v_brother = get_input("V.brothername")
v_gf = get_input("V.gfname")
v_gfdob = get_input("V.gfdob")
v_surname = get_input("V.surname")
v_gfsurname = get_input("V.gfsurname")
custom_words = get_input("Custom words")
special_chars = get_input("Special characters")
special_numbers = get_input("Special numbers")

wordlist_name = input("\nName of wordlist file: ").strip()
if wordlist_name == "":
    wordlist_name = "wordlist"

# combine base words
base_words = (
    v_name + v_number + v_dob + v_father + v_mother +
    v_sister + v_brother + v_gf + v_gfdob +
    v_surname + v_gfsurname + custom_words
)

base_words = list(set(base_words))

if len(base_words) == 0:
    print("\nError: You must enter at least one base word.")
    exit()

passwords = set()

print("\nGenerating passwords...\n")

while len(passwords) < MAX_PASSWORDS:

    w1 = random.choice(base_words)
    w2 = random.choice(base_words)

    char = random.choice(special_chars) if special_chars else ""
    num = random.choice(special_numbers) if special_numbers else ""

    patterns = [
        w1 + w2,
        w1 + num,
        w1 + char + num,
        w1 + num + char,
        w1 + char + w2,
        num + w1,
        w1 + w2 + num,
        w1 + char + w2 + num
    ]

    password = random.choice(patterns)

    if MIN_LEN <= len(password) <= MAX_LEN:

        # case variations
        passwords.add(password.lower())
        passwords.add(password.capitalize())
        passwords.add(password.upper())

    if len(passwords) >= MAX_PASSWORDS:
        break

print("Generated:", len(passwords), "passwords")

file_name = wordlist_name + ".txt"

with open(file_name, "w", encoding="utf-8") as f:
    for p in passwords:
        f.write(p + "\n")

print("\nWordlist saved to:", file_name)
print("Done!")