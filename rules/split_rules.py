# split_rules.py  — run once when you update your rules
import re, os

CATEGORIES = {
    "ransomware":  ["RANSOMWARE", "RANSOM"],
    "trojans":     ["TROJAN"],
    "backdoors":   ["BACKDOOR"],
    "webshells":   ["WEBSHELL"],
    "cryptominers":["MINER", "CRYPTOMINER"],
    "apt":         ["APT"],
    "spyware":     ["STEALER", "SPYWARE", "SPY"],
}

def get_category(rule_text):
    name_match = re.search(r'rule\s+(\w+)', rule_text)
    name = name_match.group(1).upper() if name_match else ""
    tags_match = re.search(r'rule\s+\w+\s*:\s*([\w\s]+)\{', rule_text)
    tags = tags_match.group(1).upper() if tags_match else ""
    combined = name + " " + tags
    for category, keywords in CATEGORIES.items():
        if any(kw in combined for kw in keywords):
            return category
    return "other"

with open("yara-rules-core.yar") as f:
    content = f.read()

# Split on rule boundaries, keep imports at top
rules = re.split(r'(?=\nrule )', content)
header = rules[0]  # imports and file header

buckets = {cat: [header] for cat in list(CATEGORIES.keys()) + ["other"]}

for rule in rules[1:]:
    cat = get_category(rule)
    buckets[cat].append(rule)

os.makedirs("rules", exist_ok=True)
for cat, parts in buckets.items():
    if len(parts) > 1:  # only write if has actual rules
        with open(f"rules/{cat}.yar", "w") as f:
            f.write("\n".join(parts))
        print(f"rules/{cat}.yar — {len(parts)-1} rules")