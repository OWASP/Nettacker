from collections import Counter
from pathlib import Path

nettacker_path = Path(__file__).parent.parent.parent.parent


def test_top_1000_common_passwords():
    top_1000_passwords_file_path = (
        nettacker_path / "nettacker/lib/payloads/passwords/top_1000_common_passwords.txt"
    )
    with open(top_1000_passwords_file_path) as f:
        top_1000_passwords = [line.strip() for line in f.readlines() if line.strip()]

    assert len(top_1000_passwords) == 1000, "There should be exactly 1000 passwords"

    assert len(set(top_1000_passwords)) == len(
        top_1000_passwords
    ), f"The passwords aren't unique: {Counter(top_1000_passwords).most_common(1)[0][0]}"
