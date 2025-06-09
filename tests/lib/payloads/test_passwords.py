from collections import Counter
from pathlib import Path

import pytest

top_1000_common_passwords_path = Path(
    "nettacker/lib/payloads/passwords/top_1000_common_passwords.txt"
)
nettacker_path = Path(__file__).parent.parent.parent.parent


@pytest.mark.xfail(reason="It currently contains 1001 passwords.")
def test_top_1000_common_passwords():
    full_path = nettacker_path / top_1000_common_passwords_path
    with open(full_path) as f:
        top_1000_passwords = [line.strip() for line in f.readlines()]

    assert len(top_1000_passwords) == 1000, "There should be exactly 1000 passwords"

    assert len(set(top_1000_passwords)) == len(
        top_1000_passwords
    ), f"The passwords aren't unique: {Counter(top_1000_passwords).most_common(1)[0][0]}"
