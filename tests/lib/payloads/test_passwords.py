from collections import Counter
import pytest
from tests.test_common import TestCase

class TestPasswords(TestCase):

    def setUp(self):
        super().setUp()  # Call parent setup to ensure nettacker_path is set
        self.top_1000_common_passwords_path = self.nettacker_path / "lib" / "payloads" / "passwords" / "top_1000_common_passwords.txt"

    @pytest.mark.xfail(reason="It currently contains 1001 passwords.")
    def test_top_1000_common_passwords(self):
        with open(self.top_1000_common_passwords_path) as top_1000_file:
            top_1000_passwords = [line.strip() for line in top_1000_file.readlines()]

        self.assertEqual(len(top_1000_passwords), 1000, "There should be exactly 1000 passwords")

        self.assertEqual(
            len(set(top_1000_passwords)),
            len(top_1000_passwords),
            f"The passwords aren't unique: {Counter(top_1000_passwords).most_common(1)[0][0]}",
        )
