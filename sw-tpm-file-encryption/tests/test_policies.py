import unittest

from src.errors import AppError
from src.policies import PolicyName, parse_pcrs, validate_policy_inputs


class PolicyTests(unittest.TestCase):
    def test_password_policy_requires_auth(self):
        with self.assertRaisesRegex(AppError, "requires --auth"):
            validate_policy_inputs("password", auth=None, pcrs=None)

    def test_pcr_policy_requires_pcr_selection(self):
        with self.assertRaisesRegex(AppError, "requires --pcrs"):
            validate_policy_inputs("pcr", auth=None, pcrs=None)

    def test_pcr_policy_accepts_comma_separated_pcrs(self):
        policy = validate_policy_inputs("pcr", auth=None, pcrs="7, 16")

        self.assertEqual(policy, PolicyName.PCR)
        self.assertEqual(parse_pcrs("7, 16"), [7, 16])

    def test_pcr_policy_rejects_invalid_pcr_index(self):
        with self.assertRaisesRegex(AppError, "PCR indexes must be between 0 and 23"):
            parse_pcrs("24")


if __name__ == "__main__":
    unittest.main()
