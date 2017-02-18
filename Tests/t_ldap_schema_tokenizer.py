"""
test module ldap.schema.tokenizer
"""

import unittest

import ldap.schema

# basic test cases
TESTCASES_BASIC = (
    (" BLUBBER DI BLUBB ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER DI BLUBB", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER  DI   BLUBB  ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER  DI  'BLUBB'   ", ["BLUBBER", "DI", "BLUBB"]),
    ("BLUBBER ( DI ) 'BLUBB'   ", ["BLUBBER", "(", "DI", ")", "BLUBB"]),
    ("BLUBBER(DI)", ["BLUBBER", "(", "DI", ")"]),
    ("BLUBBER ( DI)", ["BLUBBER", "(", "DI", ")"]),
    ("BLUBBER ''", ["BLUBBER", ""]),
    ("( BLUBBER (DI 'BLUBB'))", ["(", "BLUBBER", "(", "DI", "BLUBB", ")", ")"]),
    ("BLUBB (DA$BLAH)", ['BLUBB', "(", "DA", "BLAH", ")"]),
    ("BLUBB ( DA $  BLAH )", ['BLUBB', "(", "DA", "BLAH", ")"]),
    ("BLUBB (DA$ BLAH)", ['BLUBB', "(", "DA", "BLAH", ")"]),
    ("BLUBB (DA $BLAH)", ['BLUBB', "(", "DA", "BLAH", ")"]),
    ("BLUBB 'DA$BLAH'", ['BLUBB', "DA$BLAH"]),
    ("BLUBB DI 'BLU B B ER' DA 'BLAH' ", ['BLUBB', 'DI', 'BLU B B ER', 'DA', 'BLAH']),
    ("BLUBB DI 'BLU B B ER' DA 'BLAH' LABER", ['BLUBB', 'DI', 'BLU B B ER', 'DA', 'BLAH', 'LABER']),
)

# broken schema of Oracle Internet Directory
TESTCASES_BROKEN_OID = (
    ("BLUBBER DI 'BLU'BB ER' DA 'BLAH' ", ["BLUBBER", "DI", "BLU'BB ER", "DA", "BLAH"]),
    ("BLUBB DI 'BLU B B ER'MUST 'BLAH' ", ['BLUBB', 'DI', 'BLU B B ER', 'MUST', 'BLAH'])
)

# for quoted single quotes inside string values
TESTCASES_ESCAPED_QUOTES = (
    ("BLUBBER DI 'BLU\'BB ER' DA 'BLAH' ", ["BLUBBER", "DI", "BLU'BB ER", "DA", "BLAH"]),
)


class TestSplitTokens(unittest.TestCase):
    """
    test function ldap.schema.tokenizer.split_tokens()
    """

    def _run_split_tokens_tests(self, test_cases):
        for test_value, test_result in test_cases:
            token_list = ldap.schema.split_tokens(test_value)
            self.assertEqual(token_list, test_result)

    def test_basic(self):
        """
        run test cases specified in constant TESTCASES_BASIC
        """
        self._run_split_tokens_tests(TESTCASES_BASIC)

    @unittest.expectedFailure
    def test_broken_oid(self):
        """
        run test cases specified in constant TESTCASES_BROKEN_OID
        """
        self._run_split_tokens_tests(TESTCASES_BROKEN_OID)

    @unittest.expectedFailure
    def test_escaped_quotes(self):
        """
        run test cases specified in constant TESTCASES_ESCAPED_QUOTES
        """
        self._run_split_tokens_tests(TESTCASES_ESCAPED_QUOTES)


if __name__ == '__main__':
    unittest.main()
