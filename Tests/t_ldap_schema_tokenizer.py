"""
test module ldap.schema.tokenizer
"""

import unittest

import ldap.schema

# all basic test cases
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
# for broken schema of Oracle Internet Directory
TESTCASES_OID = (
    ("BLUBBER DI 'BLU'BB ER' DA 'BLAH' ", ["BLUBBER", "DI", "BLU'BB ER", "DA", "BLAH"]),
    ("BLUBB DI 'BLU B B ER'MUST 'BLAH' ", ['BLUBB', 'DI', 'BLU B B ER', 'MUST', 'BLAH'])
)


class TestSplitTokens(unittest.TestCase):
    """
    test function ldap.schema.tokenizer.split_tokens()
    """

    def _run_split_tokens_tests(self, test_cases):
        for test_value, test_result in test_cases:
            token_list = ldap.schema.tokenizer.split_tokens(test_value, None)
            self.assertEqual(token_list, test_result)

    def test_basic(self):
        """
        run test cases specified in constant TESTCASES_BASIC
        """
        self._run_split_tokens_tests(TESTCASES_BASIC)

    @unittest.expectedFailure
    def test_oid(self):
        """
        run test cases specified in constant TESTCASES_OID
        """
        self._run_split_tokens_tests(TESTCASES_OID)


if __name__ == '__main__':
    unittest.main()
