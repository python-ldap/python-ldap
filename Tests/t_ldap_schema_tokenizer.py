import unittest

import ldap.schema
from ldap.schema.tokenizer import split_tokens,extract_tokens

class TestTokenize(unittest.TestCase):
    testcases_split_tokens = (
        (" BLUBBER DI BLUBB ", ["BLUBBER", "DI", "BLUBB"]),
        ("BLUBBER DI BLUBB",["BLUBBER","DI","BLUBB"]),
        ("BLUBBER  DI   BLUBB  ",["BLUBBER","DI","BLUBB"]),
        ("BLUBBER  DI  'BLUBB'   ",["BLUBBER","DI","BLUBB"]),
        ("BLUBBER ( DI ) 'BLUBB'   ",["BLUBBER","(","DI",")","BLUBB"]),
        ("BLUBBER(DI)",["BLUBBER","(","DI",")"]),
        ("BLUBBER ( DI)",["BLUBBER","(","DI",")"]),
        ("BLUBBER ''",["BLUBBER",""]),
        ("( BLUBBER (DI 'BLUBB'))",["(","BLUBBER","(","DI","BLUBB",")",")"]),
        ("BLUBB (DA$BLAH)",['BLUBB',"(","DA","BLAH",")"]),
        ("BLUBB ( DA $  BLAH )",['BLUBB',"(","DA","BLAH",")"]),
        ("BLUBB (DA$ BLAH)",['BLUBB',"(","DA","BLAH",")"]),
        ("BLUBB (DA $BLAH)",['BLUBB',"(","DA","BLAH",")"]),
        ("BLUBB 'DA$BLAH'",['BLUBB',"DA$BLAH"]),
        ("BLUBB DI 'BLU B B ER' DA 'BLAH' ",['BLUBB','DI','BLU B B ER','DA','BLAH']),
        ("BLUBB DI 'BLU B B ER' DA 'BLAH' LABER",['BLUBB','DI','BLU B B ER','DA','BLAH','LABER']),

        #("BLUBBER DI 'BLU'BB ER' DA 'BLAH' ", ["BLUBBER", "DI", "BLU'BB ER", "DA", "BLAH"]), # for Oracle
        #("BLUBB DI 'BLU B B ER'MUST 'BLAH' ",['BLUBB','DI','BLU B B ER','MUST','BLAH']) # for Oracle
    )

    def test_split_tokens(self):
        for t, r in self.testcases_split_tokens:
            l = ldap.schema.tokenizer.split_tokens(t, {'MUST':None})
            self.assertEqual(l, r)


if __name__ == '__main__':
    unittest.main()
