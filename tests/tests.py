import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


import unittest
import json
import pprint

import pyipttool.coverage

class Tests(unittest.TestCase):
    def test_coverage(self):
        disasm = pyipttool.coverage.Disasm(base_address = 0x400000, filename = r'coverage\00400000.dmp')

        with open(r'coverage\coverage.json') as fd:
            coverage_data_list = json.load(fd)

        for coverage_data in coverage_data_list:
            instructions = []
            for instruction in disasm.trace(coverage_data['start_address'], coverage_data['end_address']):
                instructions.append({'address': instruction.address, 'mnemonic': instruction.mnemonic, 'op_str': instruction.op_str})
                    
            self.assertEqual(instructions, coverage_data['instructions'])

if __name__ == '__main__':
    unittest.main()
