import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


import unittest
import json
import pprint

import pyipttool.ipt
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

    def test_dump_blocks(self):
        pt_filename = r'notepad\trace.pt'
        dump_filename = r'notepad\notepad.exe.dmp'
        dump_symbols = False
        start_offset = 0x13aba74
        end_offset = 0x13adb4f
        block_offset = 0x13ada69
        ptlog_analyzer = pyipttool.ipt.Analyzer(dump_filename, 
                                         dump_symbols = dump_symbols, 
                                         load_image = True,
                                         debug_level = 1)

        ptlog_analyzer.open_ipt_log(pt_filename, start_offset = start_offset, end_offset = end_offset)

        # block.ip: 00007ffbb49de260 ~ 00007ffbb49de291 (000000000000000b)
        expected_ip = 0x00007ffbb49de260
        expected_end_ip = 0x00007ffbb49de291
        expected_ninsn = 0x000000000000000b
        for block in ptlog_analyzer.decode_blocks(offset = block_offset):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
            self.assertEqual(expected_ip, block.ip)
            self.assertEqual(expected_end_ip, block.end_ip)
            self.assertEqual(expected_ninsn, block.ninsn)

if __name__ == '__main__':
    unittest.main()
