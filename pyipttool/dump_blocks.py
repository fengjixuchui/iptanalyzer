import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pickle
import pprint
import copy
import logging
from zipfile import ZipFile
from datetime import datetime, timedelta

import pyipttool.ipt
import capstone

class Coverage:
    def __init__(self, module_name, start_address, end_address, pt_filename, dump_filename, debugger):
        self.module_name = module_name
        self.pt_filename = pt_filename
        self.dump_filename = dump_filename
        self.start_address = start_address
        self.end_address = end_address
        self.addresses = {}
        self.debugger = debugger

        self.ptlog_analyzer = pyipttool.ipt.Analyzer(self.dump_filename,
                                        dump_symbols = False,
                                        dump_instructions = False,
                                        load_image = True,
                                        progress_report_interval = 0)

        self.ptlog_analyzer.open_ipt_log(self.pt_filename)

    def add_block(self, offset, block):
        start_address = block['IP']
        if not start_address in self.addresses:
            self.addresses[start_address] = {}
        self.addresses[start_address][ block['EndIP']] = (offset, block)

    def enumerate_instructions_by_pt(self):
        sync_offsets = {}
        for start_address in self.addresses.keys():
            for end_address in self.addresses[start_address].keys():
                (offset, block) = self.addresses[start_address][end_address]
                sync_offset = block['SyncOffset']
                if not sync_offset in sync_offsets:
                    sync_offsets[sync_offset] = []

                sync_offsets[sync_offset].append(block)

        instruction_addresses = {}
        for sync_offset, blocks in sync_offsets.items():
            logging.debug("sync_offset: %x" % sync_offset)
            ranges = []
            for block in blocks:
                ranges.append((block['IP'], block['EndIP']))

            for insn in self.ptlog_analyzer.decode_ranges(sync_offset = block['SyncOffset'], ranges = ranges):
                logging.debug("\tinsn.ip: %x" % insn.ip)
                instruction_addresses[insn.ip] = 1

            logging.debug('len(instruction_addresses): %d' % len(instruction_addresses))

        return instruction_addresses

    def enumerate_instruction_by_disassemble(self):
        instruction_addresses = {}
        for start_address in self.addresses.keys():
            for end_address in self.addresses[start_address].keys():
                (offset, block) = self.addresses[start_address][end_address]
                start_address = block['IP']
                end_address = block['EndIP']

                logging.debug('block: %.16x - %.16x' % (block['IP'], block['EndIP']))

                # self.disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
                # cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if x64 else capstone.CS_MODE_32)
                # retrieve dump using windbg
                # disassemble from start_address
                # continue
                # follow jump/calls
                # end when met with end_address
                # record instruction IPs

        return instruction_addresses

    def save(self, output_filename):
        instruction_addresses= self.enumerate_instruction_by_disassemble()

        with open(output_filename, 'w') as fd:
            for address in instruction_addresses.keys():
                fd.write('%s+%x\n' % (module_name, address - self.start_address))

    def print(self):
        for address in self.addresses.keys():
            print('%s+%x' % (module_name, address - start_address))

if __name__ == '__main__':
    import argparse
    import pyipttool.cache
    import windbgtool.debugger

    def auto_int(x):
        return int(x, 0)

    parser = argparse.ArgumentParser(description='pyipt')
    parser.add_argument('-p', action = "store", default = "", dest = "pt_filename")
    parser.add_argument('-d', action = "store", default = "", dest = "dump_filename")

    parser.add_argument('-m', action = "store", dest = "module_name", default = "")
    parser.add_argument('-o', action = "store", dest = "output_filename", default = "output.log")
    parser.add_argument('-D', action = "store", dest = "debug_filename", default = "")
    parser.add_argument('-f', action = "store", dest = "format", default = "instruction")

    parser.add_argument('-s', dest = "start_address", default = 0, type = auto_int)
    parser.add_argument('-e', dest = "end_address", default = 0, type = auto_int)

    parser.add_argument('-S', dest = "start_offset", default = 0, type = auto_int)
    parser.add_argument('-E', dest = "end_offset", default = 0, type = auto_int)

    parser.add_argument('-b', dest = "block_offset", default = 0, type = auto_int)
    
    parser.add_argument('-c', action = "store", dest = "cache_file")
    parser.add_argument('-C', dest = "cr3", default = 0, type = auto_int)    

    args = parser.parse_args()

    if args.dump_filename:
        dump_symbols = True
        load_image = True
    else:
        dump_symbols = False
        load_image = False

    if args.debug_filename:
        handlers = []
        if args.debug_filename == 'stdout':
            handlers.append(logging.StreamHandler())
        else:
            handlers.append(logging.FileHandler(args.debug_filename))

        logging.basicConfig(
            level=logging.DEBUG,
            format = '%(name)s - %(levelname)s - %(message)s',
            handlers = handlers
        )

    if args.cache_file:
        block_analyzer = pyipttool.cache.Reader(args.cache_file, args.pt_filename)

        debugger = windbgtool.debugger.DbgEngine()
        debugger.load_dump(args.dump_filename)
        debugger.enumerate_modules()

        start_address = 0
        end_address = 0

        if args.module_name:
            module_name = args.module_name
            (start_address, end_address) = debugger.get_module_range(args.module_name)
        else:
            module_name = ''
            start_address = args.start_address
            end_address = args.end_address

        coverage = Coverage(module_name, start_address, end_address, args.pt_filename, args.dump_filename, debugger = debugger)
        
        for (offset, block) in block_analyzer.enumerate_block_range(cr3 = args.cr3, start_address = start_address, end_address = end_address):
            if args.format == 'instruction':
                address = block['IP']
                symbol = debugger.find_symbol(address)
                print('> %.16x (%s) (sync_offset=%x, offset=%x)' % (address, symbol, block['SyncOffset'], offset))
                print('\t' + debugger.get_disassembly_line(address))
            elif args.format == 'modoffset_coverage':
                coverage.add_block(offset, block)

        if args.format == 'modoffset_coverage':
            if args.output_filename:
                coverage.save(args.output_filename)
            else:
                coverage.print()

    else:
        ptlog_analyzer = pyipttool.ipt.Analyzer(args.dump_filename, 
                                         dump_symbols = dump_symbols, 
                                         load_image = load_image)

        ptlog_analyzer.open_ipt_log(args.pt_filename, start_offset = args.start_offset, end_offset = args.end_offset)
        for block in ptlog_analyzer.decode_blocks(offset = args.block_offset, start_address = start_address, end_address = end_address):
            print('block.ip: %.16x ~ %.16x (%.16x)' % (block.ip, block.end_ip, block.ninsn))
