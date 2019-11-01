import os
import sys
sys.path.append(r'..\x64\Debug')

import pickle
import pprint
from zipfile import ZipFile
from datetime import datetime, timedelta

import capstone

import decoder
import windbgtool.debugger

if __name__ == '__main__':
    cache_folder = 'Tmp'
    pt_filename = '../TestFiles/trace.pt'
    dump_filename = '../TestFiles/notepad.exe.dmp'
    start_offset = 0x283d2178 - 1024*5
    end_offset = start_offset + 1024*10

    pytracer = decoder.PTLogAnalyzer(pt_filename, 
                                     dump_filename, 
                                     dump_symbols = True, 
                                     load_image = True, 
                                     start_offset = start_offset,
                                     end_offset = end_offset)
    pytracer.DecodeInstruction(move_forward = False)