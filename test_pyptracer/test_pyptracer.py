import os
import sys
sys.path.append(r'..\x64\Debug')

from zipfile import ZipFile

import pyptracer

if not os.path.isfile('trace.pt'):
    print("* Extracting test trace file:")
    with ZipFile('trace.zip', 'r') as zf:
       zf.extractall()

p=pyptracer.PTracer()
p.Open(r'trace.pt')
p.StartInstructionDecoding()

while 1:
    pinsn = p.DecodeInstruction()
    print('%x: %x' % (p.GetOffset(), pinsn.ip))
