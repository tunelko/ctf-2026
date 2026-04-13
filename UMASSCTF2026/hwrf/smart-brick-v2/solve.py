#!/usr/bin/env python3
"""Smart Brick v2 — UMassCTF 2026 (hwrf)
KiCad PCB with 26 74LSxx logic ICs implementing a 7-bit ASCII decoder.
7 inputs (IN0-IN6) drive 19 LEDs (D1-D19) through combinational logic.
Each LED position = one flag character. Brute-force all 128 ASCII inputs."""
import re

# Parse IC types and pin nets from KiCad PCB
def parse_pcb(path):
    with open(path) as f:
        content = f.read()
    blocks = re.split(r'\n\t\(footprint ', content)[1:]
    ics = {}
    for block in blocks:
        if 'DIP-14' not in block.split('\n')[0]:
            continue
        ref = re.search(r'\(property "Reference" "([^"]+)"', block)
        val = re.search(r'\(property "Value" "([^"]+)"', block)
        if not ref or not val:
            continue
        pads = {}
        for m in re.finditer(r'\(pad "(\d+)".*?\(net \d+ "([^"]*?)"\)', block, re.DOTALL):
            pads[int(m.group(1))] = m.group(2).strip('/')
        ics[ref.group(1)] = (val.group(1), pads)
    return ics

def build_equations(ics):
    eq = {}
    def c(net): return net if net and net != 'NC' and 'unconnected' not in net and net not in ('+5V','GND','') else None

    for name, (typ, p) in ics.items():
        if typ == '74LS04':  # Hex NOT
            for a,y in [(1,2),(3,4),(5,6),(9,8),(11,10),(13,12)]:
                i,o = c(p.get(a)), c(p.get(y))
                if i and o: eq[o] = ('NOT', [i])
        elif typ == '74LS00':  # Quad NAND
            for a,b,y in [(1,2,3),(4,5,6),(9,10,8),(12,13,11)]:
                i1,i2,o = c(p.get(a)),c(p.get(b)),c(p.get(y))
                if i1 and i2 and o: eq[o] = ('NAND', [i1,i2])
        elif typ == '74LS02':  # Quad NOR (2,3→1 etc)
            for a,b,y in [(2,3,1),(5,6,4),(8,9,10),(11,12,13)]:
                i1,i2,o = c(p.get(a)),c(p.get(b)),c(p.get(y))
                if i1 and i2 and o: eq[o] = ('NOR', [i1,i2])
        elif typ == '74LS08':  # Quad AND
            for a,b,y in [(1,2,3),(4,5,6),(9,10,8),(12,13,11)]:
                i1,i2,o = c(p.get(a)),c(p.get(b)),c(p.get(y))
                if i1 and i2 and o: eq[o] = ('AND', [i1,i2])
        elif typ == '74LS32':  # Quad OR
            for a,b,y in [(1,2,3),(4,5,6),(9,10,8),(12,13,11)]:
                i1,i2,o = c(p.get(a)),c(p.get(b)),c(p.get(y))
                if i1 and i2 and o: eq[o] = ('OR', [i1,i2])
        elif typ == '74LS86':  # Quad XOR
            for a,b,y in [(1,2,3),(4,5,6),(9,10,8),(12,13,11)]:
                i1,i2,o = c(p.get(a)),c(p.get(b)),c(p.get(y))
                if i1 and i2 and o: eq[o] = ('XOR', [i1,i2])
        elif typ == '74LS20':  # Dual 4-input NAND (NC=4,12)
            for ins,y in [((1,2,3,5),6),((9,10,11,13),8)]:
                ii = [c(p.get(x)) for x in ins]; o = c(p.get(y))
                if all(ii) and o: eq[o] = ('NAND4', ii)
        elif typ == '74LS21':  # Dual 4-input AND (NC=4,12)
            for ins,y in [((1,2,3,5),6),((9,10,11,13),8)]:
                ii = [c(p.get(x)) for x in ins]; o = c(p.get(y))
                if all(ii) and o: eq[o] = ('AND4', ii)
        elif typ == '74LS27':  # Triple 3-input NOR
            for ins,y in [((1,2,13),12),((3,4,5),6),((9,10,11),8)]:
                ii = [c(p.get(x)) for x in ins]; o = c(p.get(y))
                if all(ii) and o: eq[o] = ('NOR3', ii)
    return eq

def evaluate(net, state, eq, depth=0):
    if net in state: return state[net]
    if depth > 50 or net not in eq: return 0
    func, inputs = eq[net]
    v = [evaluate(i, state, eq, depth+1) for i in inputs]
    ops = {'NOT': lambda v: 1-v[0], 'AND': lambda v: v[0]&v[1],
           'AND4': lambda v: v[0]&v[1]&v[2]&v[3],
           'NAND': lambda v: 1-(v[0]&v[1]),
           'NAND4': lambda v: 1-(v[0]&v[1]&v[2]&v[3]),
           'OR': lambda v: v[0]|v[1], 'NOR': lambda v: 1-(v[0]|v[1]),
           'NOR3': lambda v: 1-(v[0]|v[1]|v[2]),
           'XOR': lambda v: v[0]^v[1]}
    state[net] = ops[func](v)
    return state[net]

# LED D_n driven by gate G_x via transistor Q_n
LED_GATES = {1:'G59',2:'G62',3:'G13',4:'G19',5:'G21',6:'G24',7:'G26',
             8:'G29',9:'G31',10:'G36',11:'G39',12:'G41',13:'G43',14:'G45',
             15:'G47',16:'G49',17:'G52',18:'G54',19:'G56'}

ics = parse_pcb('smart-brick-v2.kicad_pcb')
eq = build_equations(ics)

# Simulate all 128 ASCII inputs
flag = {}
for val in range(128):
    state = {f'IN{b}': (val>>b)&1 for b in range(7)}
    for led, gate in LED_GATES.items():
        if evaluate(gate, state, eq):
            flag.setdefault(led, chr(val) if 32<=val<127 else '?')

print('[+] FLAG:', ''.join(flag.get(i,'?') for i in range(1,20)))
