#!/usr/bin/env python3
"""Custom WASM parser for Dart2Wasm GC binaries with js-string builtins"""

import struct, sys

data = open('/home/student/ctfs/UNbreakable2026/rev/webd-art/main.wasm', 'rb').read()

pos = 0

def read_byte():
    global pos
    b = data[pos]
    pos += 1
    return b

def read_bytes(n):
    global pos
    r = data[pos:pos+n]
    pos += n
    return r

def read_leb128_unsigned():
    global pos
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            return result

def read_leb128_signed():
    global pos
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            return result

def read_string():
    length = read_leb128_unsigned()
    return read_bytes(length).decode('utf-8', errors='replace')

# Parse header
magic = read_bytes(4)
version = read_bytes(4)
print(f"Magic: {magic.hex()}, Version: {version.hex()}")

# Parse sections
sections = []
while pos < len(data):
    sec_start = pos
    sec_id = read_byte()
    sec_size = read_leb128_unsigned()
    sec_content_start = pos
    sections.append({
        'id': sec_id,
        'offset': sec_content_start,
        'size': sec_size,
        'start': sec_start
    })
    pos = sec_content_start + sec_size

print(f"\nSections: {len(sections)}")
for s in sections:
    sec_names = {0: 'custom', 1: 'type', 2: 'import', 3: 'function', 4: 'table',
                 5: 'memory', 6: 'global', 7: 'export', 8: 'start', 9: 'element',
                 10: 'code', 11: 'data', 12: 'datacount'}
    name = sec_names.get(s['id'], f'unknown({s["id"]})')
    print(f"  Section {s['id']:3d} ({name:12s}): offset=0x{s['offset']:04x}, size={s['size']}")

# Parse import section
import_sec = next(s for s in sections if s['id'] == 2)
pos = import_sec['offset']
import_count = read_leb128_unsigned()
print(f"\n=== Import Section: {import_count} imports ===")

imports = []
func_imports = 0
global_imports = 0
string_imports = []

for i in range(import_count):
    imp_start = pos
    try:
        mod_name = read_string()
        field_name = read_string()
        kind = read_byte()

        imp = {'module': mod_name, 'field': field_name, 'kind': kind, 'offset': imp_start}

        if kind == 0x00:  # func
            type_idx = read_leb128_unsigned()
            imp['type_idx'] = type_idx
            func_imports += 1
        elif kind == 0x01:  # table
            reftype = read_byte()
            flags = read_byte()
            min_val = read_leb128_unsigned()
            max_val = read_leb128_unsigned() if flags & 1 else None
            imp['table'] = (reftype, min_val, max_val)
        elif kind == 0x02:  # memory
            flags = read_byte()
            min_val = read_leb128_unsigned()
            max_val = read_leb128_unsigned() if flags & 1 else None
            imp['memory'] = (min_val, max_val)
        elif kind == 0x03:  # global
            valtype = read_byte()
            mut = read_byte()
            imp['global'] = (valtype, mut)
            global_imports += 1
            if mod_name == 'S':
                string_imports.append(field_name)
        elif kind == 0x04:  # tag
            attr = read_byte()
            type_idx = read_leb128_unsigned()
            imp['tag'] = (attr, type_idx)
        elif kind == 0x42:  # js-string builtin (special kind)
            # This is the problematic import kind
            # Try to figure out what follows - likely a type index
            type_idx = read_leb128_unsigned()
            imp['builtin_type'] = type_idx
            print(f"  Import #{i}: {mod_name}.{field_name} kind=0x42 type_idx={type_idx}")
        else:
            print(f"  Import #{i} at 0x{imp_start:04x}: {mod_name}.{field_name} UNKNOWN kind=0x{kind:02x}")
            # Try to continue - assume it's like a function import
            type_idx = read_leb128_unsigned()
            imp['unknown_type'] = type_idx
            print(f"    Guessed type_idx={type_idx}, next bytes: {data[pos:pos+4].hex()}")

        imports.append(imp)
    except Exception as e:
        print(f"  Error at import #{i}, offset 0x{pos:04x}: {e}")
        break

print(f"\nFunc imports: {func_imports}")
print(f"Global imports: {global_imports}")
print(f"String constants (from 'S' module): {len(string_imports)}")
print("\nAll string constants:")
for s in string_imports:
    print(f"  '{s}'")

print(f"\nAll non-S imports:")
for imp in imports:
    if imp['module'] != 'S':
        kind_name = {0: 'func', 1: 'table', 2: 'memory', 3: 'global', 4: 'tag', 0x42: 'builtin'}
        print(f"  {imp['module']}.{imp['field']}: kind={kind_name.get(imp['kind'], hex(imp['kind']))}")
