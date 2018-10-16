#!/usr/bin/env python3

import sys

ndigits_dict = {}
names_dict = {}

def digits(x, base):
    ds = []
    while x >= base:
        d = x % base
        ds.append(d)
        x = (x - d) // base
    ds.append(x)
    return ds

def digits_for_pos(pos, base):
    max_ndigits = 0;
    ds = []
    for x in range(256):
        d = digits(x << (8*pos), base)
        ds.append(d)
        max_ndigits = max(len(d), max_ndigits)

    # pad them to be the same length
    for d in ds:
        while (len(d) < max_ndigits):
            d.append(0)

    return (max_ndigits, ds)

def write_tables_for_base(base, f):
    ndigits_dict[base] = []
    names_dict[base] = []
    for pos in range(16):
        (n, ds) = digits_for_pos(pos, base)
        name = f"BASE{base}_POS{pos}"
        ndigits_dict[base].append(n)
        names_dict[base].append(name)
        print(f"const uint8_t {name} [][{n}] = {{", file=f)

        line = ""
        for d in ds:
            line += "{" + ",".join(map(str, d)) + "}, "
            if len(line) > 100:
                print("    " + line, file=f)
                line = ""
        if len(line) > 0:
            print("    " + line, file=f)
        print("};\n", file=f)


def write_header(f):
    print("#include <stdint.h>", file=f);
    print("#include <stddef.h>", file=f);
    print("#include <stdbool.h>\n", file=f);

def write_get_table_function(f):
    print("uint8_t* c_get_table(uint8_t base, size_t pos) {", file=f)
    print("    switch (base) {", file=f)

    for base, names in names_dict.items():
        names_arr = ", ".join(names)
        print(f"        case {base}: return {names_arr}[pos];", file=f)

    print("        default: return NULL;", file=f)
    print("    }", file=f)
    print("}\n", file=f)

def write_num_digits_function(f):
    print("uint8_t* c_num_digits(uint8_t base, size_t pos) {", file=f)
    print("    switch (base) {", file=f)

    for base, ndigits in ndigits_dict.items():
        print(f"        case {base}: return {{" + ", ".join(map(str,ndigits)) + "}[pos];", file=f)

    print("        default: return 0;", file=f)
    print("    }", file=f)
    print("}\n", file=f)

with open('base_conversion/cbits/base_conversion_tables.c', 'w') as f:
    write_header(f)

    for base in range(3,114):
        write_tables_for_base(base, f)

    write_get_table_function(f)
    write_num_digits_function(f)
