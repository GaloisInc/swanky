#!/usr/bin/env python3

# Galois, Inc. 2022

# Translate a tiny subset of Verilog to a Bristol Fashion circuit.
#
# The following Verilog keywords are recognized:
#  module, input, output, wire, INV, AND, XOR, BUF, endmodule.
# The Verilog `localparam` keyword is allowed only in a specific
#  context (see next paragraph). Other uses of `localparam` are
#  not allowed.
#
# The BF circuit advertises the number of inputs and outputs and
# the number of wires associated with each. This information is
# not represented in the Verilog file emitted by ABC; specially
# formatted parameters may be added to the Verilog file to provide
# this information:
#  localparam vg2bf_input_wpv = "<input-wires-per-value>";
#  localparam vg2bf_output_wpv = "<output-wires-per-value>";
# where each <...> is a comma-separated list of wire counts.
# The counts must sum to the total number of input or output wires
# declared for the circuit. The localparam vg2bf_input_wpv statement
# must immediately follow the module's list of input wires. The
# localparam vg2bf_output_wpv statement must immediately follow the
# module's list of output wires. When these parameters are not present
# in the Verilog file, the corresponding wires are not partitioned
# into distinct values in the Bristol Fashion output file.
#
# The Verilog source file is checked for these semantic errors:
#  * wire name declared more than once
#  * improperly labeled gate pins
#  * reference to undeclared wire
#  * multiple outputs drive one wire
#  * wire used as input before attached to signal source
#  * unused output and interconnect wires
#  * `localparam v22bf_..._wvp = "...";` has wrong total count
#  NOTE: The Verilog `module`'s parameter list is unused; input
#   and output wire names are denoted by the lists following the
#   `input` and `output` keywords.

import os
import re
import sys
import tokenize


def eprint(msg):
    print(msg, file=sys.stderr)


def usage():
    eprint("usage: {} VERILOG_FILE NEW_BF_FILE".format(os.path.basename(sys.argv[0])))
    exit(1)


if len(sys.argv) != 3:
    usage()

line = 0
column = 0

COMMENT = "//"
NEWLINE = "\n"
whitespace_regex = re.compile(r"^[\t ]*$")


def scan(vfile):
    global line
    global column
    tokens = tokenize.generate_tokens(vfile.readline)
    while True:
        t = next(tokens)
        if t.string == COMMENT:
            while t.string != NEWLINE:
                t = next(tokens)
            continue
        if t.string == NEWLINE:
            continue
        if whitespace_regex.match(t.string):
            continue
        line = t.start[0]
        column = t.start[1]
        yield t


peeked = None  # token object or None


def peek(tokens):
    global peeked
    if peeked == None:
        token = next(tokens)
        peeked = token
        return token.string
    else:
        token = peeked
        peeked = None
        return token.string


def accept(tokens):
    global peeked
    if peeked == None:
        return next(tokens).string
    else:
        token = peeked
        peeked = None
        return token.string


def fatal(msg):
    eprint("fatal: {}".format(msg))
    exit(1)


def error(msg):
    eprint(msg)
    exit(1)


def sfail(msg):
    eprint("{} at line {} column {}".format(msg, line, column))
    exit(1)


def fail(msg, token):
    if type(msg) is list:
        sfail("expected one of {}; found '{}'".format(msg, token))
    else:
        sfail("expected '{}'; found '{}'".format(msg, token))
    exit(1)


def expect(tokens, match):
    t = accept(tokens)
    if t == match:
        return
    else:
        fail(match, t)


LPAR = "("
RPAR = ")"
SEMI = ";"
DOT = "."
COMMA = ","
EQUAL = "="


def parse_arglist(tokens):
    expect(tokens, LPAR)
    while True:
        if accept(tokens) == RPAR:
            break
    expect(tokens, SEMI)


current_wire = 0
wires = {}  # wire-name => index


def register_wire(name):
    global current_wire
    global wires
    if name in wires:
        sfail("duplicate wire {}".format(name))
    wires[name] = current_wire
    current_wire += 1


def register_wires(wires_list):
    for wire in wires_list:
        register_wire(wire)


def collect_wires():
    wires = []
    while True:
        wires += [accept(tokens)]
        if peek(tokens) == COMMA:
            accept(tokens)
        else:
            break
    return wires


input_wires = []


def parse_input_list(tokens):
    global input_wires
    expect(tokens, "input")
    input_wires = collect_wires()
    expect(tokens, SEMI)


output_wires = []

numbers_list_regex = r'^"[0-9]+(,[0-9]+)*"$'


def parse_wpv_list(param_name, tokens):
    expect(tokens, param_name)
    expect(tokens, EQUAL)
    t = accept(tokens)  # quoted string
    if not re.match(numbers_list_regex, t):
        fail("numbers list", t)
    expect(tokens, SEMI)
    return t[1:-1].split(COMMA)


iwv = None


def maybe_parse_input_wpv(tokens):
    global iwv
    if peek(tokens) == "localparam":
        accept(tokens)
        iwv = parse_wpv_list("vg2bf_input_wpv", tokens)
    else:
        iwv = [len(input_wires)]


def parse_output_list(tokens):
    global output_wires
    expect(tokens, "output")
    output_wires = collect_wires()
    expect(tokens, SEMI)


owv = None


def maybe_parse_output_wpv(tokens):
    global owv
    if peek(tokens) == "localparam":
        accept(tokens)
        owv = parse_wpv_list("vg2bf_output_wpv", tokens)
    else:
        owv = [len(output_wires)]


internal_wires = []


def parse_wire_list(tokens):
    global internal_wires
    expect(tokens, "wire")
    internal_wires = collect_wires()
    expect(tokens, SEMI)


valid_gates = ["AND", "XOR", "INV", "BUF"]


def parse_gate_kind(tokens):
    t = accept(tokens)
    if t in valid_gates:
        return [t]
    else:
        fail(valid_gates, t)


def parse_gate_pin(tokens):
    expect(tokens, DOT)
    label = accept(tokens)
    expect(tokens, LPAR)
    wire = accept(tokens)
    expect(tokens, RPAR)
    return [[label, wire]]


def parse_gate(tokens):
    gate_info = parse_gate_kind(tokens)
    name = accept(tokens)
    expect(tokens, LPAR)
    while True:
        gate_info += parse_gate_pin(tokens)
        if peek(tokens) == RPAR:
            accept(tokens)
            break
        else:
            expect(tokens, COMMA)
    while True:
        if accept(tokens) == SEMI:
            return gate_info


bfile = None


def bprint(msg):
    print(msg, file=bfile)


def bprinc(msg):
    print(msg, end="", file=bfile)


def bterpri():
    print(file=bfile)


patch_offset = None

wires_count = None
iwc = None
xwc = None
owc = None


def emit_BF_header():
    global patch_offset
    global wires_count
    global iwc
    global xwc
    global owc
    iwc = len(input_wires)
    xwc = len(internal_wires)
    owc = len(output_wires)
    wires_count = iwc + xwc + owc
    patch_offset = bfile.tell()
    # line 1: #gates #wires
    bprint("{:<10} {}".format(0, wires_count))
    # line 2: #input-values #wires-per-input-value...
    bprinc("{}".format(len(iwv)))
    tniw = 0
    for wc in iwv:
        bprinc(" {}".format(wc))
        tniw += int(wc)
    bterpri()
    if tniw != iwc:
        error(
            "input wires allocated ({}) do not match \
input wires generated ({})".format(
                tniw, iwc
            )
        )
    # line 3: #output-values #wires-per-output-value...
    bprinc("{}".format(len(owv)))
    tnow = 0
    for wc in owv:
        bprinc(" {}".format(wc))
        tnow += int(wc)
    bterpri()
    if tnow != owc:
        error(
            "output wires allocated ({}) do not match \
output wires generated ({})".format(
                tnow, owc
            )
        )
    # line 4: empty-line
    bterpri()


def patch_BF_header(ngates):
    bfile.seek(patch_offset)
    bprinc("{:<10}".format(ngates))


valid_wires = None
# wire_number -> has_signal


def init_valid_wires():
    global valid_wires
    valid_wires = [False for _ in range(wires_count)]
    for i in range(iwc):
        valid_wires[i] = True


def note_wire_has_signal(wire_num):
    global valid_wires
    if valid_wires[wire_num]:
        sfail("conflicting source for wire {}".format(wire_num))
    valid_wires[wire_num] = True


def wire_has_signal(wire_num):
    return valid_wires[wire_num]


def list_unused_wires():
    global valid_wires
    unused = [k for k, v in enumerate(valid_wires) if not v]
    uwires = [k for i, (k, v) in enumerate(wires.items()) if v in unused]
    if len(uwires) > 0:
        eprint("unused wires: {}".format(uwires))


def wire(gate_info, label):
    global wires
    for elt in gate_info:
        if type(elt) is list and elt[0] == label:
            nm = elt[1]
            if not nm in wires:
                sfail("no wire {}".format(nm))
            wire_num = wires[nm]
            if label in ["A", "B"]:
                if not wire_has_signal(wire_num):
                    sfail("input {} not driven".format(label))
            elif label == "Y":
                note_wire_has_signal(wire_num)
            else:
                fatal("invalid label {}".format(label))
            return wires[nm]
    sfail("no gate pin labeled {}".format(label))


count_AND = 0
count_XOR = 0
count_INV = 0
count_EQW = 0


def emit_BF_gate(gate_info):
    global count_AND
    global count_XOR
    global count_INV
    global count_EQW
    kind = gate_info[0]
    if kind in ["AND", "XOR"]:
        bprint(
            "2 1 {} {} {} {}".format(
                wire(gate_info, "A"), wire(gate_info, "B"), wire(gate_info, "Y"), kind
            )
        )
        if kind == "AND":
            count_AND += 1
        elif kind == "XOR":
            count_XOR += 1
        else:
            fatal("uncounted 2-input gate")
    elif kind in ["INV"]:
        bprint("1 1 {} {} {}".format(wire(gate_info, "A"), wire(gate_info, "Y"), kind))
        count_INV += 1
    elif kind == "BUF":
        bprint("1 1 {} {} {}".format(wire(gate_info, "A"), wire(gate_info, "Y"), "EQW"))
        count_EQW += 1
    else:
        fatal("unhandled gate kind")


gates_count = 0


def parse_gates(tokens):
    global gates_count
    while True:
        gate_info = parse_gate(tokens)
        emit_BF_gate(gate_info)
        gates_count += 1
        if peek(tokens) == "endmodule":
            return


def parse_verilog(tokens):
    expect(tokens, "module")
    module_name = accept(tokens)
    eprint("Parsing Verilog module {}".format(module_name))
    parse_arglist(tokens)
    parse_input_list(tokens)
    maybe_parse_input_wpv(tokens)
    parse_output_list(tokens)
    maybe_parse_output_wpv(tokens)
    parse_wire_list(tokens)
    register_wires(input_wires)
    register_wires(internal_wires)
    register_wires(output_wires)
    emit_BF_header()
    init_valid_wires()
    parse_gates(tokens)
    patch_BF_header(gates_count)
    expect(tokens, "endmodule")
    list_unused_wires()


def pl(count):
    if int(count) != 1:
        return "s"
    else:
        return ""


def summarize():
    eprint(
        "gates:\t{:>10}\t(AND: {}; XOR: {}; INV: {}; EQW: {})\
\nwires:\t{:>10}\t(input: {}; interconnect: {}; output: {})".format(
            gates_count,
            count_AND,
            count_XOR,
            count_INV,
            count_EQW,
            wires_count,
            iwc,
            xwc,
            owc,
        )
    )
    i = 0
    for wc in iwv:
        i += 1
        eprint("in  {}:\t{:>4} wire{}".format(i, wc, pl(wc)))
    i = 0
    for wc in owv:
        i += 1
        eprint("out {}:\t{:>4} wire{}".format(i, wc, pl(wc)))


try:
    with open(sys.argv[2], "w") as bfile:
        with tokenize.open(sys.argv[1]) as vfile:
            tokens = scan(vfile)
            parse_verilog(tokens)
    summarize()
except Exception as e:
    eprint(e)
