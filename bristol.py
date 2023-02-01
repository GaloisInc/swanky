f = open("mac-n-cheese/compiler/src/aes_128.txt")
inputs = [
    ch == "1"
    for ch in "01000111110101111110110010000010010101100000010111100111001001110000010111111001100101110100101111110000010111100001010001001000"
    * 2
]
nout = 128
wires = {i: v for i, v in enumerate(inputs)}
for line in f.read().split("\n"):
    if "XOR" not in line and "AND" not in line and "INV" not in line:
        continue
    parts = line.split()
    match parts[-1]:
        case "XOR":
            out = wires[int(parts[2])] ^ wires[int(parts[3])]
            assert int(parts[-2]) not in wires
            wires[int(parts[-2])] = out
        case "AND":
            out = wires[int(parts[2])] & wires[int(parts[3])]
            assert int(parts[-2]) not in wires
            wires[int(parts[-2])] = out
        case "INV":
            out = not wires[int(parts[2])]
            assert int(parts[-2]) not in wires
            wires[int(parts[-2])] = out

num_wires = 36919
out = [wires[num_wires - nout + i] for i in range(nout)]
print("".join("1" if bit else "0" for bit in out))
