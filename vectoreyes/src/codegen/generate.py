import json
import re
import subprocess
import sys
from itertools import product, takewhile
from pathlib import Path

import jinja2

CODEGEN = Path(__file__).resolve().parent

from .avx2 import *
from .cgtypes import *


def assert_eq(a, b):
    assert a == b, f"{repr(a)} == {repr(b)}"


def strip_common_whitespace_prefix(lines):
    prefix = "".join(takewhile(lambda ch: ch.isspace(), lines[0]))
    for line in lines:
        prefix = "".join(
            map(
                lambda pair: pair[0],
                takewhile(lambda pair: pair[0] == pair[1], zip(line, prefix)),
            )
        )
    for line in lines:
        assert line.startswith(prefix)
    for line in lines:
        yield line[len(prefix) :]


def doc_comment_code(code, add_prefix=""):
    lines = [line for line in code.split("\n") if line.strip() != ""]
    if len(lines) == 0:
        return ""
    return "\n".join(
        "/// " + add_prefix + line for line in strip_common_whitespace_prefix(lines)
    )


def dict_concat(a, b):
    return a | b


def extract_bit(x, bit):
    return (x >> bit) & 1


def render_latency(latency):
    minl = latency["min_latency"]
    maxl = latency["max_latency"]
    if minl["value"] == maxl["value"]:
        out = str(minl["value"])
        if (not minl["is_exact"]) or (not maxl["is_exact"]):
            out = f"&le;{out}"
        return out
    render = lambda l: ("" if l["is_exact"] else "&le;") + str(l["value"])
    return f"[{render(minl)};{render(maxl)}]"


def fixed_aes_key(key_size):
    assert key_size in [128, 192, 256]
    from hashlib import sha256

    return sha256(f"fixed_key_aes_key_schedule_{key_size}".encode("ascii")).digest()[
        0 : key_size // 8
    ]


env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(CODEGEN / "templates")),
    autoescape=False,
    undefined=jinja2.StrictUndefined,
    extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
)
for k in [
    "VECTOR_TYPES",
    "VECTOR_SIZES",
    "INTEGER_TYPES",
    "VectorType",
    "IntegerType",
    "BoolType",
    "ArrayType",
    "Signedness",
    "IntelIntrinsicBuilder",
    "IntelIntrinsic",
    "assert_eq",
    "dict_concat",
    "extract_bit",
    "fixed_aes_key",
]:
    env.globals[k] = globals()[k]
env.globals["len"] = len
env.filters["repr"] = repr
env.filters["list"] = list
env.filters["doc_comment_code"] = doc_comment_code
env.filters["render_latency"] = render_latency


# Since the generated files are checked-in to the repo, we want to try to keep them small.


def compress_test_code(code):
    return compress_implementation(re.sub(r"///.*\n", "", code))


def compress_implementation(code):
    lines = []
    doc_acu = []
    doc_strings = []
    for line in re.sub(
        r"\n[ \t]+", "\n", re.sub(r"\n+", "\n", re.sub(r"[ \t]+\n", "\n", code))
    ).split("\n"):
        if re.match(r"^[ \t]*///", line):
            doc_acu.append(re.sub(r"^[ \t]*///", "", line, count=1))
        elif re.match(r"^[ \t]+$", line):
            continue
        else:
            if doc_acu:
                doc_acu = "\n".join(strip_common_whitespace_prefix(doc_acu))
                doc_strings.append((len(lines), doc_acu))
                lines.append("DOC STRINGS GO HERE!")
                doc_acu = []
            lines.append(re.sub(r"[ \t]+", " ", line))
    for i, doc in doc_strings:
        lines[i] = f"#[doc={json.dumps(doc)}]"
    return " ".join(line + "\n" if "//" in line else line for line in lines)


def generate():
    out = {}

    def write_rust(dst, code):
        nonlocal out
        if "/test/" in str(dst):
            code = compress_test_code(code)
        else:
            code = compress_implementation(code)
        assert dst not in out
        out[dst] = b"".join(
            [
                b"// @generated\n",
                b"// rustfmt-format_generated_files: false\n",
                b"// This file was auto-generated by generate.py DO NOT MODIFY\n",
                subprocess.run(
                    ["rustfmt", "--edition=2018"],
                    input=code.encode("ascii"),
                    check=True,
                    stdout=subprocess.PIPE,
                ).stdout,
            ]
        )

    write_rust(
        "implementation.rs",
        env.get_template("implementation.tmpl").render(),
    )
    write_rust("tests/scalar.rs", env.get_template("tests/scalar.tmpl").render())
    write_rust("tests/aes.rs", env.get_template("tests/aes.tmpl").render())
    for ty in VECTOR_TYPES:
        write_rust(
            f"tests/{str(ty).lower()}.rs",
            env.get_template("tests/vector.tmpl").render(ty=ty),
        )
    write_rust("tests.rs", env.get_template("tests.tmpl").render())
    return out
