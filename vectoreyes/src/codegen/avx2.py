import dataclasses
import json
import lzma
import os
import typing
import xml.etree.ElementTree as ET
from collections import namedtuple
from pathlib import Path
from uuid import uuid4

from cgtypes import *

INTEL_INTRINSICS_XML_XZ = (
    Path(__file__).resolve().parent / "intel-intrinsics-3.4.5.xml.xz"
)
with lzma.open(INTEL_INTRINSICS_XML_XZ) as compressed_xml:
    INTEL_INTRINSICS_XML = {
        x.get("name"): x for x in ET.parse(compressed_xml).getroot()
    }

if "UOPS_INFO_XML" in os.environ:
    UOPS_INFO_DB = dict()
    _Latency = namedtuple("_Latency", "value is_exact")
    with open(os.environ["UOPS_INFO_XML"]) as xml:
        UOPS_XML = ET.parse(xml)

    def perf(arch):
        measurement = arch.find("measurement")
        if measurement is None:
            return None
        min_latency = _Latency(0x10000, True)
        max_latency = _Latency(0, False)
        for latency_elem in measurement.findall("latency"):
            for k, v in latency_elem.attrib.items():
                if "cycles" not in k or "upper_bound" in k:
                    continue
                l = _Latency(int(v), not latency_elem.get(f"{k}_is_upper_bound"))
                min_latency = min(l, min_latency)
                max_latency = max(l, max_latency)
        return dict(
            # TODO: is "unrolled" the right "default" to fall back to?
            throughput=measurement.get("TP", measurement.get("TP_unrolled")),
            min_latency=min_latency._asdict(),
            max_latency=max_latency._asdict(),
        )

    for ext in UOPS_XML.getroot():
        for insn in ext:
            iform = insn.get("iform")
            if not iform:
                continue
            key = iform
            if key in UOPS_INFO_DB:
                # db[key] = {"has_duplicate": True}
                continue
            data = dict(
                url=insn.get("url"),
                ref_url=insn.get("url-ref"),
                string=insn.get("string"),
                summary=insn.get("summary"),
                perf={
                    arch.get("name"): perf(arch)
                    for arch in insn.findall("architecture")
                    if arch.find("measurement")
                },
            )
            UOPS_INFO_DB[key] = data
else:
    UOPS_INFO_DB = None

SWANKY_CACHE_DIR = (
    Path(os.environ["SWANKY_CACHE_DIR"]) / "avx2-uops.info-dbm-cache"
    if "SWANKY_CACHE_DIR" in os.environ
    else Path(__file__).resolve().parent
)


def uops_info(iform):
    if UOPS_INFO_DB is None:
        return None
    return UOPS_INFO_DB.get(iform)


@dataclasses.dataclass(frozen=True)
class IntelInstruction:
    xml: typing.Any
    uops_info: typing.Any

    @property
    def name(self):
        return self.xml.get("name")

    @property
    def form(self):
        return self.xml.get("form")

    @property
    def xed_form(self):
        return self.xml.get("xed")

    @property
    def reference_url(self):
        if self.uops_info:
            return "https://" + self.uops_info["ref_url"]
        else:
            return None

    @property
    def perf_url(self):
        if self.uops_info:
            return "https://" + self.uops_info["url"]
        else:
            return None

    @property
    def summary(self):
        if self.uops_info:
            return self.uops_info["summary"]
        else:
            return None

    @property
    def perf(self):
        if self.uops_info:
            return self.uops_info["perf"]
        else:
            return None

    def __str__(self):
        if self.uops_info:
            return self.uops_info["string"]
        else:
            return f"{self.name} {self.form}"


class IntelIntrinsic(namedtuple("IntelIntrinsic", "name")):
    @property
    def xml(self):
        return INTEL_INTRINSICS_XML[self.name]

    def intel_reference_url(self):
        return f"https://software.intel.com/sites/landingpage/IntrinsicsGuide/#text={self.name}"

    def sequence(self):
        return (self.xml.get("sequence") or "").lower() == "true"

    def cpuid(self):
        return [x.text for x in self.xml.findall("CPUID")]

    def instructions(self):
        return [
            IntelInstruction(x, uops_info(x.get("xed")))
            for x in self.xml.findall("instruction")
        ]

    def __str__(self):
        return self.name


# Due to limitations on const generics, we need to do manipulation on `const` generics
# in the intrinsic wrapper, rather than at a higher-level.
IntrinsicImmediateArgumentOverride = namedtuple(
    "IntrinsicImmediateArgumentOverride", "const_args immediate_body"
)


def _make_immediate_argument_overrides():
    shuffle = IntrinsicImmediateArgumentOverride(
        const_args={f"I{i}": "usize" for i in reversed(range(4))},
        immediate_body="((I3 << 6) | (I2 << 4) | (I1 << 2) | I0) as i32",
    )
    if_true = lambda flag, value: f"((!(({flag} as u64).wrapping_sub(1))) & {value})"
    hi1 = if_true("HI1", "0xf0")
    hi0 = if_true("HI0", "0x0f")
    clmul = IntrinsicImmediateArgumentOverride(
        const_args={"HI1": "bool", "HI0": "bool"},
        immediate_body=f"({hi1} | {hi0}) as i32",
    )
    blend = lambda count: IntrinsicImmediateArgumentOverride(
        const_args={f"B{i}": "bool" for i in reversed(range(count))},
        immediate_body="("
        + " | ".join(f"((B{i} as u8) << {i})" for i in range(count))
        + ") as i32",
    )
    return {
        "_mm256_shuffle_epi32": shuffle,
        "_mm_shuffle_epi32": shuffle,
        "_mm256_permute4x64_epi64": shuffle,
        "_mm_shufflelo_epi16": shuffle,
        "_mm256_shufflelo_epi16": shuffle,
        "_mm_shufflehi_epi16": shuffle,
        "_mm256_shufflehi_epi16": shuffle,
        "_mm_clmulepi64_si128": clmul,
        "_mm_blend_epi16": blend(8),
        "_mm_blend_epi32": blend(4),
        "_mm256_blend_epi32": blend(8),
    }


INTRINSIC_IMMEDIATE_ARGUMENT_OVERRIDES = _make_immediate_argument_overrides()


class IntelIntrinsicBuilder:
    # TODO: what microarchitectures do we care about?
    # Use the naming convention from `rustc -C target-cpu=help`
    TARGET_CPUS = [
        "skylake",
        "skylake-avx512",
        "cascadelake",
        "znver1",
        "znver2",
        "znver3",
    ]
    # None corresponds to the fallback value
    # Otherwise, these numbers are the latncies of aes enc/dec instructions for their respsctive
    # targets, since the throughputs for all these instructions are 1.
    AES_BLOCK_COUNT_HINT = {
        None: 8,
        "skylake": 4,
        "skylake-avx512": 4,
        "cascadelake": 4,
        "znver1": 4,
        "znver2": 4,
        "znver3": 4,
    }
    TARGET_CPU_NAMES = {
        None: "Unknown",
        "skylake": "Skylake",
        "skylake-avx512": "SkylakeAvx512",
        "cascadelake": "CascadeLake",
        "znver1": "AmdZenVer1",
        "znver2": "AmdZenVer2",
        "znver3": "AmdZenVer3",
    }
    DISPLAY_PERF_NUMBERS_FOR = {
        "Skylake": "SKL",
        "Skylake-AVX512": "SKX",
        "Cascade Lake": "CLX",
        "AMD ZEN+": "ZEN+",
    }

    def __init__(self, flags):
        INHERENT_TO_x86_64 = {
            "SSE2",
        }
        self.flags = set(flags) | INHERENT_TO_x86_64
        self.needed_intrinsics = set()
        self.AES_BLOCK_COUNT_HINT = IntelIntrinsicBuilder.AES_BLOCK_COUNT_HINT
        self.DISPLAY_PERF_NUMBERS_FOR = IntelIntrinsicBuilder.DISPLAY_PERF_NUMBERS_FOR
        self.TARGET_CPUS = IntelIntrinsicBuilder.TARGET_CPUS
        self.TARGET_CPU_NAMES = IntelIntrinsicBuilder.TARGET_CPU_NAMES
        for cpu in self.TARGET_CPUS:
            assert cpu in self.AES_BLOCK_COUNT_HINT

    def intrinsic_name(self, ty, op, ty2=None):
        if ty == "raw":
            return op
        assert ty.bits in [256, 128]
        suffixes = {8: "b", 16: "w", 32: "d", 64: "q"}
        if ty.bits == 256:
            prefix = "_mm256_"
        elif ty.bits == 128:
            prefix = "_mm_"
        else:
            assert False, f"unexpected bits in {repr(ty)}"
        if ty.ty.signedness == Signedness.SIGNED:
            iu = "i"
        else:
            iu = "u"
        if op in [
            "loadu",
            "storeu",
            "xor",
            "and",
            "or",
            "testz",
            "setzero",
            "srli",
            "slli",
            "andnot",
        ]:
            return f"{prefix}{op}_si{ty.bits}"
        elif op == "shuffle" and ty.ty.bits == 8:
            return f"{prefix}shuffle_epi8"
        elif op in [
            "add_lanes",
            "sub_lanes",
            "extract",
            "shuffle",
            "cmpeq",
            "cmpgt",
            "movemask",
            "blend",
            "unpacklo",
            "unpackhi",
        ]:
            if op == "cmpgt":
                assert ty.ty.signedness == Signedness.SIGNED
            core = op.replace("_lanes", "")
            return f"{prefix}{core}_epi{ty.ty.bits}"
        elif op in ["shuffle_lo16", "shuffle_hi16"]:
            assert ty.ty.bits == 16
            lo_or_hi = "lo" if "lo16" in op else "hi"
            return f"{prefix}shuffle{lo_or_hi}_epi16"
        elif op == "broadcast_lo":
            return f"{prefix}broadcast{suffixes[ty.ty.bits]}_epi{ty.ty.bits}"
        elif op in ["broadcast", "set"]:
            core = op
            if core == "broadcast":
                core = "set1"
            out = f"{prefix}{core}_epi{ty.ty.bits}"
            if ty.ty.bits == 64:
                out += "x"
            return out
        elif op == "mul_lo_32":
            return f"{prefix}mul_ep{iu}32"
        elif op in ["max", "min", "adds", "subs"]:
            return f"{prefix}{op}_ep{iu}{ty.ty.bits}"
        elif op in ["shift_left_const", "shift_right_const"]:
            if "right" in op:
                if ty.ty.signedness == Signedness.SIGNED:
                    return f"{prefix}srai_epi{ty.ty.bits}"
                else:
                    return f"{prefix}srli_epi{ty.ty.bits}"
            else:
                return f"{prefix}slli_epi{ty.ty.bits}"
        elif op in ["gather", "masked_gather"]:
            masked = "mask_" if "masked" in op else ""
            assert ty2 is not None
            values = ty
            indices = ty2
            assert values.count == indices.count, repr((values, indices))
            if indices.ty.bits == 32:
                assert indices.ty.signedness == Signedness.SIGNED
            if indices.bits == 256:
                prefix = "_mm256_"
            return f"{prefix}{masked}i{indices.ty.bits}gather_epi{values.ty.bits}"
        elif op == "convert":
            assert ty2 is not None
            dst = ty
            src = ty2
            assert dst.ty.signedness == src.ty.signedness
            assert dst.ty.bits >= src.ty.bits
            return f"{prefix}cvtep{iu}{src.ty.bits}_epi{dst.ty.bits}"
        elif op == "permute":
            assert ty.bits == 256
            assert ty.ty.bits == 64
            return "_mm256_permute4x64_epi64"
        elif op in [
            "shift_lo_left",
            "shift_lo_right",
            "shift_var_left",
            "shift_var_right",
        ]:
            v = "v" if "var" in op else ""
            if "left" in op:
                return f"{prefix}sll{v}_epi{ty.ty.bits}"
            else:
                if ty.ty.signedness == Signedness.SIGNED:
                    return f"{prefix}sra{v}_epi{ty.ty.bits}"
                else:
                    return f"{prefix}srl{v}_epi{ty.ty.bits}"
        raise Exception(f"TODO: {repr(ty)}, {repr(op)}, {repr(ty2)}")

    def __call__(self, ty, op, ty2=None):
        intrinsic = self.intrinsic_name(ty, op, ty2)
        self.needed_intrinsics.add(intrinsic)
        return intrinsic

    def convert_type(self, ty):
        ty = ty.replace(" *", "*")
        mapping = {
            "__m128i": "::std::arch::x86_64::__m128i",
            "__m256i": "::std::arch::x86_64::__m256i",
            "__int32": "i32",
            "unsigned int": "u32",
            "int": "i32",
            "char": "i8",
            "short": "i16",
            "const unsigned int": "u32",
            "const int": "i32",
            "__m64": "i64",
            "long long": "i64",
            "__m128i*": "*mut ::std::arch::x86_64::__m128i",
            "__m256i*": "*mut ::std::arch::x86_64::__m256i",
            "__m128i const*": "*const ::std::arch::x86_64::__m128i",
            "__m256i const*": "*const ::std::arch::x86_64::__m256i",
            "int const*": "*const i32",
            "__int64 const*": "*const i64",
            "__int64": "i64",
        }
        if ty in mapping:
            return mapping[ty]
        else:
            raise Exception("TODO: handle type: " + repr(ty))

    @property
    def cfg_body(self):
        # TODO: why can't we specify SSE4.1?
        core = (
            "all("
            + ", ".join(
                f"target_feature = {json.dumps(flag.lower())}"
                for flag in sorted(list(self.flags))
            )
            + ")"
        )
        return f'all(target_arch="x86_64", {core})'

    def define_intrinsics(self):
        out = ""

        def line(x):
            nonlocal out
            out += x
            out += "\n"

        line("#![allow(non_upper_case_globals, non_snake_case)]")
        for name in sorted(list(self.needed_intrinsics)):
            intrinsic = INTEL_INTRINSICS_XML[name]
            assert intrinsic.tag == "intrinsic"
            immediate_override = INTRINSIC_IMMEDIATE_ARGUMENT_OVERRIDES.get(name)
            required_cpuid = set(x.text for x in intrinsic.findall("CPUID"))
            missing_cpuid = required_cpuid - self.flags
            if len(missing_cpuid) > 0:
                raise Exception(
                    f"Intrinsic {name} requires missing CPU flags {repr(missing_cpuid)}"
                )
            # TODO: this is the case for the intrinsics we care about. There are still
            # some other unsafe intrinsics.
            unsafe = any(
                "*" in param.get("type") for param in intrinsic.findall("parameter")
            )
            unsafe = "unsafe " if unsafe else ""
            immediates = {}
            for param in intrinsic.findall("parameter"):
                if param.get("etype") != "IMM":
                    continue
                # With current const generics support, we can't do `x as i32` if `x as i32`
                # is destined for a const generic parameter. However, the immediate
                # arguments to intrinsics are just any constant. So we can push the type
                # coercion into the intrinsic's wrapper.
                # TODO: do we always want usize for the immediates?
                immediates[param.get("varname")] = "usize"
            if immediate_override:
                immediates = immediate_override.const_args
            if len(immediates) == 0:
                immediates = ""
            else:
                immediates = (
                    "<"
                    + ", ".join(f"const {k}: {v}" for k, v in immediates.items())
                    + ">"
                )
            line("#[inline(always)]")
            line(f"pub(super) {unsafe}fn {name}{immediates}(")
            num_params = len(intrinsic.findall("parameter"))
            has_immediate = False
            for i, param in enumerate(intrinsic.findall("parameter")):
                if param.get("etype") == "IMM":
                    if param.get("immwidth") is not None:
                        assert int(param.get("immwidth")) <= 8, name
                    assert i == num_params - 1
                    has_immediate = True
                    continue
                if param.get("type") == "void":
                    continue
                line(f"{param.get('varname')}: {self.convert_type(param.get('type'))},")
            rt = intrinsic.find("return").get("type")
            if rt == "void":
                line(") {")
            else:
                line(f") -> {self.convert_type(rt)} {{")
            param_body = ", ".join(
                param.get("varname")
                for param in intrinsic.findall("parameter")
                if param.get("type") != "void" and param.get("etype") != "IMM"
            )
            if has_immediate:
                param = intrinsic.findall("parameter")[-1]
                imm_body = (
                    immediate_override.immediate_body
                    if param.get("etype") == "IMM" and immediate_override
                    else param.get("varname")
                )
                imm_kind = "0..256"
                if param.get("immtype") == "_MM_INDEX_SCALE":
                    imm_kind = "[1, 2, 4, 8]"
                elif name in ["_mm256_bslli_epi128", "_mm256_slli_si256"]:
                    imm_kind = "0..32"
                elif param.get("immwidth") == "1" and name != "_mm_clmulepi64_si128":
                    imm_kind = "0..2"
                elif param.get("immwidth") == "4":
                    imm_kind = "0..16"
                elif param.get("immwidth") == "2":
                    imm_kind = "0..4"
                elif param.get("immwidth") == "3":
                    imm_kind = "0..8"
                elif param.get("immwidth") == "5":
                    imm_kind = "0..32"
                assert param.get("immwidth") in [
                    None,
                    "1",
                    "4",
                    "2",
                    "8",
                    "3",
                    "5",
                ], name
                imm_body += f" as {self.convert_type(param.get('type'))}"
                core = f"constify_imm!(::std::arch::x86_64::{name} => ({param_body}, @@ [{imm_kind}] {imm_body}))"
            else:
                core = f"::std::arch::x86_64::{name}({param_body})"
            if unsafe:
                line(core)
            else:
                line(
                    "// SAFETY: we've verified that the required CPU flags are available."
                )
                line(f"unsafe {{ {core} }}")
            line("}")
        return out
