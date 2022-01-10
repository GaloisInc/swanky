import enum
from collections import namedtuple
from itertools import product, takewhile


class BoolType(namedtuple("BoolType", "")):
    def __bool__(self):
        return True

    def __str__(self):
        return "bool"


class Signedness(enum.Enum):
    SIGNED = "i"
    UNSIGNED = "u"


class IntegerType(namedtuple("IntegerType", "signedness bits")):
    @property
    def signed(self):
        return IntegerType(signedness=Signedness.SIGNED, bits=self.bits)

    @property
    def unsigned(self):
        return IntegerType(signedness=Signedness.UNSIGNED, bits=self.bits)

    @property
    def proptest_strategy(self):
        return f"any::<{self}>()"

    def __str__(self):
        return f"{self.signedness.value}{self.bits}"


INTEGER_TYPES = [IntegerType(s, b) for s, b in product(Signedness, [8, 16, 32, 64])]
VECTOR_SIZES = [128, 256]


class VectorType(namedtuple("VectorType", "ty count")):
    @property
    def signed(self):
        return VectorType(self.ty.signed, self.count)

    @property
    def unsigned(self):
        return VectorType(self.ty.unsigned, self.count)

    @property
    def bits(self):
        return self.count * self.ty.bits

    @property
    def array(self):
        return ArrayType(self.ty, self.count)

    @property
    def proptest_strategy(self):
        return f"any::<[{self.ty}; {self.count}]>()"

    @property
    def broadcast_lo_from(self):
        return VectorType(self.ty, 128 // self.ty.bits)

    @property
    def can_cast_from(self):
        global VECTOR_TYPES
        return [x for x in VECTOR_TYPES if x != self and x.bits == self.bits]

    @property
    def can_convert_from(self):
        global VECTOR_TYPES
        return [
            x
            for x in VECTOR_TYPES
            if x != self
            and x.ty.bits < self.ty.bits
            and x.count == self.count
            and x.ty.signedness == self.ty.signedness
        ]

    @property
    def can_extending_cast_from(self):
        global VECTOR_TYPES
        return [
            x
            for x in VECTOR_TYPES
            if x != self
            and x.ty.signedness == self.ty.signedness
            and x.ty.bits < self.ty.bits
            and x.bits <= self.bits
            and x.bits == 128
        ]

    def __str__(self):
        return f"{str(self.ty).upper()}x{self.count}"


class ArrayType(VectorType):
    def __str__(self):
        return f"[{self.ty}; {self.count}]"


VECTOR_TYPES = [
    VectorType(ty, sz // ty.bits) for ty, sz in product(INTEGER_TYPES, VECTOR_SIZES)
]
