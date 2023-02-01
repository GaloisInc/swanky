from collections import namedtuple
import math
from random import randint

R = 40  # polynomial num coefficients


def humansize(nbytes):
    # Copied from stackoverflow!
    # https://stackoverflow.com/a/14996816
    suffixes = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while nbytes >= 1024 and i < len(suffixes) - 1:
        nbytes /= 1024.0
        i += 1
    f = ("%.2f" % nbytes).rstrip("0").rstrip(".")
    return "%s %s" % (f, suffixes[i])


class LpnParams(namedtuple("LpnParams", "k n t")):
    "m = self.n // self.t MUST be a power of 2"

    def bits_of_security(self):
        return math.log2((self.k + 1) / (1 - self.k / self.n) ** self.t)

    def num_output_voles(self):
        # assuming F2
        return self.n - (self.k + self.t + R)

    def matrix_size_bytes(self):
        return (self.k + self.t + R) * 8

    def matrix_compressed_size_bytes(self):
        count = self.k + self.t + R
        return count * ((5 + 5 + 1) / 2)

    def m(self):
        return self.n // self.t

    def kos_ot_cost(self, choices):
        out = 0
        # TODO: kos.rs:37 send_setup
        # kos.rs:115
        out += 16 * choices
        # kos.rs:116
        out += 16 * choices
        return out

    def communication_bytes(self, bytes_per_f2=1):
        n = self.m()
        r = R
        base_voles = self.t + r
        base_uwus = base_voles - r
        total_len = base_voles
        base_consistency = total_len - (total_len - r)
        t = base_uwus
        out = 0
        # spsvole.rs:151
        out += base_uwus * bytes_per_f2  # write F2 field element
        nbits = int(math.log2(n))
        choices = nbits * t
        # spsvole.rs:164
        out += self.kos_ot_cost(choices)
        # spsvole.rs:180
        out += base_uwus * bytes_per_f2  # write F2 field element
        # Batch consistency check
        out += r * bytes_per_f2  # spsvole:223
        out += 16  # spsvole:226
        # eq_send
        # spsvole.rs:55
        out += bytes_per_f2 + 32 + 32 + bytes_per_f2 + 32
        return out

    def compressed_communication_bytes(self):
        return self.communication_bytes(bytes_per_f2=0.125)

    def bits_per_vole(self):
        return self.communication_bytes() * 8 / self.num_output_voles()

    def compressed_bits_per_vole(self):
        return self.compressed_communication_bytes() * 8 / self.num_output_voles()

    def describe(self):
        print(repr(self))
        for k, conv in [
            ("m", lambda x: x),
            ("bits_of_security", float),
            ("num_output_voles", lambda x: x),
            ("matrix_size_bytes", humansize),
            ("matrix_compressed_size_bytes", humansize),
            ("communication_bytes", humansize),
            ("bits_per_vole", float),
            ("compressed_bits_per_vole", float),
            ("compressed_communication_bytes", humansize),
        ]:
            print("    %s = %s" % (k, str(conv(getattr(self, k)()))))

    @classmethod
    def from_log2m(cls, k, log2m, t):
        m = 2**log2m
        n = m * t
        return cls(k, n, t)


if False:

    def possible_configs():
        for log2m in range(4, 16):
            # for log2num_saved in range(4, 24):
            # num_saved = 2**log2num_saved
            for num_saved in range(1000, 1_000_000, 1000):
                for t in range(64, 10_000_000, 1000):
                    try:
                        out = LpnParams.from_log2m(num_saved - R - t, log2m, t)
                        if float(out.bits_of_security()) < 120:
                            continue
                        if out.num_output_voles() < 0:
                            continue
                        if out.bits_per_vole() < 0:
                            continue
                        if out.bits_per_vole() >= 3.25:
                            continue
                        yield out
                    except ValueError:
                        continue
                    except ZeroDivisionError:
                        continue
                    except OverflowError:
                        continue

    SKL_L2_CACHE = 256 * 1024
    SKL_L1_CACHE = 32 * 1024

    min(
        possible_configs(), key=lambda cfg: cfg.matrix_compressed_size_bytes()
    ).describe()

"""
LpnParams(k=71896, n=1089536, t=1064)
    m = 1024
    bits_of_security = 120.92336703713016
    num_output_voles = 1016575
    matrix_size_bytes = 570.31 KB
    matrix_compressed_size_bytes = 392.09 KB
    communication_bytes = 334.73 KB
    bits_per_vole = 2.6973868135651573
    compressed_communication_bytes = 332.87 KB
NUM SAVED: 65601
LpnParams(k=65275, n=292864, t=286)
    m = 1024
    bits_of_security = 120.04107430485803
    num_output_voles = 227302
    matrix_size_bytes = 512.51 KB
    matrix_compressed_size_bytes = 352.35 KB
    communication_bytes = 90.08 KB
    bits_per_vole = 3.246641032634997
    compressed_communication_bytes = 89.56 KB
NUM SAVED: 65567
LpnParams(k=65242, n=291840, t=285)
    m = 1024
    bits_of_security = 120.03064997333392
    num_output_voles = 226312
    matrix_size_bytes = 512.24 KB
    matrix_compressed_size_bytes = 352.17 KB
    communication_bytes = 89.77 KB
    bits_per_vole = 3.2494609212061225
NUM SAVED: 65551
LpnParams(k=65226, n=291840, t=285)
    m = 1024
    bits_of_security = 120.0012647278601
    num_output_voles = 226328
    matrix_size_bytes = 512.12 KB
    matrix_compressed_size_bytes = 352.08 KB
    communication_bytes = 89.77 KB
    bits_per_vole = 3.249231204269909
    compressed_communication_bytes = 89.25 KB
NUM SAVED: 65381
LpnParams(k=65062, n=285696, t=279)
    m = 1024
    bits_of_security = 120.0079222736336
    num_output_voles = 220354
    matrix_size_bytes = 510.79 KB
    matrix_compressed_size_bytes = 351.17 KB
    communication_bytes = 87.88 KB
    bits_per_vole = 3.267179175326974
    compressed_communication_bytes = 87.37 KB
NUM SAVED: 65378
LpnParams(k=65059, n=285696, t=279)
    m = 1024
    bits_of_security = 120.00238276126557
    num_output_voles = 220357
    matrix_size_bytes = 510.77 KB
    matrix_compressed_size_bytes = 351.15 KB
    communication_bytes = 87.88 KB
    bits_per_vole = 3.2671346950630116
    compressed_bits_per_vole = 3.2480747151213714
    compressed_communication_bytes = 87.37 KB
NUM SAVED: 65377
LpnParams(k=65058, n=285696, t=279)
    m = 1024
    bits_of_security = 120.00053627299816
    num_output_voles = 220358
    matrix_size_bytes = 510.76 KB
    matrix_compressed_size_bytes = 351.15 KB
    communication_bytes = 87.88 KB
    bits_per_vole = 3.2671198685774967
    compressed_bits_per_vole = 3.248059975131377
    compressed_communication_bytes = 87.37 KB
"""
if False:
    acu = LpnParams(k=65059, n=285696, t=279)
    acu_num_saved = acu.k + acu.t + R
    while True:
        log2m = randint(8, 12)
        # num_saved = randint(acu_num_saved // 2, (acu_num_saved or 65536) + 1)
        num_saved = randint(acu_num_saved - 256, acu_num_saved + 1)
        t = randint(1, acu.t * 2)
        try:
            out = LpnParams.from_log2m(num_saved - R - t, log2m, t)
            if float(out.bits_of_security()) < 120:
                continue
            if out.num_output_voles() < 0:
                continue
            if out.compressed_bits_per_vole() < 0:
                continue
            if out.compressed_bits_per_vole() >= 3.25:
                continue
            if acu is None or acu.matrix_size_bytes() > out.matrix_size_bytes():
                print("NUM SAVED: %d" % num_saved)
                out.describe()
                acu = out
                acu_num_saved = num_saved
        except ValueError:
            continue
        except ZeroDivisionError:
            continue
        except OverflowError:
            continue

log2m = 10
t = 279
num_saved = 1 << 16
LpnParams.from_log2m(num_saved - R - t, log2m, t).describe()

"""
With this, arrays are 2^16 in size, so we can avoid the multiply and can do masking for the bounded
multiplication.

LpnParams(k=65217, n=285696, t=279)
    m = 1024
    bits_of_security = 120.29422754194812
    num_output_voles = 220199
    matrix_size_bytes = 512 KB
    matrix_compressed_size_bytes = 352 KB
    communication_bytes = 87.88 KB
    bits_per_vole = 3.2694789712941477
    compressed_bits_per_vole = 3.2504053151921672
    compressed_communication_bytes = 87.37 KB
"""
