#!/usr/bin/python3
# coding: utf-8
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

"""A simple implementation of P-256 (ECDH, ECDSA) for tests."""

import secrets
import hashlib


class ModInt:
    """Modular integer."""

    def __init__(self, x, n):
        """Build x mod n."""
        self.x = x % n
        self.n = n

    def __repr__(self):
        """Represent self."""
        return "ModInt({}, {})".format(self.x, self.n)

    def __int__(self):
        """Return the representant in [0, n)."""
        return self.x

    def __eq__(self, other):
        """Compare to another ModInt."""
        return self.x == other.x and self.n == other.n

    def __add__(self, other):
        """Add to another ModInt."""
        return ModInt(self.x + other.x, self.n)

    def __sub__(self, other):
        """Subtract another ModInt."""
        return ModInt(self.x - other.x, self.n)

    def __neg__(self):
        """Negate self."""
        return ModInt(-self.x, self.n)

    def __mul__(self, other):
        """Multiply by another ModInt."""
        return ModInt(self.x * other.x, self.n)

    def __rmul__(self, other):
        """Multiply self by an integer."""
        return ModInt(self.x * other, self.n)

    def __pow__(self, other):
        """Elevate to an integer power."""
        return ModInt(pow(self.x, other, self.n), self.n)

    def inv(self):
        """Return modular inverse as a ModInt or raise ZeroDivisionError."""
        a, b, u, s = self.x, self.n, 1, 0
        # invariants: a < b and a == u*x mod n and b == s*x mod n
        while a > 1:
            q, r = divmod(b, a)  # r = b - q*a
            a, b, u, s = r, a, s - q*u, u
        if a != 1:
            raise ZeroDivisionError
        return ModInt(u, self.n)

    def __truediv__(self, other):
        """Divide by another ModInt or raise ZeroDivisionError."""
        return self * other.inv()

    def is_zero(self):
        """Tell if we're 0."""
        return self.x == 0


class Curve:
    """Curve parameters - Short Weierstrass curves over GF(p), p > 3."""

    # assuming cofactor of 1 (true for NIST and Brainpool curves),
    # so n is the order of the curve and of the base point G

    def __init__(self, name, *, p, a, b, gx, gy, n):
        """Build a Curve from the given int parameters."""
        self.name = name
        self.p = p
        self.a = ModInt(a, p)
        self.b = ModInt(b, p)
        self.gx = ModInt(gx, p)
        self.gy = ModInt(gy, p)
        self.n = n

        self.p_bits = p.bit_length()
        self.p_bytes = (self.p_bits + 7) // 8

        self.n_bits = n.bit_length()
        self.n_bytes = (self.n_bits + 7) // 8

    def __str__(self):
        """Human-friendly name."""
        return self.name

    def zero(self):
        """Return the origin (point at infinity)."""
        return CurvePoint(None, self)

    def base_point(self):
        """Return this curve's conventional base point."""
        return CurvePoint((self.gx, self.gy), self)


# rfc 6090 app. D, or rfc 5903 3.1, or sec2-v2 2.4.2, or FIPS 186-4 D.1.2.3
p256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
)


class CurvePoint:
    """Point on a Curve."""

    def __init__(self, coordinates, curve):
        """Coordinates is either a pair of ModInt or None for 0."""
        self.coord = coordinates
        self.curve = curve

    def is_zero(self):
        """Tell if this is 0 (aka the origin aka the point at infinity."""
        return self.coord is None

    def x(self):
        """Return the x coordinate as a ModInt."""
        return self.coord[0]

    def y(self):
        """Return the y coordinate as a ModInt."""
        return self.coord[1]

    def __eq__(self, other):
        """Compare to another point on the curve."""
        if self.is_zero() and other.is_zero():
            return True

        if self.is_zero() or other.is_zero():
            return False

        return self.x() == other.x() and self.y() == other.y()

    def __add__(self, other):
        """Add to another point - RFC 6090 Appendix F.1."""
        if self.is_zero():
            return other

        if other.is_zero():
            return self

        x1, y1, x2, y2 = self.x(), self.y(), other.x(), other.y()

        if self != other and x1 == y1:
            return CurvePoint(None, self.curve)

        if self != other:
            x3 = ((y2-y1) / (x2-x1))**2 - x1 - x2
            y3 = (x1-x3) * (y2-y1) / (x2-x1) - y1
            return CurvePoint((x3, y3), self.curve)

        # this can't happen with curves of large prime order,
        # but let's just follow the formulas in the RFC
        if y1.is_zero():
            return CurvePoint(None, self.curve)

        a = self.curve.a
        x3 = ((3*x1**2 + a) / (2*y1))**2 - 2*x1
        y3 = (x1-x3)*(3*x1**2 + a) / (2*y1) - y1
        return CurvePoint((x3, y3), self.curve)

    def __rmul__(self, other):
        """Multiply self by a positive integer (scalar multiplication)."""
        # invariant: result + scale * scalar = self * other
        result = self.curve.zero()
        scale = self
        scalar = other
        while scalar != 0:
            if scalar % 2 != 0:
                result += scale
            scale += scale
            scalar //= 2

        return result


def ecdsa_modint_from_hash(msg_hash, n, nbits):
    """Derive an integer mod n from a message hash for ECDSA."""
    # This is Sec1 4.1.3 step 5 or 4.1.4 step 3
    # Subteps 1-3: simplify when nbits is a multiple of 8
    assert(nbits % 8 == 0)
    use_len = min(32, len(msg_hash))
    msg_hash = msg_hash[:use_len]
    # Substep 4: 2.3.8 says big endian
    e = int.from_bytes(msg_hash, 'big')
    # Extra: mod n
    return ModInt(e, n)


class EcdsaSigner:
    """A private key, able to create ECDSA signatures."""

    def __init__(self, curve, d=None):
        """Create an ECDSA private key for curve or load it from an int."""
        self.curve = curve
        self.d = d if d is not None else self._gen_scalar()

    def _gen_scalar(self):
        # sec1 3.2.1: d in [1, n-1] ( = [0, n-1) + 1 )
        return secrets.randbelow(self.curve.n - 1) + 1

    def _gen_public(self, d):
        return d * self.curve.base_point()

    def public_key(self):
        """Return the associated public key as a CurvePoint."""
        return self._gen_public(self.d)

    def sign(self, msg_hash, k=None):
        """Generate a signature (int pair) for that message hash (bytes)."""
        # sec1 4.1.3, but instead of retrying just abort
        n = self.curve.n
        nbits = self.curve.n_bits
        # 1. Set ephemeral keypair
        if k is None:
            k = self._gen_scalar()
        R = self._gen_public(k)
        k = ModInt(k, n)
        # 2, 3. Convert to integer mod n
        r = ModInt(int(R.x()), n)
        assert(not r.is_zero())
        # 4. Skipped - we take the hash as input
        # 5. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 6. Compute s
        d = ModInt(self.d, n)
        s = (e + r * d) / k
        assert(not s.is_zero())
        # 7. Output two integers
        return (int(r), int(s))


class EcdsaVerifier:
    """An ECDSA public key, able to verify signatures."""

    def __init__(self, curve, public_key):
        """Create an ECDSA verifier from a public key (CurvePoint)."""
        self.curve = curve
        self.Q = public_key

    def is_valid(self, sig, msg_hash):
        """Tell if signature (int pair) is valid for that hash (bytes)."""
        # sec1 4.1.4
        n = self.curve.n
        nbits = self.curve.n_bits
        r, s = sig
        # 1. Verify range
        if not (0 < r < n and 0 < s < n):
            return False
        # 2. Skip hashing - we take the hash as input
        # 3. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 4. Compute u1, u2
        r = ModInt(r, n)
        s = ModInt(s, n)
        u1 = e / s
        u2 = r / s
        # 5. Compute R
        R = int(u1) * self.curve.base_point() + int(u2) * self.Q
        if R.is_zero():
            return False
        # 6, 7. Convert to v
        v = ModInt(int(R.x()), n)
        # 8. Compare
        return v == r


# Section 8.1 of RFC 5903
tv_ecdh_rfc5903 = dict(
    i=0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433,
    gix=0xDAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180,
    giy=0x5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3,
    r=0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53,
    grx=0xD12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63,
    gry=0x56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB,
    girx=0xD6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE,
    giry=0x522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2,
)

# NIST KAS_ECC_CDH_PrimitiveTest.txt P-256 counts 0 to 9
tv_ecdh_nist = (
    dict(
        ox=0x700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287,
        oy=0xdb71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac,
        d=0x7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534,
        Qx=0xead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230,
        Qy=0x28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141,
        Z=0x46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b,
    ), dict(
        ox=0x809f04289c64348c01515eb03d5ce7ac1a8cb9498f5caa50197e58d43a86a7ae,
        oy=0xb29d84e811197f25eba8f5194092cb6ff440e26d4421011372461f579271cda3,
        d=0x38f65d6dce47676044d58ce5139582d568f64bb16098d179dbab07741dd5caf5,
        Qx=0x119f2f047902782ab0c9e27a54aff5eb9b964829ca99c06b02ddba95b0a3f6d0,
        Qy=0x8f52b726664cac366fc98ac7a012b2682cbd962e5acb544671d41b9445704d1d,
        Z=0x057d636096cb80b67a8c038c890e887d1adfa4195e9b3ce241c8a778c59cda67,
    ), dict(
        ox=0xa2339c12d4a03c33546de533268b4ad667debf458b464d77443636440ee7fec3,
        oy=0xef48a3ab26e20220bcda2c1851076839dae88eae962869a497bf73cb66faf536,
        d=0x1accfaf1b97712b85a6f54b148985a1bdc4c9bec0bd258cad4b3d603f49f32c8,
        Qx=0xd9f2b79c172845bfdb560bbb01447ca5ecc0470a09513b6126902c6b4f8d1051,
        Qy=0xf815ef5ec32128d3487834764678702e64e164ff7315185e23aff5facd96d7bc,
        Z=0x2d457b78b4614132477618a5b077965ec90730a8c81a1c75d6d4ec68005d67ec,
    ), dict(
        ox=0xdf3989b9fa55495719b3cf46dccd28b5153f7808191dd518eff0c3cff2b705ed,
        oy=0x422294ff46003429d739a33206c8752552c8ba54a270defc06e221e0feaf6ac4,
        d=0x207c43a79bfee03db6f4b944f53d2fb76cc49ef1c9c4d34d51b6c65c4db6932d,
        Qx=0x24277c33f450462dcb3d4801d57b9ced05188f16c28eda873258048cd1607e0d,
        Qy=0xc4789753e2b1f63b32ff014ec42cd6a69fac81dfe6d0d6fd4af372ae27c46f88,
        Z=0x96441259534b80f6aee3d287a6bb17b5094dd4277d9e294f8fe73e48bf2a0024,
    ), dict(
        ox=0x41192d2813e79561e6a1d6f53c8bc1a433a199c835e141b05a74a97b0faeb922,
        oy=0x1af98cc45e98a7e041b01cf35f462b7562281351c8ebf3ffa02e33a0722a1328,
        d=0x59137e38152350b195c9718d39673d519838055ad908dd4757152fd8255c09bf,
        Qx=0xa8c5fdce8b62c5ada598f141adb3b26cf254c280b2857a63d2ad783a73115f6b,
        Qy=0x806e1aafec4af80a0d786b3de45375b517a7e5b51ffb2c356537c9e6ef227d4a,
        Z=0x19d44c8d63e8e8dd12c22a87b8cd4ece27acdde04dbf47f7f27537a6999a8e62,
    ), dict(
        ox=0x33e82092a0f1fb38f5649d5867fba28b503172b7035574bf8e5b7100a3052792,
        oy=0xf2cf6b601e0a05945e335550bf648d782f46186c772c0f20d3cd0d6b8ca14b2f,
        d=0xf5f8e0174610a661277979b58ce5c90fee6c9b3bb346a90a7196255e40b132ef,
        Qx=0x7b861dcd2844a5a8363f6b8ef8d493640f55879217189d80326aad9480dfc149,
        Qy=0xc4675b45eeb306405f6c33c38bc69eb2bdec9b75ad5af4706aab84543b9cc63a,
        Z=0x664e45d5bba4ac931cd65d52017e4be9b19a515f669bea4703542a2c525cd3d3,
    ), dict(
        ox=0x6a9e0c3f916e4e315c91147be571686d90464e8bf981d34a90b6353bca6eeba7,
        oy=0x40f9bead39c2f2bcc2602f75b8a73ec7bdffcbcead159d0174c6c4d3c5357f05,
        d=0x3b589af7db03459c23068b64f63f28d3c3c6bc25b5bf76ac05f35482888b5190,
        Qx=0x9fb38e2d58ea1baf7622e96720101cae3cde4ba6c1e9fa26d9b1de0899102863,
        Qy=0xd5561b900406edf50802dd7d73e89395f8aed72fba0e1d1b61fe1d22302260f0,
        Z=0xca342daa50dc09d61be7c196c85e60a80c5cb04931746820be548cdde055679d,
    ), dict(
        ox=0xa9c0acade55c2a73ead1a86fb0a9713223c82475791cd0e210b046412ce224bb,
        oy=0xf6de0afa20e93e078467c053d241903edad734c6b403ba758c2b5ff04c9d4229,
        d=0xd8bf929a20ea7436b2461b541a11c80e61d826c0a4c9d322b31dd54e7f58b9c8,
        Qx=0x20f07631e4a6512a89ad487c4e9d63039e579cb0d7a556cb9e661cd59c1e7fa4,
        Qy=0x6de91846b3eee8a5ec09c2ab1f41e21bd83620ccdd1bdce3ab7ea6e02dd274f5,
        Z=0x35aa9b52536a461bfde4e85fc756be928c7de97923f0416c7a3ac8f88b3d4489,
    ), dict(
        ox=0x94e94f16a98255fff2b9ac0c9598aac35487b3232d3231bd93b7db7df36f9eb9,
        oy=0xd8049a43579cfa90b8093a94416cbefbf93386f15b3f6e190b6e3455fedfe69a,
        d=0x0f9883ba0ef32ee75ded0d8bda39a5146a29f1f2507b3bd458dbea0b2bb05b4d,
        Qx=0xabb61b423be5d6c26e21c605832c9142dc1dfe5a5fff28726737936e6fbf516d,
        Qy=0x733d2513ef58beab202090586fac91bf0fee31e80ab33473ab23a2d89e58fad6,
        Z=0x605c16178a9bc875dcbff54d63fe00df699c03e8a888e9e94dfbab90b25f39b4,
    ), dict(
        ox=0xe099bf2a4d557460b5544430bbf6da11004d127cb5d67f64ab07c94fcdf5274f,
        oy=0xd9c50dbe70d714edb5e221f4e020610eeb6270517e688ca64fb0e98c7ef8c1c5,
        d=0x2beedb04b05c6988f6a67500bb813faf2cae0d580c9253b6339e4a3337bb6c08,
        Qx=0x3d63e429cb5fa895a9247129bf4e48e89f35d7b11de8158efeb3e106a2a87395,
        Qy=0x0cae9e477ef41e7c8c1064379bb7b554ddcbcae79f9814281f1e50f0403c61f3,
        Z=0xf96e40a1b72840854bb62bc13c40cc2795e373d4e715980b261476835a092e0b,
    )
)

# Section 8.1 of RFC 4754
tv_ecdsa_rfc4754 = dict(
    w=0xDC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F,
    gwx=0x2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970,
    gwy=0x6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D,
    k=0x9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE,
    r=0xCB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C,
    s=0x86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315,
    h="BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
)

# Section A.2.5 of RFC 6979
tv_ecdsa_rfc6979_key = dict(
    x=0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
    Ux=0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
    Uy=0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299,
)
tv_ecdsa_rfc6979 = (
    dict(
        h=hashlib.sha1(b"sample").digest(),
        k=0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4,
        r=0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32,
        s=0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB,
    ), dict(
        h=hashlib.sha224(b"sample").digest(),
        k=0x103F90EE9DC52E5E7FB5132B7033C63066D194321491862059967C715985D473,
        r=0x53B2FFF5D1752B2C689DF257C04C40A587FABABB3F6FC2702F1343AF7CA9AA3F,
        s=0xB9AFB64FDC03DC1A131C7D2386D11E349F070AA432A4ACC918BEA988BF75C74C,
    ), dict(
        h=hashlib.sha256(b"sample").digest(),
        k=0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60,
        r=0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716,
        s=0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8,
    ), dict(
        h=hashlib.sha384(b"sample").digest(),
        k=0x09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4,
        r=0x0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719,
        s=0x4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954,
    ), dict(
        h=hashlib.sha512(b"sample").digest(),
        k=0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5,
        r=0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00,
        s=0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE,
    ), dict(
        h=hashlib.sha1(b"test").digest(),
        k=0x8C9520267C55D6B980DF741E56B4ADEE114D84FBFA2E62137954164028632A2E,
        r=0x0CBCC86FD6ABD1D99E703E1EC50069EE5C0B4BA4B9AC60E409E8EC5910D81A89,
        s=0x01B9D7B73DFAA60D5651EC4591A0136F87653E0FD780C3B1BC872FFDEAE479B1,
    ), dict(
        h=hashlib.sha224(b"test").digest(),
        k=0x669F4426F2688B8BE0DB3A6BD1989BDAEFFF84B649EEB84F3DD26080F667FAA7,
        r=0xC37EDB6F0AE79D47C3C27E962FA269BB4F441770357E114EE511F662EC34A692,
        s=0xC820053A05791E521FCAAD6042D40AEA1D6B1A540138558F47D0719800E18F2D,
    ), dict(
        h=hashlib.sha256(b"test").digest(),
        k=0xD16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0,
        r=0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367,
        s=0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083,
    ), dict(
        h=hashlib.sha384(b"test").digest(),
        k=0x16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8,
        r=0x83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6,
        s=0x8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C,
    ), dict(
        h=hashlib.sha512(b"test").digest(),
        k=0x6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F,
        r=0x461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04,
        s=0x39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55,
    ),
)


if __name__ == '__main__':
    print("P-256 ECDH test vectors from RFC 5903 Sec. 8.1...",
          end=' ', flush=True)
    tv = tv_ecdh_rfc5903

    gi = tv['i'] * p256.base_point()
    assert(tv['gix'] == int(gi.x()) and tv['giy'] == int(gi.y()))

    gr = tv['r'] * p256.base_point()
    assert(tv['grx'] == int(gr.x()) and tv['gry'] == int(gr.y()))

    si = tv['i'] * gr
    assert(tv['girx'] == int(si.x()) and tv['giry'] == int(si.y()))

    sr = tv['r'] * gi
    assert(tv['girx'] == int(sr.x()) and tv['giry'] == int(sr.y()))

    print("OK")

    print("P-256 ECDH test vectors from NIST...",
          end=' ', flush=True)

    for tv in tv_ecdh_nist:
        Q = tv['d'] * p256.base_point()
        assert(tv['Qx'] == int(Q.x()) and tv['Qy'] == int(Q.y()))

        ox = ModInt(tv['ox'], p256.p)
        oy = ModInt(tv['oy'], p256.p)
        o = CurvePoint((ox, oy), p256)
        do = tv['d'] * o
        assert(tv['Z'] == int(do.x()))

    print("OK")

    print("P-256 ECDSA test vectors from RFC 4754 Sec. 8.1...",
          end=' ', flush=True)
    tv = tv_ecdsa_rfc4754
    h = bytes.fromhex(tv['h'])

    # signature generation
    signer = EcdsaSigner(p256, tv['w'])
    sig = signer.sign(h, tv['k'])
    assert(sig == (tv['r'], tv['s']))

    # key generation
    pub = signer.public_key()
    assert(tv['gwx'] == int(pub.x()))
    assert(tv['gwy'] == int(pub.y()))

    # signature verification
    verif = EcdsaVerifier(p256, pub)
    assert(verif.is_valid((tv['r'], tv['s']), h) is True)

    bad_r = tv['r'] + 1
    bad_s = tv['s'] + 1
    bad_h = h[::-1]
    assert(verif.is_valid((bad_r, tv['s']), h) is False)
    assert(verif.is_valid((tv['r'], bad_s), h) is False)
    assert(verif.is_valid((tv['r'], tv['s']), bad_h) is False)

    print("OK")

    print("P-256 ECDSA test vectors from RFC 6979 A.2.5...",
          end=' ', flush=True)

    # key generation
    tv = tv_ecdsa_rfc6979_key
    signer = EcdsaSigner(p256, tv['x'])
    pub = signer.public_key()
    assert(tv['Ux'] == int(pub.x()))
    assert(tv['Uy'] == int(pub.y()))
    verif = EcdsaVerifier(p256, pub)

    # signature generation and verification
    for tv in tv_ecdsa_rfc6979:
        h, k, r, s = tv['h'], tv['k'], tv['r'], tv['s']
        sig = signer.sign(h, k)
        assert(sig == (r, s))
        assert(verif.is_valid((r, s), h) is True)
        assert(verif.is_valid((r+1, s), h) is False)
        assert(verif.is_valid((r, s+1), h) is False)
        assert(verif.is_valid((r, s), h[::-1]) is False)

    print("OK")
