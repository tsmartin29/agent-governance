"""Pure-Python Ed25519 (RFC 8032 section 6 reference algorithm, rewritten), so the package has no dependencies.

Slow (tens of milliseconds per signature) and not constant-time: fine for signing a handful of human control entries, not for bulk or
adversarial-timing use. Ed25519 is deterministic, so any RFC 8032 library produces identical signatures."""
import hashlib

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I_SQRT = pow(2, (P - 1) // 4, P)


def _inv(x):
    return pow(x, P - 2, P)


def _point_add(a, b):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = a, b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P
    Dd = 2 * z1 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _point_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_eq(a, b):
    (x1, y1, z1, _), (x2, y2, z2, _) = a, b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I_SQRT % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * _inv(5) % P
G_X = _recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % P)


def _compress(p):
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _secret_expand(seed):
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = _secret_expand(seed)
    return _compress(_point_mul(a, G))


def sign(seed, msg):
    a, prefix = _secret_expand(seed)
    A = _compress(_point_mul(a, G))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % Q
    Rs = _compress(_point_mul(r, G))
    h = int.from_bytes(hashlib.sha512(Rs + A + msg).digest(), "little") % Q
    s = (r + h * a) % Q
    return Rs + int.to_bytes(s, 32, "little")


def verify(pk, msg, sig):
    if len(pk) != 32 or len(sig) != 64:
        return False
    A = _decompress(pk)
    if A is None:
        return False
    Rs = sig[:32]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(Rs + pk + msg).digest(), "little") % Q
    sB = _point_mul(s, G)
    hA = _point_mul(h, A)
    return _point_eq(sB, _point_add(R, hA))


if __name__ == "__main__":                                 # RFC 8032 section 7.1 test 1 and test 2
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert public_key(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = sign(seed, b"")
    assert sig.hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"), sig.hex()
    assert verify(public_key(seed), b"", sig)
    assert not verify(public_key(seed), b"x", sig)
    seed2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    sig2 = sign(seed2, bytes([0x72]))
    assert sig2.hex() == ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                          "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"), sig2.hex()
    print("ed25519_pure: RFC 8032 vectors OK")
