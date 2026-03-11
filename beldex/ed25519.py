import binascii
import nacl.bindings

edwards_add = nacl.bindings.crypto_core_ed25519_add
inv = nacl.bindings.crypto_core_ed25519_scalar_invert
scalar_add = nacl.bindings.crypto_core_ed25519_scalar_add
scalarmult_B = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp
scalarmult = nacl.bindings.crypto_scalarmult_ed25519_noclamp

H = binascii.unhexlify(
    "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
)


def scalarmult_H(v):
    return scalarmult(v, H)


def scalar_reduce(v):
    return nacl.bindings.crypto_core_ed25519_scalar_reduce(v + (64 - len(v)) * b"\0")


def public_from_secret_hex(hk):
    try:
        return binascii.hexlify(scalarmult_B(binascii.unhexlify(hk))).decode()
    except nacl.exceptions.RuntimeError:
        raise ValueError("Invalid secret key")
