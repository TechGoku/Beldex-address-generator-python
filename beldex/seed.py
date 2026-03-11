from binascii import hexlify, unhexlify
from os import urandom
from . import base58, const, ed25519, wordlists
from .address import address
from .keccak import keccak_256


class Seed(object):
    """Creates a seed object either from local system randomness or an imported phrase."""

    def __init__(self, phrase_or_hex="", wordlist="English"):
        """
        Initialize seed from mnemonic phrase or hexadecimal seed.
        If no seed is provided, generate a new random one.
        """

        self.phrase = ""  # 24 or 25 word mnemonic
        self.hex = ""  # hexadecimal seed

        self.word_list = wordlists.get_wordlist(wordlist)

        self._ed_pub_spend_key = None
        self._ed_pub_view_key = None

        if phrase_or_hex:
            seed_split = phrase_or_hex.split(" ")

            if len(seed_split) >= 24:
                # Standard Beldex mnemonic
                self.phrase = phrase_or_hex

                if len(seed_split) == 25:
                    # checksum word present
                    self._validate_checksum()

                self._decode_seed()

            elif len(seed_split) == 1:
                # assume hexadecimal seed
                if not len(phrase_or_hex) % 8 == 0:
                    raise ValueError(
                        "Not valid hexadecimal: {hex}".format(hex=phrase_or_hex)
                    )

                self.hex = phrase_or_hex
                self._encode_seed()

            else:
                raise ValueError(
                    "Not valid mnemonic phrase or hex: {arg}".format(arg=phrase_or_hex)
                )

        else:
            # generate new random seed
            self.hex = generate_random_hex()
            self._encode_seed()

    def _encode_seed(self):
        """Convert hexadecimal string to mnemonic phrase with checksum."""
        self.phrase = self.word_list.encode(self.hex)

    def _decode_seed(self):
        """Convert mnemonic phrase to hexadecimal seed."""
        self.hex = self.word_list.decode(self.phrase)

    def _validate_checksum(self):
        """Validate mnemonic checksum (last word)."""
        phrase = self.phrase.split(" ")

        if self.word_list.get_checksum(self.phrase) == phrase[-1]:
            return True

        raise ValueError("Invalid checksum")

    def hex_seed(self):
        """Return hexadecimal seed."""
        return self.hex

    def secret_spend_key(self):
        """Derive secret spend key."""
        return hexlify(ed25519.scalar_reduce(unhexlify(self.hex))).decode()

    def secret_view_key(self):
        """Derive secret view key."""
        b = unhexlify(self.secret_spend_key())
        return hexlify(ed25519.scalar_reduce(keccak_256(b).digest())).decode()

    def public_spend_key(self):
        """Derive public spend key."""
        if self._ed_pub_spend_key:
            return self._ed_pub_spend_key

        self._ed_pub_spend_key = ed25519.public_from_secret_hex(
            self.secret_spend_key()
        )

        return self._ed_pub_spend_key

    def public_view_key(self):
        """Derive public view key."""
        if self._ed_pub_view_key:
            return self._ed_pub_view_key

        self._ed_pub_view_key = ed25519.public_from_secret_hex(
            self.secret_view_key()
        )

        return self._ed_pub_view_key

    def public_address(self, net=const.NET_MAIN):
        """
        Returns the master Address represented by the seed.
        """

        _net = net[:-3] if net.endswith("net") else net

        if net not in const.NETS:
            raise ValueError(
                "Invalid net argument '{:s}'. Must be one of beldex.const.NET_*".format(
                    net
                )
            )

        netbyte = (0xd1, 53, 24)[const.NETS.index(net)]
        netbyteStr = encode_varint(netbyte)

        data = "{:s}{:s}{:s}".format(
            netbyteStr,
            self.public_spend_key(),
            self.public_view_key(),
        )

        checksum = keccak_256(unhexlify(data)).hexdigest()

        return address(base58.encode(data + checksum[0:8]))


def generate_random_hex(n_bytes=32):
    """Generate a secure random hexadecimal seed (32 bytes default)."""
    h = hexlify(urandom(n_bytes))
    return "".join(h.decode("utf-8"))


def encode_varint(i):
    """Encode integer as varint."""
    i = int(i)
    out = ""

    while i >= 0x80:
        out += format((i & 0x7F) | 0x80, "02x")
        i >>= 7

    out += format(i, "02x")

    return out