#!/usr/bin/env python3
"""Fill bait templates with random values (used by install.sh).

  render-bait.py USER HOST SRC DST [SRC DST ...]

Every @@TOKEN@@ in SRC is replaced and the result is written to DST (mode 600,
must not exist yet). All or nothing: on any error no DST is left behind. Tokens:

  @@KIND@@             random value with the kind's default length (16)
  @@KIND:N@@           N characters (N words for WORDS)
  @@KIND:N:name@@      same, but every token with that name gets the SAME value
                       across all files of one install (e.g. a password that
                       appears in both .env and docker-compose.yml)

  USER HOST UUID       the bait owner, the short hostname, a random UUID
  HEX DIGITS ALNUM     0-9a-f / 0-9 / A-Za-z0-9
  UPPER LOWER          A-Z0-9 / a-z0-9
  B64 B64URL           base64 alphabet (+/) / url-safe (-_)
  B58 BECH32           bitcoin base58 / bech32 alphabets
  PASS                 password-ish: A-Za-z0-9 plus !*-_.~+= (safe in URLs)
  WORDS                seed-phrase-like English words, space separated
"""
import os
import re
import secrets
import string
import sys
import uuid

A = string.ascii_letters + string.digits
SETS = {
    "HEX": "0123456789abcdef",
    "DIGITS": string.digits,
    "ALNUM": A,
    "UPPER": string.ascii_uppercase + string.digits,
    "LOWER": string.ascii_lowercase + string.digits,
    "B64": A + "+/",
    "B64URL": A + "-_",
    "B58": "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "BECH32": "qpzry9x8gf2tvdw0s3jn54khce6mua7l",
    "PASS": A + "!*-_.~+=",  # RFC 3986 unreserved / sub-delims: valid in a URL userinfo
}
DEFAULT_LEN = 16
DEFAULT_WORDS = 12
# Subset of the BIP39 English list (enough to look like a real seed phrase)
WORDS = """abandon ability absorb access actor adapt afford agent alarm album anchor
angle answer apple arena armor arrow artist atom auction autumn avocado badge balance
bamboo banana barrel basket battle beach beauty bench bicycle blanket blossom bonus
border bounce brain bread bridge broccoli bubble budget buffalo cabin cactus camera
canal candy canyon carbon cargo carpet castle catalog cattle ceiling cement census
cereal champion chaos charge cherry chicken chimney cinnamon circle citizen clever
cliff clinic clock cloud coconut coffee comic coral cotton couch cousin cradle crater
cricket crystal cupboard curtain cushion dance danger dawn debate decade defense delay
dentist desert design device diamond dinosaur dolphin donkey dragon drama drift eagle
earth eclipse elbow elegant elephant embark emerge empty energy engine enrich escape
essay estate eternal evolve exhaust exotic fabric falcon fancy fashion feature
festival fiction filter fiscal flavor flight fluid foam forest fossil fragile frozen
galaxy garden garlic gauge genius ghost giant ginger giraffe glacier glory goose
gorilla gossip guitar habit hamster harbor harvest hazard helmet hero hobby horizon
hospital hover hybrid icon image impact income infant inherit insect island ivory
jacket jaguar jazz jelly jewel journey jungle kangaroo kettle kidney kitchen kiwi
ladder lantern laptop lava lemon leopard liberty lizard lobster lottery lunar luxury
machine magnet mammal mango marble margin meadow melody mercy method midnight mimic
miracle mixture monkey mosquito motor mountain muffin museum mushroom napkin needle
neutral noodle nuclear oasis object ocean olive opera orbit orchard ostrich oxygen
oyster paddle palace panda panther parrot pelican penguin pepper piano pigeon pilot
pioneer planet plastic pledge pony potato powder pumpkin puzzle pyramid quantum quiz
rabbit raccoon radar rebel recipe reptile rhythm ribbon robot rocket rookie saddle
salmon sausage scorpion season shadow sheriff shrimp silver siren skeleton slogan
snack soccer solar spider sponsor squirrel stadium stomach subway sunset surge
swallow symbol tackle tattoo tenant theater thunder ticket timber tomato tornado
tortoise tourist trophy tunnel turkey turtle umbrella unicorn universe uranium
utility vacuum valley vanish velvet venture vessel veteran vibrant violin virus visa
volcano voyage walnut warrior wasp weasel whale whisper wisdom wolf yellow zebra""".split()

TOKEN = re.compile(r"@@([A-Z0-9]+)(?::(\d+))?(?::([A-Za-z0-9_]+))?@@")


def random_chars(alphabet, n):
    return "".join(secrets.choice(alphabet) for _ in range(n))


def random_words(n):
    return " ".join(secrets.choice(WORDS) for _ in range(n))


def gen(kind, n, user, host):
    """A fresh value for one token kind; n = 0 means the kind's default size."""
    if kind == "USER":
        return user
    if kind == "HOST":
        return host
    if kind == "UUID":
        return str(uuid.uuid4())
    if kind == "WORDS":
        return random_words(n or DEFAULT_WORDS)
    if kind not in SETS:
        raise SystemExit(f"render-bait: unknown token kind @@{kind}@@")
    return random_chars(SETS[kind], n or DEFAULT_LEN)


def token_value(m, user, host, named):
    """Value for one TOKEN match; named tokens reuse the value stored in NAMED."""
    kind, n, name = m.group(1), int(m.group(2) or 0), m.group(3)
    if not name:
        return gen(kind, n, user, host)
    if name not in named:
        named[name] = gen(kind, n, user, host)
    return named[name]


def render(text, user, host, named):
    return TOKEN.sub(lambda m: token_value(m, user, host, named), text)


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def render_all(pairs, user, host):
    """[(dst, rendered text)] for [(src, dst)]; nothing is written yet, so a
    bad token aborts before any file exists. Named values span all files."""
    named = {}
    return [(dst, render(read_text(src), user, host, named)) for src, dst in pairs]


def create_new(dst):
    """fd of a new DST (mode 600); raises if it already exists."""
    return os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)


def write_fd(fd, data):
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data)


def remove_quietly(paths):
    for p in paths:
        try:
            os.unlink(p)
        except OSError:
            pass


def write_all(rendered):
    """Write every file or none: if one write fails, remove what this run
    wrote, so a re-run doesn't refuse half-created baits as "real" files."""
    written = []
    try:
        for dst, data in rendered:
            fd = create_new(dst)
            written.append(dst)  # only after O_EXCL succeeded: it's ours
            write_fd(fd, data)
    except BaseException:
        remove_quietly(written)
        raise


def parse_args(argv):
    """(user, host, [(src, dst), ...]) or None if the arguments are wrong."""
    if len(argv) < 4 or len(argv) % 2:
        return None
    user, host, *rest = argv
    return user, host, list(zip(rest[::2], rest[1::2]))


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args is None:
        sys.exit(__doc__)
    user, host, pairs = args
    write_all(render_all(pairs, user, host))


if __name__ == "__main__":
    main()
