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


def main():
    if len(sys.argv) < 5 or len(sys.argv) % 2 == 0:
        sys.exit(__doc__)
    user, host, *pairs = sys.argv[1:]
    named = {}

    def gen(kind, n):
        if kind == "USER":
            return user
        if kind == "HOST":
            return host
        if kind == "UUID":
            return str(uuid.uuid4())
        if kind == "WORDS":
            return " ".join(secrets.choice(WORDS) for _ in range(n or 12))
        if kind not in SETS:
            raise SystemExit(f"render-bait: unknown token kind @@{kind}@@")
        return "".join(secrets.choice(SETS[kind]) for _ in range(n or 16))

    def sub(m):
        kind, n, name = m.group(1), int(m.group(2) or 0), m.group(3)
        if not name:
            return gen(kind, n)
        if name not in named:
            named[name] = gen(kind, n)
        return named[name]

    # All or nothing: render every template first (a bad token aborts before
    # anything is written), then write; if a write fails, remove what this run
    # wrote, so a re-run doesn't refuse half-created baits as "real" files.
    rendered = []
    for src, dst in zip(pairs[::2], pairs[1::2]):
        with open(src, encoding="utf-8") as f:
            rendered.append((dst, TOKEN.sub(sub, f.read())))
    written = []
    try:
        for dst, data in rendered:
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            written.append(dst)  # only after O_EXCL succeeded: it's ours
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
    except BaseException:
        for dst in written:
            try:
                os.unlink(dst)
            except OSError:
                pass
        raise


if __name__ == "__main__":
    main()
