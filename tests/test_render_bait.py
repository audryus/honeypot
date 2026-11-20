import os
import re
import tempfile
import unittest
import uuid
from unittest import mock

from load import load

rb = load("render-bait.py", "render_bait")


class Gen(unittest.TestCase):
    def test_user_host(self):
        self.assertEqual(rb.gen("USER", 0, "alice", "nas01"), "alice")
        self.assertEqual(rb.gen("HOST", 5, "alice", "nas01"), "nas01")

    def test_uuid(self):
        uuid.UUID(rb.gen("UUID", 0, "u", "h"))  # raises if not a UUID

    def test_default_lengths(self):
        self.assertEqual(len(rb.gen("HEX", 0, "u", "h")), rb.DEFAULT_LEN)
        self.assertEqual(len(rb.gen("WORDS", 0, "u", "h").split()), rb.DEFAULT_WORDS)

    def test_explicit_length(self):
        self.assertEqual(len(rb.gen("ALNUM", 40, "u", "h")), 40)
        self.assertEqual(len(rb.gen("WORDS", 24, "u", "h").split()), 24)

    def test_every_alphabet(self):
        for kind, alphabet in rb.SETS.items():
            v = rb.gen(kind, 200, "u", "h")
            self.assertTrue(set(v) <= set(alphabet), kind)

    def test_words_come_from_the_list(self):
        self.assertTrue(set(rb.random_words(50).split()) <= set(rb.WORDS))

    def test_unknown_kind(self):
        with self.assertRaises(SystemExit):
            rb.gen("NOPE", 0, "u", "h")


class Render(unittest.TestCase):
    def test_plain_text_untouched(self):
        self.assertEqual(rb.render("no tokens @@ here", "u", "h", {}), "no tokens @@ here")

    def test_tokens_replaced(self):
        out = rb.render("user=@@USER@@ key=@@HEX:8@@", "alice", "h", {})
        self.assertRegex(out, r"^user=alice key=[0-9a-f]{8}$")

    def test_unnamed_tokens_differ(self):
        a, b = rb.render("@@ALNUM:32@@ @@ALNUM:32@@", "u", "h", {}).split()
        self.assertNotEqual(a, b)

    def test_named_tokens_share_a_value(self):
        named = {}
        a = rb.render("@@PASS:20:db@@", "u", "h", named)
        b = rb.render("x=@@PASS:20:db@@", "u", "h", named)
        self.assertEqual("x=" + a, b)
        self.assertEqual(named, {"db": a})

    def test_lowercase_is_not_a_token(self):
        self.assertEqual(rb.render("@@hex@@", "u", "h", {}), "@@hex@@")


class Args(unittest.TestCase):
    def test_pairs(self):
        self.assertEqual(rb.parse_args(["u", "h", "s1", "d1", "s2", "d2"]),
                         ("u", "h", [("s1", "d1"), ("s2", "d2")]))

    def test_wrong_count(self):
        self.assertIsNone(rb.parse_args(["u", "h", "s1"]))
        self.assertIsNone(rb.parse_args(["u", "h"]))
        self.assertIsNone(rb.parse_args(["u", "h", "s1", "d1", "s2"]))


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, name, content=None):
        p = os.path.join(self.d, name)
        if content is not None:
            with open(p, "w") as f:
                f.write(content)
        return p

    def test_render_all_shares_named_values_across_files(self):
        s1 = self.path("s1", "@@HEX:12:k@@")
        s2 = self.path("s2", "v=@@HEX:12:k@@")
        (d1, t1), (d2, t2) = rb.render_all([(s1, "d1"), (s2, "d2")], "u", "h")
        self.assertEqual(("d1", "d2"), (d1, d2))
        self.assertEqual("v=" + t1, t2)

    def test_written_mode_600(self):
        dst = self.path("out")
        rb.write_all([(dst, "secret")])
        with open(dst) as f:
            self.assertEqual(f.read(), "secret")
        self.assertEqual(os.stat(dst).st_mode & 0o777, 0o600)

    def test_existing_file_is_kept_and_nothing_left_behind(self):
        first = self.path("first")
        existing = self.path("existing", "the user's file")
        with self.assertRaises(FileExistsError):
            rb.write_all([(first, "a"), (existing, "b")])
        self.assertFalse(os.path.exists(first))          # ours: removed
        with open(existing) as f:
            self.assertEqual(f.read(), "the user's file")  # not ours: kept

    def test_failed_write_removes_the_half_written_file(self):
        dst = self.path("out")
        with mock.patch.object(rb, "write_fd", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                rb.write_all([(dst, "x")])
        self.assertFalse(os.path.exists(dst))

    def test_bad_token_writes_nothing(self):
        good = self.path("good", "@@HEX@@")
        bad = self.path("bad", "@@NOPE@@")
        out = self.path("o1")
        with self.assertRaises(SystemExit):
            rb.main(["u", "h", good, out, bad, self.path("o2")])
        self.assertFalse(os.path.exists(out))

    def test_main(self):
        src = self.path("src", "host=@@HOST@@\n")
        dst = self.path("dst")
        rb.main(["u", "nas01", src, dst])
        with open(dst) as f:
            self.assertEqual(f.read(), "host=nas01\n")

    def test_main_usage(self):
        with self.assertRaises(SystemExit):
            rb.main(["u"])


class Examples(unittest.TestCase):
    """Every shipped decoy must render (a typo'd token would abort an install)."""

    def test_all_examples_render(self):
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
        templates = [os.path.join(dp, f) for dp, _, fs in os.walk(root) for f in fs
                     if f != "README.md"]
        self.assertTrue(templates)
        for path, text in rb.render_all([(t, t) for t in templates], "alice", "nas01"):
            self.assertNotRegex(text, rb.TOKEN, path)
            self.assertIsNone(re.search(r"@@[A-Z0-9:_a-z]+@@", text), path)


if __name__ == "__main__":
    unittest.main()
