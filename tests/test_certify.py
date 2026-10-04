"""Independent certifications (certify.py).

The bias is A NAME TAKEN ON ITS WORD. A certification is worth exactly
the key that signed it, for exactly the bytes it names -- so these tests
change a word, borrow a name, point it at other bytes, and assert it
counts for nothing; and that a certifier's later withdrawal beats their
earlier word.
"""

from __future__ import annotations

import json

import pytest
from setu import catalog, certify
from setu.cli import main

SUBJECT = {"kind": "recipe", "id": "ha-fan-speed", "version": "a85f406e0000",
           "sha256": "a85f406e" + "0" * 56}


@pytest.fixture
def acme(tmp_path):
    pub, kid = certify.keygen(tmp_path / "acme.key", "Acme Labs")
    return tmp_path / "acme.key", certify.load_public(pub)


def cert(key, **kw):
    kw.setdefault("name", "Acme Labs")
    kw.setdefault("statement", "Ran it a week against our staging home; does what it says.")
    kw.setdefault("checks", ["deployed", "read-the-code"])
    return certify.make(kw.pop("subject", SUBJECT), key, **kw)


class TestTheDocument:
    def test_a_certification_checks_out(self, acme):
        key, pub = acme
        c = cert(key)
        assert certify.verify(c) == pub["id"]
        assert c["certifier"]["name"] == "Acme Labs"

    def test_a_changed_word_or_a_borrowed_name_counts_for_nothing(self, acme, tmp_path):
        key, _ = acme
        c = cert(key)
        tampered = {**c, "statement": "certified by everyone"}
        with pytest.raises(certify.CertError, match="signature"):
            certify.verify(tampered)
        certify.keygen(tmp_path / "mallory.key", "Mallory")
        other = cert(tmp_path / "mallory.key", name="Acme Labs")      # a name is a claim
        assert other["certifier"]["key"] != c["certifier"]["key"]
        claimed = {**other, "certifier": {**other["certifier"], "key": c["certifier"]["key"]}}
        with pytest.raises(certify.CertError):
            certify.verify(claimed)

    def test_a_statement_and_known_checks_are_required(self, acme):
        key, _ = acme
        with pytest.raises(certify.CertError, match="statement"):
            cert(key, statement=" ")
        with pytest.raises(certify.CertError, match="unknown check"):
            cert(key, checks=["trust-me"])
        with pytest.raises(certify.CertError, match="sha256"):
            cert(key, subject={**SUBJECT, "sha256": "short"})


class TestWhatACardSays:
    def test_trusted_apart_from_the_others(self, acme, tmp_path):
        key, pub = acme
        certify.keygen(tmp_path / "kumar.key", "R. Kumar")
        certify.keygen(tmp_path / "stranger.key", "Someone")
        certs = [cert(key), cert(tmp_path / "kumar.key", name="R. Kumar"),
                 cert(tmp_path / "stranger.key", name="Someone")]
        trusted = {pub["id"]: {"public": pub["public"], "name": "Acme Labs"}}
        st = certify.standing(certs, SUBJECT, trusted)
        assert st == {"trusted": ["Acme Labs"], "others": 2, "revoked": []}
        assert certify.line(st) == "certified by 1 you trust (Acme Labs) + 2 others"

    def test_other_bytes_are_not_this_version(self, acme):
        key, pub = acme
        v2 = {**SUBJECT, "version": "ffff", "sha256": "f" * 64}
        st = certify.standing([cert(key, subject=v2)], SUBJECT, {})
        assert st == {"trusted": [], "others": 0, "revoked": []}

    def test_a_later_withdrawal_wins(self, acme):
        key, pub = acme
        said = cert(key, at="2026-10-04T10:00:00Z")
        withdrawn = cert(key, verdict="revoked", at="2026-10-05T10:00:00Z",
                         statement="It posts to a host it never declared.")
        trusted = {pub["id"]: {"public": pub["public"], "name": "Acme Labs"}}
        st = certify.standing([withdrawn, said], SUBJECT, trusted)
        assert st == {"trusted": [], "others": 0, "revoked": ["Acme Labs"]}
        assert certify.line(st) == "withdrawn by Acme Labs"


class TestTheCommands:
    def test_keygen_trust_sign_verify(self, home, tmp_path, capsys):
        # a catalog listing the recipe, so the subject comes from the signed index
        cat_key = tmp_path / "cat.key"
        pub, _ = catalog.keygen(cat_key)
        catalog.trust(catalog.load_public(pub))
        index = tmp_path / "index.json"
        index.write_text(json.dumps({"format": catalog.FORMAT, "issued": "2026-10-04",
                                     "connectors": [], "recipes": [{
                                         "name": "ha-fan-speed", "label": "partner",
                                         "bundle": {"url": "https://x/f.json",
                                                    "sha256": SUBJECT["sha256"]}}]}))
        index.with_name("index.json.sig").write_text(
            json.dumps(catalog.sign(index.read_bytes(), cat_key)))
        catalog.use(index)
        assert main(["certify", "keygen", str(tmp_path / "me.key"), "--as", "Acme Labs"]) == 0
        out = tmp_path / "c.json"
        assert main(["certify", "sign", "--subject", "recipe:ha-fan-speed", "--key",
                     str(tmp_path / "me.key"), "--statement", "deployed a week",
                     "--checks", "deployed,scan", "--out", str(out)]) == 0
        written = json.loads(out.read_text())
        assert written["subject"] == SUBJECT and written["certifier"]["name"] == "Acme Labs"
        assert main(["certify", "verify", str(out)]) == 0
        assert main(["certify", "trust", str(tmp_path / "me.key.pub")]) == 0
        capsys.readouterr()
        assert main(["certify", "trust"]) == 0
        assert "Acme Labs" in capsys.readouterr().out
        assert main(["certify", "sign", "--subject", "recipe:not-listed", "--key",
                     str(tmp_path / "me.key"), "--statement", "x"]) == 2
