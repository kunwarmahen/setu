"""The signed catalog: labels, installs, withdrawn versions -- and refusal.

The bias is A CATALOG TAKEN ON ITS WORD. An index says who wrote each
connector and which versions are withdrawn; believed unsigned, anyone
who could write the file could relabel a stranger's code "by Setu" or
quietly un-withdraw a bad version. So these tests change one byte, sign
with a key nobody trusts, damage the kept copy -- and assert the index
is refused WHOLE, and that a refusal never replaces the last good copy.

Also designed against:

* **A leaked key with no way out.** Rotation ships now: a new key the
  old one vouched for is accepted, and once the old key is distrusted
  its vouching is worth nothing.
* **Calling Setu's own connector sideloaded.** With no catalog there is
  no label at all; only an index that omits an installed connector
  makes it sideloaded.
"""

from __future__ import annotations

import json
import stat
from importlib.metadata import version

import pytest
from setu import catalog
from setu.cli import main
from setu.status import report


def index_doc(**over) -> dict:
    doc = {"format": catalog.FORMAT, "issued": "2026-10-03T00:00:00Z",
           "connectors": [{"id": "gmail", "name": "Gmail", "label": "by-setu",
                           "author": "Setu", "package": "setu-gmail",
                           "version": version("setu-gmail"), "installs": 41,
                           "yanked": {}}],
           "recipes": [{"name": "ha-fan-speed", "needs": ["homeassistant"],
                        "author": "priya", "label": "partner", "installs": 7}]}
    doc.update(over)
    return doc


@pytest.fixture
def signer(home, tmp_path):
    """A signing key the person trusts, and a way to publish an index."""
    pub, kid = catalog.keygen(tmp_path / "keys" / "setu.key")
    catalog.trust(catalog.load_public(pub))

    def publish(doc: dict, key=tmp_path / "keys" / "setu.key", chain=None, name="index.json"):
        path = tmp_path / name
        path.write_text(json.dumps(doc))
        path.with_name(name + ".sig").write_text(
            json.dumps(catalog.sign(path.read_bytes(), key, chain)))
        return path
    publish.kid = kid
    publish.dir = tmp_path
    return publish


class TestKeys:
    def test_a_signing_key_is_owner_only_and_never_overwritten(self, tmp_path):
        key = tmp_path / "k"
        catalog.keygen(key)
        assert stat.S_IMODE(key.stat().st_mode) == 0o600
        with pytest.raises(catalog.CatalogError, match="never overwritten"):
            catalog.keygen(key)

    def test_a_pub_files_id_is_recomputed_not_believed(self, tmp_path):
        pub, kid = catalog.keygen(tmp_path / "k")
        data = json.loads(pub.read_text())
        pub.write_text(json.dumps({**data, "id": "0000000000000000"}))
        assert catalog.load_public(pub)["id"] == kid


class TestRefusal:
    def test_a_good_index_is_kept(self, signer):
        index = catalog.use(signer(index_doc()))
        assert index.key == signer.kid and "gmail" in index.connectors
        assert catalog.kept().connectors["gmail"]["installs"] == 41

    def test_one_changed_byte_refuses_it_whole(self, signer):
        path = signer(index_doc())
        path.write_text(path.read_text().replace('"installs": 41', '"installs": 99'))
        with pytest.raises(catalog.CatalogError, match="refused whole"):
            catalog.use(path)

    def test_a_key_nobody_trusts_is_refused(self, signer, tmp_path):
        catalog.keygen(tmp_path / "stranger.key")
        path = signer(index_doc(), key=tmp_path / "stranger.key")
        with pytest.raises(catalog.CatalogError, match="no trusted key vouches"):
            catalog.use(path)

    def test_a_refusal_keeps_the_last_good_copy(self, signer, tmp_path):
        catalog.use(signer(index_doc()))
        catalog.keygen(tmp_path / "stranger.key")
        bad = signer(index_doc(connectors=[]), key=tmp_path / "stranger.key", name="bad.json")
        with pytest.raises(catalog.CatalogError):
            catalog.use(bad)
        assert "gmail" in catalog.kept().connectors

    def test_a_damaged_kept_copy_is_a_problem_not_a_label(self, signer, home):
        catalog.use(signer(index_doc()))
        kept = home / "catalog" / "index.json"
        kept.write_text(kept.read_text().replace("by-setu", "partner"))
        data = report()
        assert any(p.startswith("catalog:") for p in data["problems"])
        assert next(c for c in data["connectors"] if c["id"] == "gmail")["label"] is None

    def test_an_index_may_not_call_an_entry_sideloaded(self, signer):
        doc = index_doc()
        doc["connectors"][0]["label"] = "sideloaded"
        with pytest.raises(catalog.CatalogError, match="by-setu or partner"):
            catalog.use(signer(doc))

    def test_no_trusted_key_says_how_to_add_one(self, home, tmp_path):
        with pytest.raises(catalog.CatalogError, match="setu catalog trust"):
            catalog.verify(b"{}", {"key": "x", "sig": ""}, {})


class TestRotation:
    def test_a_key_the_old_one_vouched_for_is_accepted(self, signer, tmp_path):
        new_pub, new_kid = catalog.keygen(tmp_path / "keys" / "next.key")
        link = catalog.vouch(tmp_path / "keys" / "setu.key", catalog.load_public(new_pub))
        index = catalog.use(signer(index_doc(), key=tmp_path / "keys" / "next.key",
                                   chain=[link]))
        assert index.key == new_kid

    def test_a_distrusted_keys_word_is_worth_nothing(self, signer, tmp_path):
        new_pub, _ = catalog.keygen(tmp_path / "keys" / "next.key")
        link = catalog.vouch(tmp_path / "keys" / "setu.key", catalog.load_public(new_pub))
        assert catalog.distrust(signer.kid)
        catalog.trust(catalog.load_public(new_pub.with_name("next.key.pub")))
        catalog.keygen(tmp_path / "keys" / "rogue.key")
        rogue = catalog.vouch(tmp_path / "keys" / "setu.key",
                              catalog.load_public(tmp_path / "keys" / "rogue.key.pub"))
        path = signer(index_doc(), key=tmp_path / "keys" / "rogue.key", chain=[link, rogue])
        with pytest.raises(catalog.CatalogError, match="no trusted key vouches"):
            catalog.use(path)


class TestWhatAHarnessSees:
    def test_no_catalog_means_no_label(self, home):
        data = report()
        assert data["catalog"] is None
        assert all(c["label"] is None for c in data["connectors"])

    def test_listed_is_labelled_and_unlisted_is_sideloaded(self, signer):
        catalog.use(signer(index_doc()))
        data = report()
        by_id = {c["id"]: c for c in data["connectors"]}
        assert by_id["gmail"]["label"] == "by-setu" and by_id["gmail"]["installs"] == 41
        assert by_id["homeassistant"]["label"] == "sideloaded"
        assert data["catalog"]["recipes"][0]["name"] == "ha-fan-speed"

    def test_a_withdrawn_installed_version_says_why_and_is_a_problem(self, signer):
        doc = index_doc()
        doc["connectors"][0]["yanked"] = {version("setu-gmail"): "sent mail to a host it "
                                                                 "did not declare"}
        catalog.use(signer(doc))
        data = report()
        gmail = next(c for c in data["connectors"] if c["id"] == "gmail")
        assert "did not declare" in gmail["yanked"]
        assert any("gmail: withdrawn by Setu" in p for p in data["problems"])

    def test_the_cli_round_trip(self, home, tmp_path, capsys):
        key = tmp_path / "k"
        assert main(["catalog", "keygen", str(key)]) == 0
        assert main(["catalog", "trust", str(key) + ".pub"]) == 0
        path = tmp_path / "index.json"
        path.write_text(json.dumps(index_doc()))
        assert main(["catalog", "sign", str(path), "--key", str(key)]) == 0
        assert main(["catalog", "use", str(path)]) == 0
        capsys.readouterr()
        assert main(["catalog"]) == 0
        out = capsys.readouterr().out
        assert "gmail" in out and "by Setu" in out and "41 installs" in out
        assert "homeassistant" in out and "sideloaded" in out
        assert "recipe ha-fan-speed" in out
