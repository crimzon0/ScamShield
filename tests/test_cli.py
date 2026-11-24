import csv

import pytest

from scamshield import cli
from scamshield.cli import eval as ev


@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    from scamshield.core.config import settings

    monkeypatch.setattr(settings, "db_path", tmp_path / "t.db")


def _write(p, text):
    p.write_text(text, encoding="utf-8")
    return str(p)


def _read(p):
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_batch_keeps_order_and_columns(tmp_path):
    inp = _write(tmp_path / "in.csv", "id,link\n1,https://a.example/\n2,\n3,https://b.example/x\n")
    out = str(tmp_path / "out.csv")
    assert cli.main([inp, "--out", out, "-q"]) == 0
    rows = _read(out)
    assert [r["id"] for r in rows] == ["1", "2", "3"]
    assert rows[0]["url"] == "https://a.example/"
    for c in cli.OUT_COLS:
        assert c in rows[0]
    assert rows[1]["label"]  # bad row still produces a row
    assert all(r["is_scam"] in ("0", "1") for r in rows)


def test_headerless_and_resume(tmp_path):
    inp = _write(tmp_path / "in.csv", "https://a.example/\nhttps://b.example/\n")
    out = str(tmp_path / "out.csv")
    cli.main([inp, "--out", out, "-q"])
    first = _read(out)
    cli.main([inp, "--out", out, "-q"])
    second = _read(out)
    assert len(first) == len(second) == 2
    assert [r["scan_id"] for r in first] == [r["scan_id"] for r in second]


def test_threshold():
    assert cli.is_scam("likely_scam") == 1
    assert cli.is_scam("suspicious") == 0
    assert cli.is_scam("suspicious", "suspicious") == 1


def test_metrics():
    m = ev.metrics([(1, 1), (1, 0), (0, 0), (0, 1)])
    assert m["tp"] == m["fp"] == m["fn"] == m["tn"] == 1
    assert m["precision"] == 0.5 and m["fpr"] == 0.5


def test_resume_refuses_stale_output(tmp_path, monkeypatch, capsys):
    inp = _write(tmp_path / "in.csv", "url\nhttps://a.example/\n")
    out = str(tmp_path / "out.csv")
    cli.main([inp, "--out", out, "-q"])
    capsys.readouterr()
    cli.main([inp, "--out", out, "-q"])
    assert "WARNING" not in capsys.readouterr().err  # same fingerprint -> resume
    monkeypatch.setattr(cli, "_fingerprint", lambda: "different-version")
    cli.main([inp, "--out", out, "-q"])
    assert "starting a fresh scan" in capsys.readouterr().err
    assert len(_read(out)) == 1
