"""Tests for email parsing (Phase 1)."""

from services.email_parser import parse_email


def test_dkim_header_extraction():
    """DKIM-Signature header fields d=, s=, a=, bh=, b= must all be extractable from parsed headers."""
    raw = b"""From: alice@legit.com
To: bob@test.com
Subject: Signed
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; c=relaxed/relaxed;
 h=from:to:subject; bh=abcdef0123456789abcdef0123456789abcdef12=;
 b=Zm9vYmFyYmF6cXV4Cg==
Message-ID: <id1@test>
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Body.
"""
    result = parse_email(raw)
    names = [h["name"].lower() for h in result["headers"]["parsed"]]
    assert "dkim-signature" in names
    dkim = next(h for h in result["headers"]["parsed"] if h["name"].lower() == "dkim-signature")
    val = dkim["value"]
    for token in ("d=example.com", "s=selector1", "a=rsa-sha256", "bh=", "b="):
        assert token in val.replace("\n", " ").replace("\r", " ")


def test_received_chain_ordering():
    """Received headers must be sorted oldest-first (reverse of header document order)."""
    raw = b"""Received: from newest.example.net by mx.last; Mon, 3 Mar 2024 12:00:00 +0000
Received: from middle.example.org by hop2; Sun, 2 Mar 2024 12:00:00 +0000
Received: from oldest.example.com by hop1; Sat, 1 Mar 2024 12:00:00 +0000
From: a@b.com
To: c@d.com
Subject: Chain
Date: Mon, 3 Mar 2024 12:00:00 +0000

Hi.
"""
    result = parse_email(raw)
    chain = result["headers"]["received_chain"]
    assert len(chain) >= 3
    # Oldest first: oldest.example.com should appear before newest
    froms = [hop["from"] for hop in chain]
    assert "oldest.example.com" in froms[0] or froms[0].endswith("oldest.example.com")


def test_reply_to_domain_mismatch_flags_suspicious():
    raw = b"""From: ceo@company.com
Reply-To: attacker@evil.com
To: victim@company.com
Subject: Urgent
Date: Mon, 1 Jan 2024 12:00:00 +0000

Please wire money.
"""
    result = parse_email(raw)
    rt = next(h for h in result["headers"]["parsed"] if h["name"].lower() == "reply-to")
    assert rt["suspicious"] is True
