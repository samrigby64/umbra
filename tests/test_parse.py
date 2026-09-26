from umbra.crawl.parse import is_onion, normalize_url, parse_page

BASE = "http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvw234yd.onion/dir/page"


def test_normalize_resolves_relative_and_strips_fragment():
    assert normalize_url(BASE, "../other") == (
        "http://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvw234yd.onion/other"
    )
    assert normalize_url(BASE, "#section") is None
    assert normalize_url(BASE, "mailto:x@y.com") is None
    assert normalize_url(BASE, "javascript:void(0)") is None


def test_is_onion():
    assert is_onion("http://foo.onion/")
    assert not is_onion("https://example.com/")


def test_parse_strips_script_and_style():
    html = (
        "<html><head><style>.x{color:red}</style></head><body>"
        "<script>var addr='0x52908400098527886E0F7030069857D2E4169EE7';</script>"
        "hello world</body></html>"
    )
    parsed = parse_page(html, BASE)
    assert "hello world" in parsed.text
    assert "color:red" not in parsed.text   # style contents excluded
    assert "0x52908400" not in parsed.text  # script contents excluded (no bogus IOCs)


def test_parse_extracts_title_meta_and_links():
    html = """
    <html><head>
      <title>Market</title>
      <meta name="description" content="a marketplace">
      <meta name="keywords" content="drugs, guns">
    </head><body>
      <a href="/listings">Listings</a>
      <a href="https://clearnet.example/x">Clearnet</a>
      Visit http://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz234yd.onion/deep too
    </body></html>
    """
    parsed = parse_page(html, BASE)
    assert parsed.title == "Market"
    assert parsed.description == "a marketplace"
    assert parsed.keywords == "drugs, guns"
    urls = {link.url for link in parsed.links}
    # relative link resolved against the onion base
    assert any(u.endswith("/listings") for u in urls)
    # onion URL mentioned in body text is discovered
    assert any("zzzz" in u for u in urls)
    # clearnet link is captured too (filtering happens in the crawler, not the parser)
    assert "https://clearnet.example/x" in urls


def test_hostile_href_skips_the_link_not_the_page():
    """Python 3.12's urlsplit raises on a bracketed non-IP host. Seen live: one
    such anchor on a category page aborted the whole page on every attempt."""
    from umbra.crawl.parse import normalize_url, parse_page

    assert normalize_url("http://x.onion/", "http://[dot]/x") is None

    html = """<html><title>Cat</title><body>listing text here
        <a href="http://[dot]/broken">bad</a>
        <a href="/good">good</a></body></html>"""
    parsed = parse_page(html, "http://x.onion/cat.cgi")
    assert parsed.title == "Cat"
    assert "listing text" in parsed.text
    assert [link.url for link in parsed.links] == ["http://x.onion/good"]
