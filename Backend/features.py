"""Feature extraction that mirrors the columns of dataset_phishing.csv.

URL-based features are computed exactly from the URL. Page-content features
are computed from a live fetch of the page (when enabled). Features that need
third-party services (WHOIS, Alexa traffic, PageRank, Google index) cannot be
computed locally and fall back to dataset medians unless the caller supplies them.
"""

import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

# Offline extractor: uses the bundled public-suffix snapshot, no network call.
_extract = tldextract.TLDExtract(suffix_list_urls=())

WORD_SPLIT = re.compile(r"[-./?=@&%:_]")

# Same (loose) pattern the dataset authors used, including hex/IPv6 forms.
IP_PATTERN = re.compile(
    r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\."
    r"([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|"
    r"((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|"
    r"(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|[0-9a-fA-F]{7}"
)

HINTS = [
    "wp", "login", "includes", "admin", "content", "site", "images", "js",
    "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "signin", "view",
]

BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix",
    "instagram", "whatsapp", "linkedin", "twitter", "yahoo", "ebay", "dropbox",
    "adobe", "outlook", "office", "chase", "wellsfargo", "bankofamerica",
    "alibaba", "aliexpress", "icloud", "steam", "spotify", "dhl", "fedex", "usps",
]

SUSPICIOUS_TLDS = {
    "fit", "tk", "gp", "ga", "work", "ml", "date", "wang", "men", "icu", "online",
    "click", "country", "stream", "download", "xin", "racing", "jetzt", "ren",
    "mom", "party", "review", "trade", "accountants", "science", "ninja", "xyz",
    "faith", "zip", "cricket", "win", "accountant", "realtor", "top", "christmas",
    "gdn", "link", "asia", "club", "la", "ae", "exposed", "pe", "go", "rs", "k12",
    "rest", "loan", "cf", "gq", "cn", "su", "mov",
}

SHORTENERS = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|"
    r"cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|"
    r"snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|just\.as|bkite\.com|"
    r"snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|"
    r"om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|"
    r"ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|"
    r"u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|"
    r"qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net|rb\.gy|cutt\.ly|shorturl\.at"
)

# Dataset medians, used when a service-dependent feature is not supplied.
EXTERNAL_DEFAULTS = {
    "whois_registered_domain": 0,
    "domain_registration_length": 242,
    "domain_age": 3993,
    "web_traffic": 1651,
    "google_index": 1,
    "page_rank": 3,
    "statistical_report": 0,
    "random_domain": 0,
}

MAX_PAGE_BYTES = 2_000_000
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishingDetector/1.0"


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def _check_public_host(host: str) -> None:
    """Block fetches to private/loopback/link-local addresses (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"Could not resolve {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError(f"{host} resolves to non-public address {ip}")


def _char_repeat(words):
    total = 0
    for word in words:
        for n in (2, 3, 4, 5):
            for i in range(len(word) - n + 1):
                chunk = word[i : i + n]
                if chunk == chunk[0] * n:
                    total += 1
    return total


def _stats(words):
    lengths = [len(w) for w in words] or [0]
    return min(lengths), max(lengths), (sum(lengths) / len(lengths) if words else 0)


def url_features(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = _extract(url)
    domain, subdomain, suffix = ext.domain.lower(), ext.subdomain.lower(), ext.suffix.lower()
    path = parsed.path + (("?" + parsed.query) if parsed.query else "")

    host_words = [w for w in WORD_SPLIT.split(f"{domain}.{subdomain}") if w]
    path_words = [w for w in WORD_SPLIT.split(path.lower()) if w]
    raw_words = host_words + path_words
    all_words = [w for w in WORD_SPLIT.split(url.lower()) if w]

    s_raw, l_raw, a_raw = _stats(raw_words)
    s_host, l_host, a_host = _stats(host_words)
    s_path, l_path, a_path = _stats(path_words)

    digits = lambda s: sum(c.isdigit() for c in s)
    dot_count = url.count(".")

    return {
        "length_url": len(url),
        "length_hostname": len(host),
        "ip": int(bool(IP_PATTERN.search(url))),
        "nb_dots": dot_count,
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" ") + url.count("%20"),
        "nb_www": sum(w == "www" for w in all_words),
        "nb_com": sum(w.count("com") for w in raw_words),
        "nb_dslash": int(url.rfind("//") > 6),
        "http_in_path": path.lower().count("http"),
        "https_token": int(parsed.scheme != "https"),
        "ratio_digits_url": digits(url) / len(url) if url else 0,
        "ratio_digits_host": digits(host) / len(host) if host else 0,
        "punycode": int("xn--" in url.lower()),
        "port": _has_port(parsed),
        "tld_in_path": int(bool(suffix) and f".{suffix}" in path.lower()),
        "tld_in_subdomain": int(bool(suffix) and suffix in subdomain.split(".")),
        "abnormal_subdomain": int(bool(re.search(r"(http[s]?://(w[w]?|\d))([w]?(\d|-))", url))),
        "nb_subdomains": 1 if dot_count == 1 else 2 if dot_count == 2 else 3,
        "prefix_suffix": int("-" in domain),
        "shortening_service": int(bool(SHORTENERS.search(host))),
        "path_extension": int(parsed.path.lower().endswith((".txt", ".exe", ".js"))),
        "length_words_raw": len(raw_words),
        "char_repeat": _char_repeat(raw_words),
        "shortest_words_raw": s_raw,
        "shortest_word_host": s_host,
        "shortest_word_path": s_path,
        "longest_words_raw": l_raw,
        "longest_word_host": l_host,
        "longest_word_path": l_path,
        "avg_words_raw": a_raw,
        "avg_word_host": a_host,
        "avg_word_path": a_path,
        "phish_hints": sum(path.lower().count(h) for h in HINTS),
        "domain_in_brand": int(domain in BRANDS),
        "brand_in_subdomain": int(any(b in subdomain for b in BRANDS if b != domain)),
        "brand_in_path": int(any(b in path.lower() for b in BRANDS if b != domain)),
        "suspecious_tld": int(suffix.split(".")[-1] in SUSPICIOUS_TLDS),
    }


def _has_port(parsed) -> int:
    try:
        return int(parsed.port is not None)
    except ValueError:
        return 1


def _dns_record(host: str) -> int:
    """0 when the host resolves (dataset convention), 1 otherwise."""
    try:
        socket.getaddrinfo(host, None)
        return 0
    except (socket.gaierror, UnicodeError):
        return 1


def _fetch(url: str, timeout: float):
    host = urlparse(url).hostname or ""
    _check_public_host(host)
    with requests.get(
        url, timeout=timeout, stream=True, allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as resp:
        final_host = urlparse(resp.url).hostname or ""
        _check_public_host(final_host)
        body = b""
        for chunk in resp.iter_content(65536):
            body += chunk
            if len(body) > MAX_PAGE_BYTES:
                break
        return resp, body.decode(resp.encoding or "utf-8", errors="replace")


def empty_page_features() -> dict:
    """Page features for an unreachable or empty page."""
    return {
        "nb_redirection": 0, "nb_external_redirection": 0,
        "nb_hyperlinks": 0, "ratio_intHyperlinks": 0, "ratio_extHyperlinks": 0,
        "ratio_nullHyperlinks": 0, "nb_extCSS": 0, "ratio_intRedirection": 0,
        "ratio_extRedirection": 0, "ratio_intErrors": 0, "ratio_extErrors": 0,
        "login_form": 0, "external_favicon": 0, "links_in_tags": 0,
        "submit_email": 0, "ratio_intMedia": 0, "ratio_extMedia": 0, "sfh": 0,
        "iframe": 0, "popup_window": 0, "safe_anchor": 0, "onmouseover": 0,
        "right_clic": 0, "empty_title": 1, "domain_in_title": 1,
        "domain_with_copyright": 1,
    }


def content_features(url: str, timeout: float = 6.0) -> tuple[dict, str | None]:
    """Return (features, error). On failure, returns empty-page style features."""
    parsed = urlparse(url)
    ext = _extract(url)
    base_domain = f"{ext.domain}.{ext.suffix}".lower()

    def is_internal(link: str) -> bool:
        h = (urlparse(urljoin(url, link)).hostname or "").lower()
        return h == base_domain or h.endswith("." + base_domain)

    feats = empty_page_features()

    try:
        resp, html = _fetch(url, timeout)
    except Exception as exc:  # network errors, SSRF guard, bad TLS, etc.
        return feats, str(exc)

    feats["nb_redirection"] = len(resp.history)
    feats["nb_external_redirection"] = sum(
        not is_internal(r.headers.get("Location", "")) for r in resp.history
    )

    soup = BeautifulSoup(html, "html.parser")

    # Hyperlinks: every href/src on the page.
    links = [t.get("href") for t in soup.find_all(href=True)]
    links += [t.get("src") for t in soup.find_all(src=True)]
    null_links = [l for l in links if l.strip() in ("", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whitespace", "#content", "#skip", "javascript:void(0)", "javascript:void(0);", "javascript::void(0)") or l.strip().lower().startswith("javascript:")]
    real_links = [l for l in links if l not in null_links]
    internal = [l for l in real_links if is_internal(l)]
    n = len(links)
    feats["nb_hyperlinks"] = n
    if n:
        feats["ratio_intHyperlinks"] = len(internal) / n
        feats["ratio_extHyperlinks"] = (len(real_links) - len(internal)) / n
        feats["ratio_nullHyperlinks"] = len(null_links) / n

    feats["nb_extCSS"] = sum(
        not is_internal(l.get("href", ""))
        for l in soup.find_all("link", rel=lambda r: r and "stylesheet" in r, href=True)
    )

    # Forms
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()
        if form.find("input", attrs={"type": "password"}) and (
            action in ("", "#", "about:blank") or not is_internal(action)
            or action.startswith("javascript")
        ):
            feats["login_form"] = 1
        if action.startswith("mailto:"):
            feats["submit_email"] = 1
        if action in ("", "about:blank"):
            feats["sfh"] = 1

    icon = soup.find("link", rel=lambda r: r and "icon" in r, href=True)
    if icon and not is_internal(icon["href"]):
        feats["external_favicon"] = 1

    tag_links = [t.get("href") for t in soup.find_all("link", href=True)]
    tag_links += [t.get("src") for t in soup.find_all("script", src=True)]
    if tag_links:
        feats["links_in_tags"] = 100 * sum(is_internal(l) for l in tag_links) / len(tag_links)

    media = [t.get("src") for t in soup.find_all(["img", "audio", "video", "embed", "source"], src=True)]
    if media:
        n_int = sum(is_internal(m) for m in media)
        feats["ratio_intMedia"] = 100 * n_int / len(media)
        feats["ratio_extMedia"] = 100 * (len(media) - n_int) / len(media)

    feats["iframe"] = int(any(
        f.get("frameborder") == "0" or "display:none" in (f.get("style") or "").replace(" ", "")
        or f.get("width") == "0" or f.get("height") == "0"
        for f in soup.find_all("iframe")
    ))
    feats["popup_window"] = int("prompt(" in html)
    feats["onmouseover"] = int(bool(re.search(r"onmouseover\s*=\s*[\"']?\s*window\.status", html, re.I)))
    feats["right_clic"] = int(bool(re.search(r"event\.button\s*==\s*2", html)))

    anchors = [a.get("href", "") for a in soup.find_all("a", href=True)]
    if anchors:
        unsafe = sum(
            a.strip() in ("", "#") or a.lower().startswith(("javascript", "mailto"))
            or not is_internal(a)
            for a in anchors
        )
        feats["safe_anchor"] = 100 * unsafe / len(anchors)

    title = soup.title.get_text(strip=True).lower() if soup.title else ""
    feats["empty_title"] = int(not title)
    feats["domain_in_title"] = int(ext.domain.lower() not in title)

    text = soup.get_text(" ").lower()
    m = re.search(r"(©|&copy;|copyright)", text)
    if m:
        window = text[max(0, m.start() - 50) : m.end() + 50]
        feats["domain_with_copyright"] = int(ext.domain.lower() not in window)

    return feats, None


def extract_features(url: str, fetch_page: bool = True, overrides: dict | None = None) -> dict:
    """Build the full feature dict plus metadata about how it was obtained."""
    url = normalize_url(url)
    host = urlparse(url).hostname or ""

    features = url_features(url)
    features.update(EXTERNAL_DEFAULTS)
    features["dns_record"] = _dns_record(host)

    if fetch_page:
        page, fetch_error = content_features(url)
    else:
        page, fetch_error = empty_page_features(), "Page fetch disabled"
    features.update(page)

    supplied = {k: v for k, v in (overrides or {}).items() if v is not None}
    features.update(supplied)

    defaulted = [k for k in EXTERNAL_DEFAULTS if k not in supplied]
    return {
        "url": url,
        "features": features,
        "defaulted_features": defaulted,
        "page_fetched": fetch_page and fetch_error is None,
        "fetch_error": fetch_error,
    }
