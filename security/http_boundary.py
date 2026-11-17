"""HTTP message-boundary validation shared by the proxy and the backend.

The two peers must agree on exactly where a request ends.  Every helper in
this module is deliberately strict: whenever a message could be framed in
more than one way it is rejected instead of being interpreted.  The
``boundary_error`` codes are stable identifiers so both peers can log the
same reason for a rejection.

Framing rules (RFC 9112 / RFC 7230):

* ``Content-Length`` and ``Transfer-Encoding`` must never appear together.
* A message may carry at most one ``Content-Length`` value.
* ``Transfer-Encoding`` may not contain duplicate ``chunked`` codings and
  its final coding must be ``chunked``.
* A header value beginning with SP/HTAB is an obs-fold continuation line,
  which is obsolete and a request-smuggling primitive here.
* Chunk framing is parsed strictly: the size is hexadecimal, extensions are
  syntactically validated, the CRLF after every chunk is mandatory and no
  bytes may follow the terminating zero-length chunk and trailer section.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

#: Maximum length of a single header line (name + ": " + value), in bytes.
MAX_HEADER_LINE_BYTES = 8192

#: Maximum number of header fields (individual values, not names).
MAX_HEADER_COUNT = 100

_HEX_RE = re.compile(rb"\A[0-9A-Fa-f]+\Z")
_TOKEN_RE = re.compile(rb"\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")

#: Byte lookup table for RFC 9110 ``tchar``.
_TOKEN_CHARS = bytes(
    1 if chr(code) in "!#$%&'*+-.^_`|~" or chr(code).isalnum() and code < 0x80
    else 0
    for code in range(256)
)

#: Chunk sizes are bounded to 64 bits.  This also keeps a hostile line of
#: hundreds of thousands of hex digits from producing a huge Python int.
_MAX_CHUNK_SIZE_HEX_DIGITS = 16


def _as_text(value: object) -> str:
    """Return *value* as text, decoding wire bytes losslessly."""
    if isinstance(value, bytes):
        return value.decode("latin-1")
    if isinstance(value, str):
        return value
    return str(value)


def normalize_header_name(name: object) -> str:
    """Canonicalize a header name.

    Leading/trailing optional whitespace is removed (so the result is safe
    to look up in a dict) and the name is lowercased.  Invalid characters
    are *not* removed here; :func:`boundary_error` validates the result.
    """
    return _as_text(name).strip(" \t").lower()


def parse_headers(headers: object) -> dict[str, list[str]]:
    """Collect header fields into ``{normalized name: [value, ...]}``.

    ``headers`` may be a mapping or an iterable of ``(name, value)`` pairs.
    Duplicate field names are preserved, in the order they were supplied,
    because their number is itself a framing signal.  Values are kept
    verbatim; callers (or :func:`boundary_error`) rely on a leading
    SP/HTAB to detect obs-fold.
    """
    parsed: dict[str, list[str]] = {}
    if headers is None:
        return parsed

    if isinstance(headers, Mapping):
        pairs: list[tuple[object, object]] = []
        for name, value in headers.items():
            if isinstance(value, (list, tuple)):
                pairs.extend((name, item) for item in value)
            else:
                pairs.append((name, value))
    else:
        pairs = []
        for entry in headers:  # type: ignore[union-attr]
            if isinstance(entry, (str, bytes)):
                raise ValueError("header must be a (name, value) pair")
            try:
                name, value = entry
            except (TypeError, ValueError):
                raise ValueError("header must be a (name, value) pair") from None
            pairs.append((name, value))

    for name, value in pairs:
        key = normalize_header_name(name)
        parsed.setdefault(key, []).append(_as_text(value))
    return parsed


def _valid_header_value(value: str) -> bool:
    """Reject control characters that cannot appear in a field value.

    HTAB is the only CTL allowed inside a value; NUL, CR, LF and the rest
    are rejected.  Values containing non-ASCII text (obs-text) are allowed
    because they are opaque to the framing layer.
    """
    for char in value:
        code = ord(char)
        if char == "\t":
            continue
        if code < 0x20 or code == 0x7F:
            return False
    return True


def _skip_ows(data: bytes, index: int) -> int:
    """Advance past optional whitespace (SP / HTAB)."""
    while index < len(data) and data[index] in (0x20, 0x09):
        index += 1
    return index


def _scan_token(data: bytes, index: int) -> int | None:
    """Return the index just past a token starting at *index*, or ``None``."""
    start = index
    while index < len(data) and _TOKEN_CHARS[data[index]]:
        index += 1
    return index if index > start else None


def _scan_quoted_string(data: bytes, index: int) -> int | None:
    """Return the index just past a quoted-string, or ``None``."""
    if index >= len(data) or data[index] != 0x22:
        return None
    index += 1
    while index < len(data):
        byte = data[index]
        if byte == 0x5C:  # quoted-pair
            index += 2
        elif byte == 0x22:
            return index + 1
        elif byte == 0x09 or byte == 0x20 or 0x21 <= byte <= 0x7E or byte >= 0x80:
            index += 1
        else:
            return None
    return None  # unterminated


def _scan_token_or_quoted_string(data: bytes, index: int) -> int | None:
    token_end = _scan_token(data, index)
    if token_end is not None:
        return token_end
    return _scan_quoted_string(data, index)


def _scan_parameters(data: bytes, index: int) -> int | None:
    """Scan ``*( BWS ";" BWS token [ BWS "=" BWS (token / quoted-string) ] )``.

    *index* points just after a coding/extension name.  Returns the index
    where the (possibly empty) parameter list ends, i.e. at the first byte
    that is not part of a parameter, or ``None`` on a syntax error.
    """
    while True:
        after_ows = _skip_ows(data, index)
        if after_ows >= len(data) or data[after_ows] != 0x3B:  # ';'
            return index
        index = _skip_ows(data, after_ows + 1)
        name_end = _scan_token(data, index)
        if name_end is None:
            return None
        index = _skip_ows(data, name_end)
        if index < len(data) and data[index] == 0x3D:  # '='
            index = _skip_ows(data, index + 1)
            value_end = _scan_token_or_quoted_string(data, index)
            if value_end is None:
                return None
            index = value_end


def _valid_transfer_encoding(values: list[str]) -> bool:
    """Validate a (non-duplicated) Transfer-Encoding field.

    Codings may carry parameters (``gzip;q=1.0``), but ``chunked`` itself
    must be bare.  ``chunked`` must appear exactly once and last.
    """
    codings: list[str] = []
    for value in values:
        if not value:
            return False
        raw = value.encode("latin-1", "replace")
        index = _skip_ows(raw, 0)
        while True:
            coding_end = _scan_token(raw, index)
            if coding_end is None:
                return False
            coding = raw[index:coding_end].decode("ascii").lower()
            after_coding = _skip_ows(raw, coding_end)
            has_parameters = (
                after_coding < len(raw) and raw[after_coding] == 0x3B
            )
            parameters_end = _scan_parameters(raw, coding_end)
            if parameters_end is None:
                return False
            if coding == "chunked" and has_parameters:
                return False
            codings.append(coding)
            index = _skip_ows(raw, parameters_end)
            if index >= len(raw):
                break
            if raw[index] != 0x2C:  # ','
                return False
            index = _skip_ows(raw, index + 1)

    if not codings or codings[-1] != "chunked":
        # A non-chunked final coding leaves the message length undefined.
        return False
    return codings.count("chunked") == 1


def boundary_error(headers: object) -> str | None:
    """Return a stable rejection code, or ``None`` if framing is unambiguous.

    Precedence is intentional: a CL/TE conflict is reported before
    duplicate-field errors, because it is the strongest indication that the
    two peers will disagree about message length.
    """
    parsed = parse_headers(headers)

    if "content-length" in parsed and "transfer-encoding" in parsed:
        return "cl_te"
    if len(parsed.get("content-length", ())) > 1:
        return "dup_cl"
    if len(parsed.get("transfer-encoding", ())) > 1:
        return "dup_te"

    for name, values in parsed.items():
        if not _TOKEN_RE.fullmatch(name.encode("latin-1", "replace")):
            return "bad_header_name"
        for value in values:
            if value[:1] in (" ", "\t"):
                return "obs_fold"
            if not _valid_header_value(value):
                return "bad_header_value"

    for value in parsed.get("content-length", ()):
        # 1*DIGIT, no sign, whitespace, list separator or hex prefix.
        if not value or not value.isascii() or not value.isdigit():
            return "bad_cl"

    if "transfer-encoding" in parsed:
        if not _valid_transfer_encoding(parsed["transfer-encoding"]):
            return "bad_te"

    return None


def _valid_chunk_extensions(extensions: bytes) -> bool:
    """Validate the data after the chunk-size ``;`` separator.

    Grammar: ``chunk-ext = *( BWS ";" BWS chunk-ext-name
    [ BWS "=" BWS chunk-ext-val ] )``; malformed extensions are rejected
    rather than forwarded, because peers disagree about when they end.
    """
    if not extensions:
        return False
    # Re-attach the separator consumed by the caller: each chunk extension
    # is syntactically a parameter, i.e. it begins with ";".
    candidate = b";" + extensions
    return _scan_parameters(candidate, 0) == len(candidate)


def _parse_chunk_size_line(line: bytes) -> int | None:
    """Parse one chunk-size line, including mandatory CRLF already removed."""
    semicolon = line.find(b";")
    if semicolon < 0:
        size_text = line
        extensions = None
    else:
        size_text = line[:semicolon].rstrip(b" \t")
        extensions = line[semicolon + 1 :]

    if not size_text or not _HEX_RE.fullmatch(size_text):
        return None
    if len(size_text) > _MAX_CHUNK_SIZE_HEX_DIGITS:
        return None
    if extensions is not None and not _valid_chunk_extensions(extensions):
        return None
    return int(size_text, 16)


def _valid_trailer_line(line: bytes) -> bool:
    """Validate a trailer field line; obs-fold is not permitted."""
    if not line or line[:1] in (b" ", b"\t"):
        return False
    name, separator, value = line.partition(b":")
    if not separator or not _TOKEN_RE.fullmatch(name):
        return False
    return _valid_header_value(value.decode("latin-1"))


def _consume_trailers(data: bytes, position: int) -> tuple[bool, int]:
    """Consume the trailer section and return ``(ok, new position)``."""
    while True:
        end = data.find(b"\r\n", position)
        if end < 0:
            return False, position
        line = data[position:end]
        position = end + 2
        if not line:
            return True, position
        if not _valid_trailer_line(line):
            return False, position


def _parse_chunked(data: bytes) -> tuple[bool, list[int]]:
    """Strictly parse a complete chunked body.

    Returns ``(True, sizes)`` where *sizes* excludes the terminating zero
    chunk, or ``(False, [])`` on any framing or syntax error.
    """
    sizes: list[int] = []
    position = 0
    length = len(data)

    while True:
        line_end = data.find(b"\r\n", position)
        if line_end < 0:
            return False, []
        line = data[position:line_end]
        position = line_end + 2

        size = _parse_chunk_size_line(line)
        if size is None:
            return False, []

        if size == 0:
            ok, position = _consume_trailers(data, position)
            if not ok or position != length:
                # Trailing bytes after the last chunk are a smuggling vector.
                return False, []
            return True, sizes

        if size > length - position:
            return False, []
        position += size
        if data[position : position + 2] != b"\r\n":
            return False, []
        position += 2
        sizes.append(size)


def _as_bytes(data: object) -> bytes | None:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    if isinstance(data, str):
        return data.encode("utf-8", "surrogatepass")
    return None


def parse_chunks(data: object) -> list[int]:
    """Return the sizes of the data chunks in a chunked body.

    Chunk extensions are accepted only when they are syntactically valid.
    A malformed or incomplete body yields ``[]`` rather than a partial
    result, so callers can treat an empty list as "reject" (a legitimately
    empty chunked body is ``0\\r\\n\\r\\n`` and also contains no data chunk).
    """
    raw = _as_bytes(data)
    if raw is None:
        return []
    ok, sizes = _parse_chunked(raw)
    return sizes if ok else []


def _wire_length(text: str) -> int:
    try:
        return len(text.encode("latin-1"))
    except UnicodeEncodeError:
        return len(text.encode("utf-8", "surrogatepass"))


def check_request(
    headers: object,
    body: object = b"",
    *,
    max_header_line_bytes: int = MAX_HEADER_LINE_BYTES,
    max_header_count: int = MAX_HEADER_COUNT,
) -> bool:
    """Return ``True`` only if both peers must frame this request identically.

    Limits are applied to the raw header line (name + colon + OWS + value),
    never to a decoded/interpreted form, so a peer cannot accept a header
    that the other silently truncates.
    """
    try:
        parsed = parse_headers(headers)
    except (TypeError, ValueError):
        return False

    if boundary_error(parsed) is not None:
        return False

    if sum(len(values) for values in parsed.values()) > max_header_count:
        return False
    for name, values in parsed.items():
        for value in values:
            if _wire_length(name) + 2 + _wire_length(value) > max_header_line_bytes:
                return False

    raw_body = _as_bytes(body)
    if raw_body is None or b"\x00" in raw_body:
        return False

    expectations = parsed.get("expect", ())
    if expectations:
        # Proxy and backend must agree on exactly one supported expectation.
        if len(expectations) != 1:
            return False
        if expectations[0].strip(" \t").lower() != "100-continue":
            return False

    if "content-length" in parsed:
        declared = int(parsed["content-length"][0])
        if declared != len(raw_body):
            return False
    elif "transfer-encoding" in parsed:
        ok, _sizes = _parse_chunked(raw_body)
        if not ok:
            return False
    elif raw_body:
        # Without CL or TE this request has no body; extra bytes belong to
        # the next request on the connection.
        return False

    return True
