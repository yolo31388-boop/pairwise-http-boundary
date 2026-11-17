import pytest

from security.http_boundary import (
    parse_headers,
    boundary_error,
    parse_chunks,
    normalize_header_name,
    check_request
)


def test_parse_dup_cl():
    assert parse_headers([('Content-Length', '5'), ('Content-Length', '7')])['content-length'] == ['5', '7']

def test_normalize():
    assert normalize_header_name(' Content-Length ') == 'content-length'

def test_cl_te():
    assert boundary_error({'content-length': ['5'], 'transfer-encoding': ['chunked']}) == 'cl_te'

def test_only_cl():
    assert boundary_error({'content-length': ['5']}) is None

def test_only_te():
    assert boundary_error({'transfer-encoding': ['chunked']}) is None

def test_dup_te():
    assert boundary_error({'transfer-encoding': ['chunked', 'chunked']}) == 'dup_te'

def test_obs_fold():
    assert boundary_error({'x-test': ['a', ' b']}) == 'obs_fold'

def test_chunks():
    assert parse_chunks('4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n') == [4, 5]

def test_chunk_ext():
    assert parse_chunks('4;foo=bar\r\nWiki\r\n0\r\n\r\n') == [4]

def test_chunks_bad():
    assert parse_chunks('Z\r\n') == []

def test_nul():
    assert check_request({'content-length': ['4']}, 'a\x00b') is False

def test_long_header():
    assert check_request({'x-long': ['a' * 9000]}, '') is False

def test_continue():
    assert check_request({'expect': ['100-continue'], 'content-length': ['4']}, 'body') is True

def test_dup_cl_error():
    assert boundary_error({'content-length': ['5', '5']}) == 'dup_cl'

def test_empty():
    assert check_request({}, '') is True
