import pytest
from app import decode_resp


def test_decode_single_chunk():
    data = b"\xff\xff\xff\xffHello world\x00"
    assert decode_resp(data) == "Hello world"


def test_decode_multiple_chunks():
    data = b"\xff\xff\xff\xffLine1\n\xff\xff\xff\xffLine2\r\n"
    assert decode_resp(data) == "Line1\nLine2"
