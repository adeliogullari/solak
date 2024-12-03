import pytest
from datetime import datetime, timedelta, UTC
from src.pytography.token.segments import Header, Payload


@pytest.mark.parametrize(
    "alg, algorithm", [["HS256", "HS256"], ["HS384", "HS384"], ["HS512", "HS512"]]
)
def test_header_verify(alg, algorithm) -> None:
    header = Header(alg=alg, typ="JWT")
    assert header.verify(algorithm=algorithm) is True


@pytest.mark.parametrize("alg", [None, "", "InvalidAlgorithm", "HS384", "HS512"])
def test_header_verify_with_invalid_alg_claim(alg) -> None:
    header = Header(alg=alg, typ="JWT")
    assert header.verify(algorithm="HS256") is False


@pytest.mark.parametrize("algorithm", [None, "", "InvalidAlgorithm", "HS384", "HS512"])
def test_header_verify_with_invalid_algorithm(algorithm) -> None:
    header = Header(alg="HS256", typ="JWT")
    assert header.verify(algorithm=algorithm) is False


def test_payload_verify() -> None:
    now = datetime.now(UTC)
    exp = (now + timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = Payload(sub="sub", iss="iss", aud="aud", exp=exp, nbf=nbf, iat=iat)

    assert payload.verify(iss=payload.iss, sub=payload.sub, aud=payload.aud) is True


def test_payload_verify_with_exceed_expiration() -> None:
    now = datetime.now(UTC)
    exp = (now - timedelta(seconds=7200)).timestamp()
    nbf = (now + timedelta(seconds=60)).timestamp()
    iat = (now + timedelta(seconds=60)).timestamp()

    payload = Payload(sub="sub", iss="iss", aud="aud", exp=exp, nbf=nbf, iat=iat)

    assert payload.verify(iss=payload.iss, sub=payload.sub, aud=payload.aud) is False
