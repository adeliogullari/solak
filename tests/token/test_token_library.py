import pytest
from typing import Any
from datetime import datetime, timedelta, UTC
from src.token.library import JsonWebToken


@pytest.mark.parametrize("algorithm", ["HS256", "HS384", "HS512"])
def test_json_web_token_verify(algorithm: Any) -> None:
    now = datetime.now(UTC)
    exp = (now + timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "aud",
        "exp": exp,
        "nbf": nbf,
        "iat": iat,
    }

    token = JsonWebToken.encode(payload=payload, key="key", algorithm=algorithm)

    assert (
        JsonWebToken.verify(
            token=token, key="key", algorithm=algorithm, iss="iss", sub="sub", aud="aud"
        )
        is True
    )


def test_json_web_token_verify_with_invalid_key() -> None:
    now = datetime.now(UTC)
    exp = (now + timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "aud",
        "exp": exp,
        "nbf": nbf,
        "iat": iat,
    }

    token = JsonWebToken.encode(payload=payload, key="key", algorithm="HS256")

    assert (
        JsonWebToken.verify(
            token=token,
            key="invalid_key",
            algorithm="HS256",
            iss="iss",
            sub="sub",
            aud="aud",
        )
        is False
    )


@pytest.mark.parametrize("algorithm", [None, "", "InvalidAlgorithm", "HS384", "HS512"])
def test_json_web_token_verify_with_invalid_algorithm(algorithm) -> None:
    now = datetime.now(UTC)
    exp = (now + timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "aud",
        "exp": exp,
        "nbf": nbf,
        "iat": iat,
    }

    token = JsonWebToken.encode(payload=payload, key="key", algorithm="HS256")

    assert (
        JsonWebToken.verify(
            token=token,
            key="key",
            algorithm=algorithm,
            iss="iss",
            sub="sub",
            aud="aud",
        )
        is False
    )


def test_json_web_token_verify_with_exceed_expiration() -> None:
    now = datetime.now(UTC)
    exp = (now - timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = {
        "iss": "iss",
        "sub": "sub",
        "aud": "aud",
        "exp": exp,
        "nbf": nbf,
        "iat": iat,
    }

    token = JsonWebToken.encode(payload=payload, key="key", algorithm="HS256")

    assert (
        JsonWebToken.verify(
            token=token, key="key", algorithm="HS256", iss="iss", sub="sub", aud="aud"
        )
        is False
    )
