from datetime import datetime, timedelta, UTC
from src.token.claims import Payload


def test_payload_verify() -> None:
    now = datetime.now(UTC)
    exp = (now + timedelta(seconds=7200)).timestamp()
    nbf = (now - timedelta(seconds=60)).timestamp()
    iat = (now - timedelta(seconds=60)).timestamp()

    payload = Payload(exp=exp, nbf=nbf, iat=iat)

    assert payload.verify(iss=payload.iss, sub=payload.sub, aud=payload.aud) is True


def test_payload_verify_with_exceed_expiration() -> None:
    now = datetime.now(UTC)
    exp = (now - timedelta(seconds=7200)).timestamp()
    nbf = (now + timedelta(seconds=60)).timestamp()
    iat = (now + timedelta(seconds=60)).timestamp()

    payload = Payload(exp=exp, nbf=nbf, iat=iat)

    assert payload.verify(iss=payload.iss, sub=payload.sub, aud=payload.aud) is False
