import secrets
from src.token.algorithms import Blake2b


def test_blake2b_verify() -> None:
    encoded_data = Blake2b.encode(
        data=b"data", key=b"key", salt=secrets.token_bytes(16)
    )
    is_verified = Blake2b.verify(data=b"data", key=b"key", encoded_data=encoded_data)
    assert is_verified is True


def test_blake2b_verify_with_invalid_data() -> None:
    encoded_data = Blake2b.encode(
        data=b"data", key=b"key", salt=secrets.token_bytes(16)
    )
    is_verified = Blake2b.verify(
        data=b"invalid_data", key=b"key", encoded_data=encoded_data
    )
    assert is_verified is False


def test_blake2b_verify_with_invalid_key() -> None:
    encoded_data = Blake2b.encode(
        data=b"data", key=b"key", salt=secrets.token_bytes(16)
    )
    is_verified = Blake2b.verify(
        data=b"data", key=b"invalid_key", encoded_data=encoded_data
    )
    assert is_verified is False
