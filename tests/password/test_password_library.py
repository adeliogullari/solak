import pytest
from typing import Literal
from src.pytography import PasswordHashLibrary


@pytest.mark.parametrize("algorithm", ["pbkdf2", "scrypt"])
def test_password_hash_library_verify(algorithm: Literal["pbkdf2", "scrypt"]) -> None:
    encoded_password = PasswordHashLibrary.encode(
        password="password", salt="salt", algorithm=algorithm
    )
    is_verified = PasswordHashLibrary.verify(
        password="password", encoded_password=encoded_password
    )
    assert is_verified is True


@pytest.mark.parametrize("algorithm", ["pbkdf2", "scrypt"])
def test_password_hash_library_verify_with_invalid_password(
    algorithm: Literal["pbkdf2", "scrypt"],
) -> None:
    encoded_password = PasswordHashLibrary.encode(
        password="password", salt="salt", algorithm=algorithm
    )
    is_verified = PasswordHashLibrary.verify(
        password="invalid_password", encoded_password=encoded_password
    )
    assert is_verified is False
