from src.pytography.password.algorithms import Pbkdf2, Scrypt


def test_pbkdf2_verify() -> None:
    encoded_password = Pbkdf2.encode(
        password="password", salt="salt", hash_name="sha256", iterations=600000
    )
    is_verified = Pbkdf2.verify(password="password", encoded_password=encoded_password)
    assert is_verified is True


def test_pbkdf2_verify_with_invalid_password() -> None:
    encoded_password = Pbkdf2.encode(
        password="password", salt="salt", hash_name="sha256", iterations=600000
    )
    is_verified = Pbkdf2.verify(
        password="invalid_password", encoded_password=encoded_password
    )
    assert is_verified is False


def test_scrypt_verify() -> None:
    encoded_password = Scrypt.encode(
        password="password", salt="salt", n=16384, r=8, p=1
    )
    is_verified = Scrypt.verify(password="password", encoded_password=encoded_password)
    assert is_verified is True


def test_scrypt_verify_with_invalid_password() -> None:
    encoded_password = Scrypt.encode(
        password="password", salt="salt", n=16384, r=8, p=1
    )
    is_verified = Scrypt.verify(
        password="invalid_password", encoded_password=encoded_password
    )
    assert is_verified is False
