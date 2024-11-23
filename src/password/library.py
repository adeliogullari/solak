import secrets
from typing import Literal
from .algorithms import Pbkdf2, Scrypt


class PasswordHashLibrary:
    @classmethod
    def encode(
        cls,
        password: str,
        salt: str = secrets.token_hex(16),
        algorithm: Literal["pbkdf2", "scrypt"] = "scrypt",
        **kwargs,
    ) -> str:
        if algorithm == "pbkdf2":
            return Pbkdf2.encode(
                password=password,
                salt=salt,
                hash_name=kwargs.get("hash_name", "sha256"),
                iterations=kwargs.get("iterations", 600000),
            )
        if algorithm == "scrypt":
            return Scrypt.encode(
                password=password,
                salt=salt,
                n=kwargs.get("n", 2**14),
                r=kwargs.get("r", 8),
                p=kwargs.get("p", 1),
            )

    @classmethod
    def verify(cls, password: str, encoded_password: str) -> bool:
        if encoded_password.startswith("pbkdf2", 1):
            return Pbkdf2.verify(password=password, encoded_password=encoded_password)
        if encoded_password.startswith("scrypt", 1):
            return Scrypt.verify(password=password, encoded_password=encoded_password)
