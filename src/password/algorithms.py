import base64
import secrets
import hashlib


class Pbkdf2:
    @classmethod
    def encode(cls, password: str, salt: str, hash_name: str, iterations: int) -> str:
        password_hash = hashlib.pbkdf2_hmac(
            hash_name=hash_name,
            password=password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            iterations=iterations,
        )

        password_hash = base64.b64encode(password_hash).decode("utf-8")

        return f"$pbkdf2-{hash_name}$i={iterations}${salt}${password_hash}"

    @classmethod
    def decode(cls, encoded_password: str) -> tuple:
        parts = encoded_password.split("$")
        hash_name = parts[1].split("-")[1]
        iterations = int(parts[2].split("=")[1])
        salt = parts[3]
        password_hash = base64.b64decode(parts[4])

        return (
            hash_name,
            salt,
            iterations,
            password_hash,
        )

    @classmethod
    def verify(cls, password: str, encoded_password: str) -> bool:
        decoded_data = cls.decode(encoded_password=encoded_password)

        password_hash = hashlib.pbkdf2_hmac(
            hash_name=decoded_data[0],
            password=password.encode("utf-8"),
            salt=decoded_data[1].encode("utf-8"),
            iterations=decoded_data[2],
        )

        return secrets.compare_digest(password_hash, decoded_data[3])


class Scrypt:
    @classmethod
    def encode(cls, password: str, salt: str, n: int, r: int, p: int) -> str:
        password_hash = hashlib.scrypt(
            password=password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=n,
            r=r,
            p=p,
        )

        password_hash = base64.b64encode(password_hash).decode("utf-8")

        return f"$scrypt$ln={n}$r={r}$p={p}${salt}${password_hash}"

    @classmethod
    def decode(cls, encoded_password: str) -> tuple:
        parts = encoded_password.split("$")
        n = int(parts[2].split("=")[1])
        r = int(parts[3].split("=")[1])
        p = int(parts[4].split("=")[1])
        salt = parts[5]
        password_hash = base64.b64decode(parts[6])

        return (
            salt,
            n,
            r,
            p,
            password_hash,
        )

    @classmethod
    def verify(cls, password: str, encoded_password: str) -> bool:
        decoded_password = cls.decode(encoded_password)

        password_hash = hashlib.scrypt(
            password=password.encode("utf-8"),
            salt=decoded_password[0].encode("utf-8"),
            n=decoded_password[1],
            r=decoded_password[2],
            p=decoded_password[3],
        )

        return secrets.compare_digest(password_hash, decoded_password[4])
