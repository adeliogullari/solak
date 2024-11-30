import json
import hmac
import base64
from typing import Literal
from secrets import compare_digest
from .segments import Payload

DigestMod = {
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}


class JsonWebToken:
    """
    A class for handling JSON Web Token (JWT) encoding, decoding, and signature verification.

    Methods:
        _generate_signature(cls, payload, header, key): Generates a JWT signature based on the payload, header, and key.
        _verify_signature(cls, payload, header, key, signature): Verifies if the provided signature matches the generated signature.
        encode(cls, payload, key, algorithm): Encodes a JWT with the provided payload, key, and algorithm.
        decode(cls, token): Decodes a JWT token into its header, payload, and signature components.
        verify(cls, token, key, iss, sub, aud): Verifies if the provided token's payload and signature are valid.
    """

    @classmethod
    def _generate_signature(cls, payload: dict, header: dict, key: str):
        """
        Generates a JWT signature based on the payload, header, and key.

        Args:
            payload (dict): The payload of the JWT.
            header (dict): The header of the JWT.
            key (str): The secret key to sign the JWT with.

        Returns:
            str: The base64-encoded JWT signature.
        """
        algorithm = header["alg"]
        header = base64.b64encode(json.dumps(header).encode("utf-8")).decode("utf-8")
        payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        msg = base64.b64encode(f"{header}.{payload}".encode("utf-8"))
        return base64.b64encode(
            hmac.new(
                key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
            ).digest()
        ).decode("utf-8")

    @classmethod
    def _verify_signature(cls, payload: dict, header: dict, key: str, signature: str):
        """
        Verifies if the provided signature matches the generated signature.

        Args:
            payload (dict): The payload of the JWT.
            header (dict): The header of the JWT.
            key (str): The secret key to verify the signature.
            signature (str): The signature to compare against the generated signature.

        Returns:
            bool: True if the signature matches, False otherwise.
        """
        decoded_signature = cls._generate_signature(
            payload=payload, header=header, key=key
        )
        return compare_digest(signature, decoded_signature)

    @classmethod
    def encode(
        cls,
        payload: dict,
        key: str,
        algorithm: Literal["HS256", "HS384", "HS512"] = "HS256",
    ) -> str:
        """
        Encodes a JWT with the provided payload, key, and algorithm.

        Args:
            payload (dict): The payload of the JWT.
            key (str): The secret key to sign the JWT.
            algorithm (str): The signing algorithm to use (default is "HS256").

        Returns:
            str: The encoded JWT.
        """
        base64_header = base64.b64encode(
            json.dumps({"alg": algorithm, "typ": "JWT"}).encode("utf-8")
        ).decode("utf-8")
        base64_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        msg = base64.b64encode(f"{base64_header}.{base64_payload}".encode("utf-8"))
        msg_hash = hmac.new(
            key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
        ).digest()
        signature = base64.b64encode(msg_hash).decode("utf-8")
        return f"{base64_header}.{base64_payload}.{signature}"

    @classmethod
    def decode(cls, token: str) -> tuple[dict, dict, str]:
        """
        Decodes a JWT token into its header, payload, and signature components.

        Args:
            token (str): The JWT to decode.

        Returns:
            tuple: A tuple containing the decoded header, payload, and signature.
        """
        header, payload, signature = token.split(".")
        header = json.loads(base64.b64decode(header.encode("utf-8")))
        payload = json.loads(base64.b64decode(payload.encode("utf-8")))
        return header, payload, signature

    @classmethod
    def verify(
        cls,
        token: str,
        key: str,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
    ) -> bool:
        """
        Verifies if the provided token's payload and signature are valid.

        Args:
            token (str): The JWT to verify.
            key (str): The secret key to verify the JWT signature.
            iss (str | None): The expected issuer to verify against the token's `iss` claim.
            sub (str | None): The expected subject to verify against the token's `sub` claim.
            aud (str | None): The expected audience to verify against the token's `aud` claim.

        Returns:
            bool: True if both the payload and the signature are valid, False otherwise.
        """
        header, payload, signature = cls.decode(token=token)
        is_payload_verified = Payload(**payload).verify(iss=iss, sub=sub, aud=aud)
        is_signature_verified = cls._verify_signature(
            payload=payload, header=header, key=key, signature=signature
        )
        return is_payload_verified and is_signature_verified
