import hashlib
import re
from enum import Enum
import json
import base64
from typing import Any, Literal
from abc import ABC, abstractmethod
from itertools import chain, repeat
from secrets import compare_digest
from .claims import Payload

# from src.talentgate.auth.crypto.digest.library import MessageDigestLibrary
import hmac

Base64Segment = r"[A-Za-z0-9+/]{4}"
Base64Padding = r"[A-Za-z0-9+/]{2}(?:==)"
Base64OptionalPadding = r"[A-Za-z0-9+/]{3}="
JsonSegment = r"\s*\{.*?}\s*"


class ALGORITHMS(str, Enum):
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"


DigestMod = {
    ALGORITHMS.HS256: "sha256",
    ALGORITHMS.HS384: "sha384",
    ALGORITHMS.HS512: "sha512",
}

DigestMod = Literal[
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "blake2b",
    "blake2s",
    "shake_128",
    "shake_256",
    "sha3_224",
    "sha3_384",
    "sha3_512",
    "sha3_256",
]


class AuthenticationToken(ABC):
    def __init__(self, algorithm: str):
        self.message_digest_library = MessageDigestLibrary(algorithm=algorithm)

    def _is_base64_encoded(self, string: str) -> bool:
        base64_pattern = re.compile(
            f"^(?:{Base64Segment})*(?:{Base64Padding}?|{Base64OptionalPadding})?$"
        )
        return base64_pattern.match(string) is not None

    def _safe_b64encode(self, obj: Any) -> bytes:
        return base64.b64encode(json.dumps(obj).encode())

    def _safe_b64decode(self, string: str) -> bytes:
        if self._is_base64_encoded(string):
            return base64.b64decode(string)
        return base64.b64decode(base64.b64encode(string.encode()))

    def _is_json_serialized(self, string: Any) -> bool:
        json_pattern = re.compile(f"^{JsonSegment}$", re.DOTALL)
        return json_pattern.match(string) is not None

    def _safe_json_loads(self, string: str) -> Any:
        if self._is_json_serialized(string):
            return json.loads(string)
        return json.loads("{}")

    def _verify_signature(self, payload: Any, headers: Any, signature: Any, key: Any):
        token = self.encode(payload=payload, key=key, headers=headers)
        _, _, decoded_signature = self.decode(token=token)
        return compare_digest(signature, decoded_signature)

    @abstractmethod
    def encode(self, payload: Any, key: str, headers: Any) -> str:
        payload = self._safe_b64encode(payload)
        headers = self._safe_b64encode(headers)
        signature = self.message_digest_library.encode(
            data=f"{payload}.{headers}", key=key
        )
        return b".".join([payload, headers, signature]).decode("utf-8")

    @abstractmethod
    def decode(self, token: str) -> tuple[Any, Any, Any]:
        payload, headers, signature, *_ = chain(token.split("."), repeat("{}", 3))
        payload = self._safe_json_loads(self._safe_b64decode(payload).decode("utf-8"))
        headers = self._safe_json_loads(self._safe_b64decode(headers).decode("utf-8"))
        return payload, headers, signature

    @abstractmethod
    def verify(
        self,
        key: str,
        token: str,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
    ) -> bool:
        payload, headers, signature = self.decode(token=token)
        is_payload_verified = Payload(**payload).verify(iss=iss, sub=sub, aud=aud)
        is_signature_verified = self._verify_signature(
            payload=payload, headers=headers, signature=signature, key=key
        )
        return is_payload_verified and is_signature_verified


class JsonWebToken:
    @classmethod
    def encode(
        cls,
        payload: dict,
        key: str,
        digestmod: Literal["sha256", "sha384", "sha512"] = "sha256",
        **kwargs,
    ) -> str:
        headers = base64.b64encode(
            json.dumps({"alg": digestmod, "typ": "JWT"}).encode("utf-8")
        ).decode("utf-8")
        payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        msg = base64.b64encode(f"{headers}.{payload}".encode("utf-8"))
        msg_hash = hmac.new(
            key=key.encode("utf-8"), msg=msg, digestmod=digestmod
        ).digest()
        signature = base64.b64encode(msg_hash).decode("utf-8")
        return f"{headers}.{payload}.{signature}"

    @abstractmethod
    def decode(self, token: str) -> tuple[Any, Any, Any]:
        headers, payload, signature, *_ = chain(token.split("."), repeat("{}", 3))
        headers = json.loads(base64.b64decode(headers.encode("utf-8")))
        payload = json.loads(base64.b64decode(payload.encode("utf-8")))
        return headers, payload, signature

    @abstractmethod
    def verify(
        self,
        key: str,
        token: str,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
    ) -> bool:
        payload, headers, signature = self.decode(token=token)
        headers = base64.b64encode(json.dumps(headers).encode("utf-8")).decode("utf-8")
        payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        msg = base64.b64encode(f"{headers}.{payload}".encode("utf-8"))
        hmac_sha3_256 = hmac.new(
            key=key.encode("utf-8"), msg=msg, digestmod=DigestMod.get(headers["alg"])
        )
        signature = base64.b64encode(hmac_sha3_256.digest()).decode("utf-8")

        is_payload_verified = Payload(**payload).verify(iss=iss, sub=sub, aud=aud)
        is_signature_verified = self._verify_signature(
            payload=payload, headers=headers, signature=signature, key=key
        )
        return is_payload_verified and is_signature_verified

    # hmac_sha256 = hmac.new(key, message, hashlib.sha256)
