import re
import json
import hmac
import base64
from typing import Any, Literal
from itertools import chain, repeat
from secrets import compare_digest

from dataclasses import dataclass
from datetime import datetime, UTC

Base64Segment = r"[A-Za-z0-9+/]{4}"
Base64Padding = r"[A-Za-z0-9+/]{2}(?:==)"
Base64OptionalPadding = r"[A-Za-z0-9+/]{3}="

DigestMod = {
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}


@dataclass
class Payload:
    iss: str | None = None
    sub: str | None = None
    aud: str | None = None
    exp: float | None = None
    nbf: float | None = None
    iat: float | None = None
    jti: str | None = None

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def _is_iss_verified(self, iss: str | None) -> bool:
        return self.iss == iss

    def _is_sub_verified(self, sub: str | None) -> bool:
        return self.sub == sub

    def _is_aud_verified(self, aud: str | None) -> bool:
        return self.aud == aud

    def _is_exp_verified(self, now: float) -> bool:
        return self.exp is None or now < self.exp

    def _is_nbf_verified(self, now: float) -> bool:
        return self.exp is None or self.nbf < now

    def _is_iat_verified(self, now: float) -> bool:
        return self.iat is None or self.iat < now

    def verify(
        self, iss: str | None = None, sub: str | None = None, aud: str | None = None
    ) -> bool:
        now = datetime.now(UTC).timestamp()
        is_iss_verified = self._is_iss_verified(iss=iss)
        is_sub_verified = self._is_sub_verified(sub=sub)
        is_aud_verified = self._is_aud_verified(aud=aud)
        is_exp_verified = self._is_exp_verified(now=now)
        is_nbf_verified = self._is_nbf_verified(now=now)
        is_iat_verified = self._is_iat_verified(now=now)
        return (
            is_iss_verified
            and is_sub_verified
            and is_aud_verified
            and is_exp_verified
            and is_nbf_verified
            and is_iat_verified
        )


class JsonWebToken:
    @classmethod
    def _is_base64_encoded(cls, string: str) -> bool:
        base64_pattern = re.compile(
            f"^(?:{Base64Segment})*(?:{Base64Padding}?|{Base64OptionalPadding})?$"
        )
        return base64_pattern.match(string) is not None

    @classmethod
    def _verify_signature(cls, payload: Any, headers: Any, signature: Any, key: Any):
        algorithm = headers["alg"]
        headers = base64.b64encode(json.dumps(headers).encode("utf-8")).decode("utf-8")
        payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")

        msg = base64.b64encode(f"{headers}.{payload}".encode("utf-8"))
        msg_hash = hmac.new(
            key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
        ).digest()
        decoded_signature = base64.b64encode(msg_hash).decode("utf-8")
        return compare_digest(signature, decoded_signature)

    @classmethod
    def encode(
        cls,
        payload: dict,
        key: str,
        algorithm: Literal["HS256", "HS384", "HS512"] = "HS256",
    ) -> str:
        headers = base64.b64encode(
            json.dumps({"alg": algorithm, "typ": "JWT"}).encode("utf-8")
        ).decode("utf-8")
        payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        msg = base64.b64encode(f"{headers}.{payload}".encode("utf-8"))
        msg_hash = hmac.new(
            key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
        ).digest()
        signature = base64.b64encode(msg_hash).decode("utf-8")
        return f"{headers}.{payload}.{signature}"

    @classmethod
    def decode(cls, token: str) -> tuple[Any, Any, Any]:
        headers, payload, signature, *_ = chain(token.split("."), repeat("{}", 3))
        headers = json.loads(base64.b64decode(headers.encode("utf-8")))
        payload = json.loads(base64.b64decode(payload.encode("utf-8")))
        return headers, payload, signature

    @classmethod
    def verify(
        cls,
        token: str,
        key: str,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
    ) -> bool:
        headers, payload, signature = cls.decode(token=token)

        # headers = base64.b64encode(json.dumps(headers).encode("utf-8")).decode("utf-8")
        # payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        # msg = base64.b64encode(f"{headers}.{payload}".encode("utf-8"))
        # hmac_sha3_256 = hmac.new(
        #    key=key.encode("utf-8"), msg=msg, digestmod=DigestMod.get(headers["alg"])
        # )
        # signature = base64.b64encode(hmac_sha3_256.digest()).decode("utf-8")

        is_payload_verified = Payload(**payload).verify(iss=iss, sub=sub, aud=aud)
        is_signature_verified = cls._verify_signature(
            payload=payload, headers=headers, signature=signature, key=key
        )
        return is_payload_verified and is_signature_verified

    # hmac_sha256 = hmac.new(key, message, hashlib.sha256)
