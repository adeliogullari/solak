import json
import hmac
import base64
from typing import Any, Literal
from secrets import compare_digest
from .segments import DigestMod, Header, Payload


class JsonWebToken:
    @classmethod
    def _verify_signature(
        cls, header: dict, payload: dict, key: str, algorithm: str, signature: str
    ):
        base64_header = base64.b64encode(json.dumps(header).encode("utf-8")).decode(
            "utf-8"
        )
        base64_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode(
            "utf-8"
        )
        msg = base64.b64encode(f"{base64_header}.{base64_payload}".encode("utf-8"))
        generated_signature = base64.b64encode(
            hmac.new(
                key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
            ).digest()
        ).decode("utf-8")

        return compare_digest(signature, generated_signature)

    @classmethod
    def encode(
        cls,
        payload: dict,
        key: str,
        algorithm: Literal["HS256", "HS384", "HS512"] = "HS256",
        header: dict | None = None,
    ) -> str:
        if header is None:
            header = {}
        header.update({"alg": algorithm, "typ": "JWT"})
        base64_header = base64.b64encode(json.dumps(header).encode("utf-8")).decode(
            "utf-8"
        )
        base64_payload = base64.b64encode(json.dumps(payload).encode("utf-8")).decode(
            "utf-8"
        )
        msg = base64.b64encode(f"{base64_header}.{base64_payload}".encode("utf-8"))
        signature = base64.b64encode(
            hmac.new(
                key=key.encode("utf-8"), msg=msg, digestmod=DigestMod[algorithm]
            ).digest()
        ).decode("utf-8")
        return f"{base64_header}.{base64_payload}.{signature}"

    @classmethod
    def decode(cls, token: str) -> tuple[Any, Any, str]:
        header, payload, signature = token.split(".")
        header = json.loads(base64.b64decode(header.encode("utf-8")))
        payload = json.loads(base64.b64decode(payload.encode("utf-8")))
        return header, payload, signature

    @classmethod
    def verify(
        cls,
        token: str,
        key: str,
        algorithm: str,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
    ) -> bool:
        header, payload, signature = cls.decode(token=token)

        is_header_verified = Header(**header).verify(algorithm=algorithm)
        if not is_header_verified:
            return False

        is_payload_verified = Payload(**payload).verify(iss=iss, sub=sub, aud=aud)
        if not is_payload_verified:
            return False

        is_signature_verified = cls._verify_signature(
            header=header,
            payload=payload,
            key=key,
            algorithm=algorithm,
            signature=signature,
        )
        if not is_signature_verified:
            return False

        return True
