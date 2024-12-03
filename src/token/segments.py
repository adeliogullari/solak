from dataclasses import dataclass
from datetime import datetime, UTC


DigestMod = {
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}


@dataclass
class Header:
    alg: str
    typ: str

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def _is_alg_verified(self, algorithm: str) -> bool:
        if (
            isinstance(self.alg, str)
            and isinstance(algorithm, str)
            and self.alg in DigestMod
            and algorithm in DigestMod
        ):
            return self.alg == algorithm

        return False

    def verify(self, algorithm: str) -> bool:
        is_alg_verified = self._is_alg_verified(algorithm=algorithm)
        return is_alg_verified


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
        if self.iss is None and iss is None:
            return True

        if isinstance(self.iss, str) and isinstance(iss, str):
            return self.iss == iss

        return False

    def _is_sub_verified(self, sub: str | None) -> bool:
        if self.sub is None and sub is None:
            return True

        if isinstance(self.sub, str) and isinstance(sub, str):
            return self.sub == sub

        return False

    def _is_aud_verified(self, aud: str | None) -> bool:
        if self.aud is None and aud is None:
            return True

        if isinstance(self.aud, str) and isinstance(aud, str):
            return self.aud == aud

        return False

    def _is_exp_verified(self, now: float) -> bool:
        if self.exp is None:
            return True

        if isinstance(self.exp, float):
            return self.exp > now

        return False

    def _is_nbf_verified(self, now: float) -> bool:
        if self.nbf is None:
            return True

        if isinstance(self.nbf, float):
            return self.nbf < now

        return False

    def _is_iat_verified(self, now: float) -> bool:
        if self.iat is None:
            return True

        if isinstance(self.iat, float):
            return self.iat < now

        return False

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
