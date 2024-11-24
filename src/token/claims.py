from dataclasses import dataclass
from datetime import datetime, UTC


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
