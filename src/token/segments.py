from dataclasses import dataclass
from datetime import datetime, UTC


@dataclass
class Payload:
    """
    A class to represent the payload of a JWT (JSON Web Token).

    Attributes:
        iss (str | None): The issuer claim, identifies the principal that issued the token.
        sub (str | None): The subject claim, identifies the principal that is the subject of the token.
        aud (str | None): The audience claim, identifies the recipients that the token is intended for.
        exp (float | None): The expiration time claim, the time after which the token is no longer valid.
        nbf (float | None): The not-before claim, the time before which the token should not be accepted.
        iat (float | None): The issued-at claim, the time at which the token was issued.
        jti (str | None): The JWT ID claim, a unique identifier for the token.

    Methods:
        _is_iss_verified(self, iss): Verifies if the `iss` claim matches the expected issuer.
        _is_sub_verified(self, sub): Verifies if the `sub` claim matches the expected subject.
        _is_aud_verified(self, aud): Verifies if the `aud` claim matches the expected audience.
        _is_exp_verified(self, now): Verifies if the token is not expired based on the `exp` claim.
        _is_nbf_verified(self, now): Verifies if the token is valid before the `nbf` claim.
        _is_iat_verified(self, now): Verifies if the token was issued before the `iat` claim.
        verify(self, iss, sub, aud): Verifies if the provided claims match the token's claims and if it is not expired.
    """

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
        """
        Verifies if the `iss` claim matches the expected issuer.

        Args:
            iss (str | None): The expected issuer to compare with the payload's `iss` claim.

        Returns:
            bool: True if the `iss` claim matches, False otherwise.
        """
        return self.iss == iss

    def _is_sub_verified(self, sub: str | None) -> bool:
        """
        Verifies if the `sub` claim matches the expected subject.

        Args:
            sub (str | None): The expected subject to compare with the payload's `sub` claim.

        Returns:
            bool: True if the `sub` claim matches, False otherwise.
        """
        return self.sub == sub

    def _is_aud_verified(self, aud: str | None) -> bool:
        """
        Verifies if the `aud` claim matches the expected audience.

        Args:
            aud (str | None): The expected audience to compare with the payload's `aud` claim.

        Returns:
            bool: True if the `aud` claim matches, False otherwise.
        """
        return self.aud == aud

    def _is_exp_verified(self, now: float) -> bool:
        """
        Verifies if the token is not expired based on the `exp` claim.

        Args:
            now (float): The current time in seconds since the epoch.

        Returns:
            bool: True if the token is not expired, False if expired or `exp` claim is not present.
        """
        return self.exp is None or now < self.exp

    def _is_nbf_verified(self, now: float) -> bool:
        """
        Verifies if the token is valid before the `nbf` claim.

        Args:
            now (float): The current time in seconds since the epoch.

        Returns:
            bool: True if the token is valid before the `nbf` claim, False otherwise.
        """
        return self.exp is None or self.nbf < now

    def _is_iat_verified(self, now: float) -> bool:
        """
        Verifies if the token was issued before the `iat` claim.

        Args:
            now (float): The current time in seconds since the epoch.

        Returns:
            bool: True if the token was issued before the `iat` claim, False otherwise.
        """
        return self.iat is None or self.iat < now

    def verify(
        self, iss: str | None = None, sub: str | None = None, aud: str | None = None
    ) -> bool:
        """
        Verifies if the provided claims match the token's claims and if it is not expired.

        Args:
            iss (str | None): The expected issuer to verify against the `iss` claim.
            sub (str | None): The expected subject to verify against the `sub` claim.
            aud (str | None): The expected audience to verify against the `aud` claim.

        Returns:
            bool: True if all claims are valid and the token is not expired, False otherwise.
        """
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
