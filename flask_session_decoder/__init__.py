from typing import Callable, Union

from base64 import urlsafe_b64decode
from hashlib import sha1
import hmac, json, zlib


class FlaskSessionSignatureError(Exception):
    ...


class FlaskSessionDecoder:
    """
    Flask session decoder.

    It only supports the default session encoding format, i.e. maybe compressed HMAC SHA1.
    """

    __slots__ = ("_salt", "_secret_key")

    # Init

    def __init__(self, *, secret_key: Union[str, bytes], salt: bytes = b"cookie-session") -> None:
        """
        Initialization.

        Arguments:
            secret_key: The secret key of the Flask application that created the session cookie.
            salt: The salt used by the Flask applicatino for signing the session cookie.
                  The default value matches the default in Flask.
        """
        self._salt: bytes = salt
        self._secret_key: bytes = secret_key if isinstance(secret_key, bytes) else secret_key.encode("utf-8")

    # -- Methods

    def json(
        self,
        cookie: str,
        *,
        verify: bool = True,
        encoding: str = "utf-8",  # Alternatively try "ascii".
        encoding_errors: str = "strict",  # Alternatively try "ignore".
        json_loader: Callable[[str], dict] = json.loads,
    ) -> dict:
        """
        Loads the JSON session cookie payload.

        Arguments:
            cookie: The session cookie to load.
            verify: Whether to verify the signature before payload loading.
            encoding: Cookie encoding to pass to `str.encode()`.
            encoding_errors: The `errors` argument for `str.encode()`.
            json_loader: The method that loads/parses the cookie payload string.
                         Default value is `json.loads`.

        Returns:
            The session cookie payload as a `dict`.

        Raises:
            FlaskSessionSignatureError: If `verify` is `True` and the cookie signature is invalid.

        """
        return json_loader(
            self.load(
                cookie,
                verify=verify,
                encoding=encoding,
                encoding_errors=encoding_errors,
            )
        )

    def load(
        self,
        cookie: str,
        *,
        encoding: str = "utf-8",  # Alternatively try "ascii".
        encoding_errors: str = "strict",  # Alternatively try "ignore".
        verify: bool = True,
    ) -> str:
        """
        Loads the session cookie payload.

        Arguments:
            cookie: The session cookie to load.
            verify: Whether to verify the signature before payload loading.
            encoding: Cookie encoding to pass to `str.encode()`.
            encoding_errors: The `errors` argument for `str.encode()`.

        Returns:
            The session cookie payload.

        Raises:
            FlaskSessionSignatureError: If `verify` is `True` and the cookie signature is invalid.
        """
        if verify and not self.verify(cookie):
            raise FlaskSessionSignatureError("Verification failed because of invalid signature.")

        compressed = cookie.startswith(".")

        if compressed:
            cookie = cookie[1:]

        data = cookie.split(".")[0].encode(encoding, encoding_errors)
        data = urlsafe_b64decode(data + b"=" * (-len(data) % 4))
        if compressed:
            data = zlib.decompress(data)

        return data.decode("utf-8")

    def verify(self, cookie: str) -> bool:
        """
        Verifies the signature of the given session cookie.

        Arguments:
            cookie: The signed session cookie.

        Returns:
            Whether the signature is valid or not.
        """
        signed_value = cookie.encode("utf-8", "strict")
        value, signature = signed_value.rsplit(b".", 1)
        return self._verify_signature(value, signature)

    # -- Protected methods

    def _base64_decode(self, value: bytes) -> bytes:
        return urlsafe_b64decode(value + b"=" * (-len(value) % 4))

    def _calculate_signature(self, key: bytes, msg: bytes) -> bytes:
        mac = hmac.new(key, msg=msg, digestmod=sha1)
        return mac.digest()

    def _calculate_salted_hmac(self, secret_key: bytes, salt: bytes) -> bytes:
        mac = hmac.new(secret_key, digestmod=sha1)
        mac.update(salt)
        return mac.digest()

    def _verify_signature(self, value: bytes, signature: bytes) -> bool:
        signature = self._base64_decode(signature)
        key = self._calculate_salted_hmac(self._secret_key, self._salt)
        return hmac.compare_digest(signature, self._calculate_signature(key=key, msg=value))
