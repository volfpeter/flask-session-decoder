# flask-session-decoder

Zero-dependency Flask session decoder.

This is a small library without any dependencies. It works with close to default Flask session security configurations, but obviously does not provide the full cookie decoding and verification capabilities of `flask` / `werkzeug` / `itsdangerous`. If your project already depends on these libraries, use the official tooling instead.

## Installation and Usage

You can install the library from PyPI with `pip install flask-session-decoder`.

Once installed, you can import and instantiate the decoder like this:

```python
from flask_session_decoder import FlaskSessionDecoder

decoder = FlaskSessionDecoder(secret_key="the-secret-key-of-the-flask-app-that-created-the-cookie")
```

`FlaskSessionDecoder` provides three methods for cookie verification and loading:

- `decoder.load(cookie)` returns the (by default verified) decoded string representation of the cookie.
- `decoder.json(cookie)` returns the (by default verified) decoded cookie as a `dict`.
- `verify(cookie)` returns whether the cookie signature is valid, without actually loading the value.

## Development

Use `black` for code formatting and `mypy` for static code analysis.

## License - MIT

The library is open-sourced under the conditions of the MIT [license](https://choosealicense.com/licenses/mit/).
