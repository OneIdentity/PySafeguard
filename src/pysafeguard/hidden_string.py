"""Hidden string wrapper for sensitive values.

Provides protection against casual exposure of secrets (passwords, tokens)
in logs, repr, and debugger output. Uses a mutable ``bytearray`` for storage
so the value can be explicitly zeroed on disposal.

.. warning::
    This is **not** equivalent to .NET's ``SecureString``. Python cannot
    encrypt memory regions or guarantee that transient copies (the original
    ``str`` argument, decoded return values from :meth:`get_value`, copies
    made by HTTP libraries) are scrubbed. This class minimizes the *window*
    and *surface area* of plaintext exposure — it does not eliminate it.
"""

from __future__ import annotations

from typing import Any, SupportsIndex


class HiddenString:
    """A string wrapper that hides sensitive values from casual exposure.

    :param value: The plaintext secret to protect.

    Usage::

        secret = HiddenString("hunter2")
        print(secret)          # "***"
        print(repr(secret))    # "HiddenString(***)"
        secret.get_value()     # "hunter2"
        secret.dispose()       # zeros memory
        secret.get_value()     # RuntimeError
    """

    __slots__ = ("_data", "_disposed")

    def __init__(self, value: str) -> None:
        self._data: bytearray | None = bytearray(value.encode("utf-8"))
        self._disposed = False

    @property
    def value(self) -> str:
        """The plaintext value.

        :raises RuntimeError: If the string has been disposed.
        """
        if self._disposed or self._data is None:
            raise RuntimeError("HiddenString has been disposed")
        return self._data.decode("utf-8")

    def get_value(self) -> str:
        """Return the plaintext value.

        .. deprecated:: 8.0
            Use the :attr:`value` property instead.

        :raises RuntimeError: If the string has been disposed.
        """
        return self.value

    def dispose(self) -> None:
        """Zero out and release the stored value."""
        if self._data is not None:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = None
        self._disposed = True

    @property
    def is_disposed(self) -> bool:
        """Whether this hidden string has been disposed."""
        return self._disposed

    def __del__(self) -> None:
        self.dispose()

    def __repr__(self) -> str:
        return "HiddenString(***)"

    def __str__(self) -> str:
        return "***"

    def __bool__(self) -> bool:
        return not self._disposed and self._data is not None and len(self._data) > 0

    def __len__(self) -> int:
        """Return the character length of the stored value (or 0 if disposed)."""
        if self._disposed or self._data is None:
            return 0
        return len(self._data.decode("utf-8"))

    def __eq__(self, other: object) -> bool:
        """Compare two HiddenStrings by their underlying value."""
        if not isinstance(other, HiddenString):
            return NotImplemented
        if self._disposed or other._disposed:
            return self._disposed and other._disposed
        return self._data == other._data

    def __hash__(self) -> int:
        raise TypeError("unhashable type: 'HiddenString'")

    def __enter__(self) -> HiddenString:
        """Context manager entry — returns self."""
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit — disposes the secret."""
        self.dispose()

    # Block serialization and copying to prevent secret leakage

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        raise TypeError("HiddenString cannot be pickled")

    def __getstate__(self) -> Any:
        raise TypeError("HiddenString cannot be pickled")

    def __copy__(self) -> "HiddenString":
        raise TypeError("HiddenString cannot be copied — create a new instance instead")

    def __deepcopy__(self, memo: dict[Any, Any]) -> "HiddenString":
        raise TypeError("HiddenString cannot be deep-copied — create a new instance instead")
