"""Unit tests for pysafeguard.hidden_string — HiddenString wrapper."""

import copy
import pickle

import pytest

from pysafeguard.hidden_string import HiddenString


class TestHiddenStringBasic:
    def test_get_value_returns_original(self):
        hs = HiddenString("hunter2")
        assert hs.get_value() == "hunter2"

    def test_get_value_unicode(self):
        hs = HiddenString("pässwörd™")
        assert hs.get_value() == "pässwörd™"

    def test_get_value_empty_string(self):
        hs = HiddenString("")
        assert hs.get_value() == ""

    def test_bool_true_when_non_empty(self):
        assert bool(HiddenString("secret"))

    def test_bool_false_when_empty(self):
        assert not bool(HiddenString(""))


class TestHiddenStringDispose:
    def test_dispose_makes_get_value_raise(self):
        hs = HiddenString("secret")
        hs.dispose()
        with pytest.raises(RuntimeError, match="disposed"):
            hs.get_value()

    def test_is_disposed_property(self):
        hs = HiddenString("secret")
        assert not hs.is_disposed
        hs.dispose()
        assert hs.is_disposed

    def test_double_dispose_is_safe(self):
        hs = HiddenString("secret")
        hs.dispose()
        hs.dispose()  # Should not raise
        assert hs.is_disposed

    def test_bool_false_after_dispose(self):
        hs = HiddenString("secret")
        hs.dispose()
        assert not bool(hs)


class TestHiddenStringExposurePrevention:
    def test_repr_hides_value(self):
        hs = HiddenString("secret")
        assert "secret" not in repr(hs)
        assert "***" in repr(hs)

    def test_str_hides_value(self):
        hs = HiddenString("secret")
        assert str(hs) == "***"

    def test_fstring_hides_value(self):
        hs = HiddenString("secret")
        assert f"password={hs}" == "password=***"


class TestHiddenStringSerializationBlocked:
    def test_pickle_raises(self):
        hs = HiddenString("secret")
        with pytest.raises(TypeError, match="pickled"):
            pickle.dumps(hs)

    def test_copy_raises(self):
        hs = HiddenString("secret")
        with pytest.raises(TypeError, match="copied"):
            copy.copy(hs)

    def test_deepcopy_raises(self):
        hs = HiddenString("secret")
        with pytest.raises(TypeError, match="deep-copied"):
            copy.deepcopy(hs)
