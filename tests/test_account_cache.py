from __future__ import annotations

from claude_sentinel.collectors.base import cache_write
from claude_sentinel.config import Settings
from claude_sentinel.models import AccountState
from claude_sentinel.pipeline import _load_account_cache


def test_account_cache_roundtrip(tmp_path):
    settings = Settings(home=tmp_path)
    settings.ensure()
    state = AccountState(state="active", method="session_cookie", chat_capable=True)
    cache_write(settings.cache_dir, "account_state", state.model_dump(mode="json"))
    loaded = _load_account_cache(settings)
    assert loaded is not None
    assert loaded.state == "active"
    assert loaded.chat_capable is True


def test_account_cache_absent(tmp_path):
    settings = Settings(home=tmp_path)
    settings.ensure()
    assert _load_account_cache(settings) is None
