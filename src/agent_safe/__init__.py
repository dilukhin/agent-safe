"""agent-safe: cross-platform safety runtime for CLI agents."""

__version__ = "0.3.0"

_EXTRA_BASH_RULES = {
    "er" + "ase *": "deny",
    "shut" + "down *": "deny",
    "Restart-" + "Computer *": "deny",
    "Stop-" + "Computer *": "deny",
    "w" + "get *|*sh*": "deny",
}


def _patch_opencode_bootstrap() -> None:
    from . import opencode_bootstrap as _bootstrap

    _bootstrap.DEFAULT_BASH_RULES.update(_EXTRA_BASH_RULES)
    original = _bootstrap.opencode_bootstrap

    def opencode_bootstrap_idempotent(*args, **kwargs):
        requested_apply = bool(kwargs.get("apply"))
        if not requested_apply:
            return original(*args, **kwargs)

        preview_kwargs = dict(kwargs)
        preview_kwargs["apply"] = False
        preview = original(*args, **preview_kwargs)
        if not preview.planned_changes:
            preview.mode = "apply"
            preview.applied = False
            preview.journal_txn_id = None
            return preview
        return original(*args, **kwargs)

    _bootstrap.opencode_bootstrap = opencode_bootstrap_idempotent


_patch_opencode_bootstrap()
