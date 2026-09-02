"""Connector configuration management.

Allows admins to configure source credentials from the UI instead of editing
.env and restarting. Values are stored in the database and override .env
settings when present.

Security note: credentials are stored as plaintext JSON in SQLite, same as
they would be in .env. For production, consider encrypting the config column
with a key from a KMS.
"""
from __future__ import annotations

import os

from sqlalchemy import select

from .config import settings, reload_settings
from .models import ConnectorConfig, utcnow


# Field definitions per source, with which fields are sensitive
SOURCE_FIELDS = {
    "wiz": {
        "fields": [
            {"key": "client_id", "label": "Client ID", "sensitive": False, "required": True},
            {"key": "client_secret", "label": "Client Secret", "sensitive": True, "required": True},
            {"key": "api_url", "label": "API URL", "sensitive": False, "required": True,
             "placeholder": "https://api.us17.app.wiz.io/graphql"},
            {"key": "auth_url", "label": "Auth URL", "sensitive": False,
             "default": "https://auth.app.wiz.io/oauth/token"},
            {"key": "audience", "label": "Audience", "sensitive": False, "default": "wiz-api"},
            {"key": "page_size", "label": "Page Size", "sensitive": False, "default": "500"},
        ],
    },
    "falcon": {
        "fields": [
            {"key": "client_id", "label": "Client ID", "sensitive": False, "required": True},
            {"key": "client_secret", "label": "Client Secret", "sensitive": True, "required": True},
            {"key": "base_url", "label": "Base URL", "sensitive": False, "required": True,
             "placeholder": "https://api.crowdstrike.com",
             "help": "Match your cloud: api.crowdstrike.com (us-1), api.us-2.crowdstrike.com, api.eu-1.crowdstrike.com"},
            {"key": "member_cid", "label": "Member CID (MSSP only)", "sensitive": False},
            {"key": "filter_fql", "label": "Filter FQL", "sensitive": False,
             "default": "status:!'closed'"},
        ],
    },
    "github": {
        "fields": [
            {"key": "token", "label": "Personal Access Token", "sensitive": True, "required": True},
            {"key": "org", "label": "Organization", "sensitive": False, "required": True},
            {"key": "api_url", "label": "API URL", "sensitive": False,
             "default": "https://api.github.com"},
            {"key": "include_dependabot", "label": "Include Dependabot", "sensitive": False, "default": "1"},
            {"key": "include_code_scanning", "label": "Include Code Scanning", "sensitive": False, "default": "1"},
            {"key": "include_secret_scanning", "label": "Include Secret Scanning", "sensitive": False, "default": "1"},
        ],
    },
}

# Map from DB config keys to environment variable names
ENV_MAP = {
    "wiz": {
        "client_id": "WIZ_CLIENT_ID", "client_secret": "WIZ_CLIENT_SECRET",
        "api_url": "WIZ_API_URL", "auth_url": "WIZ_AUTH_URL",
        "audience": "WIZ_AUDIENCE", "page_size": "WIZ_PAGE_SIZE",
    },
    "falcon": {
        "client_id": "FALCON_CLIENT_ID", "client_secret": "FALCON_CLIENT_SECRET",
        "base_url": "FALCON_BASE_URL", "member_cid": "FALCON_MEMBER_CID",
        "filter_fql": "FALCON_FILTER_FQL",
    },
    "github": {
        "token": "GITHUB_TOKEN", "org": "GITHUB_ORG",
        "api_url": "GITHUB_API_URL",
        "include_dependabot": "GITHUB_DEPENDABOT",
        "include_code_scanning": "GITHUB_CODE_SCANNING",
        "include_secret_scanning": "GITHUB_SECRET_SCANNING",
    },
}


def get_config(db, source: str) -> dict:
    """Get the current config for a source, merging DB overrides with .env."""
    row = db.execute(
        select(ConnectorConfig).where(ConnectorConfig.source == source)
    ).scalar_one_or_none()
    db_config = (row.config if row else {}) or {}

    # Start with env vars, then override with DB values
    env_map = ENV_MAP.get(source, {})
    merged = {}
    for key, env_name in env_map.items():
        merged[key] = db_config.get(key) or os.getenv(env_name, "")

    return merged


def get_config_display(db, source: str) -> dict:
    """Get config for display, masking sensitive fields."""
    config = get_config(db, source)
    fields = SOURCE_FIELDS.get(source, {}).get("fields", [])
    display = {}
    for f in fields:
        key = f["key"]
        val = config.get(key, "")
        if f.get("sensitive") and val:
            display[key] = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
        else:
            display[key] = val
    return display


def save_config(db, source: str, config: dict, actor: str) -> dict:
    """Save connector config to the database and apply to runtime."""
    row = db.execute(
        select(ConnectorConfig).where(ConnectorConfig.source == source)
    ).scalar_one_or_none()
    if not row:
        row = ConnectorConfig(source=source)
        db.add(row)

    # Merge: only update fields that were provided (don't blank out secrets not resent)
    current = dict(row.config or {})
    for key, value in config.items():
        if value is not None and value != "":
            current[key] = value
        elif key in current and (value == "" or value is None):
            # Explicitly clearing a field
            if value == "":
                current.pop(key, None)

    # Reassign so SQLAlchemy detects the change (JSON columns don't track mutations)
    row.config = current
    row.updated_by = actor
    db.commit()

    # Apply to environment so connectors pick up the changes without restart
    apply_to_env(source, current)

    # Reload settings
    reload_settings()

    return get_config_display(db, source)


def apply_to_env(source: str, config: dict):
    """Push DB config values into environment variables so connectors see them."""
    env_map = ENV_MAP.get(source, {})
    for key, env_name in env_map.items():
        val = config.get(key)
        if val:
            os.environ[env_name] = str(val)


def apply_all_from_db(db):
    """On startup, apply any DB-stored configs to the environment."""
    for source in SOURCE_FIELDS:
        row = db.execute(
            select(ConnectorConfig).where(ConnectorConfig.source == source)
        ).scalar_one_or_none()
        if row and row.config:
            apply_to_env(source, row.config)
    reload_settings()


def get_field_definitions(source: str) -> list[dict]:
    return SOURCE_FIELDS.get(source, {}).get("fields", [])
