"""Tests for the security hardening features.

Updated 2026-04-30: caplog level fix for stdout audit test.
"""

import os
from pathlib import Path

import pytest

from borgmatic_api_app.config import load_settings, Settings
from borgmatic_api_app.auth import AuthManager, TokenRole
from borgmatic_api_app.actions import ActionStore, ActionPolicy, ActionPolicyError
from borgmatic_api_app.audit import AuditLogger


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------
class TestSecureModeConfig:
    def test_secure_mode_requires_admin_token(self):
        os.environ["SECURE_MODE"] = "true"
        os.environ["API_ACTION_TOKEN"] = "action123"
        os.environ["API_READ_TOKEN"] = "read123"
        os.environ.pop("API_ADMIN_TOKEN", None)
        os.environ.pop("API_TOKEN", None)
        with pytest.raises(RuntimeError, match="API_ADMIN_TOKEN"):
            load_settings()
        del os.environ["SECURE_MODE"]

    def test_secure_mode_requires_action_token(self):
        os.environ["SECURE_MODE"] = "true"
        os.environ["API_ADMIN_TOKEN"] = "admin123"
        os.environ["API_READ_TOKEN"] = "read123"
        os.environ.pop("API_ACTION_TOKEN", None)
        os.environ.pop("API_TOKEN", None)
        with pytest.raises(RuntimeError, match="API_ACTION_TOKEN"):
            load_settings()
        del os.environ["SECURE_MODE"]

    def test_legacy_mode_works_with_api_token(self):
        os.environ.pop("SECURE_MODE", None)
        os.environ["API_TOKEN"] = "legacy123"
        os.environ.pop("API_ADMIN_TOKEN", None)
        os.environ.pop("API_ACTION_TOKEN", None)
        os.environ.pop("API_READ_TOKEN", None)
        settings = load_settings()
        assert settings.admin_token == "legacy123"
        assert settings.read_token == "legacy123"
        del os.environ["API_TOKEN"]


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------
class TestTokenRoleAuth:
    def test_admin_token_authenticates_as_admin(self):
        settings = Settings(
            borg_config_dir=Path("/tmp"),
            borg_base_dir=Path("/tmp"),
            borg_ssh_dir=Path("/tmp"),
            aio_master="test",
            aio_daily="/test",
            aio_health="/test",
            aio_config_file=Path("/tmp"),
            required_aio_archive_format="test",
            docker_host="",
            exec_whitelist={},
            dangerous_commands=[],
            admin_token="admin123",
            action_token="action123",
            read_token="read123",
        )
        auth = AuthManager(settings)
        from unittest.mock import Mock

        req = Mock()
        req.headers = {
            "X-From-NodeRed": "BorgmaticAPI",
            "Authorization": "Bearer admin123",
        }
        role = auth.authenticate(req)
        assert role == TokenRole.ADMIN

    def test_action_token_authenticates_as_action(self):
        settings = Settings(
            borg_config_dir=Path("/tmp"),
            borg_base_dir=Path("/tmp"),
            borg_ssh_dir=Path("/tmp"),
            aio_master="test",
            aio_daily="/test",
            aio_health="/test",
            aio_config_file=Path("/tmp"),
            required_aio_archive_format="test",
            docker_host="",
            exec_whitelist={},
            dangerous_commands=[],
            admin_token="admin123",
            action_token="action123",
            read_token="read123",
        )
        auth = AuthManager(settings)
        from unittest.mock import Mock

        req = Mock()
        req.headers = {
            "X-From-NodeRed": "BorgmaticAPI",
            "Authorization": "Bearer action123",
        }
        role = auth.authenticate(req)
        assert role == TokenRole.ACTION

    def test_wrong_header_returns_none(self):
        settings = Settings(
            borg_config_dir=Path("/tmp"),
            borg_base_dir=Path("/tmp"),
            borg_ssh_dir=Path("/tmp"),
            aio_master="test",
            aio_daily="/test",
            aio_health="/test",
            aio_config_file=Path("/tmp"),
            required_aio_archive_format="test",
            docker_host="",
            exec_whitelist={},
            dangerous_commands=[],
            admin_token="admin123",
            action_token="action123",
            read_token="read123",
        )
        auth = AuthManager(settings)
        from unittest.mock import Mock

        req = Mock()
        req.headers = {
            "X-From-NodeRed": "WrongHeader",
            "Authorization": "Bearer admin123",
        }
        role = auth.authenticate(req)
        assert role is None


# ---------------------------------------------------------------------------
# Action policy tests
# ---------------------------------------------------------------------------
class TestActionPolicy:
    def test_valid_ssh_policy(self):
        store = ActionStore()
        policy = store._validate_and_create(
            "nextcloud-backup",
            {
                "type": "nextcloud_aio_backup",
                "remote_repo": "ssh://user@host:22/backup",
                "stop_timeout": 60,
                "timeout": 21600,
            },
        )
        assert policy.name == "nextcloud-backup"
        assert policy.type == "nextcloud_aio_backup"
        assert policy.remote_repo == "ssh://user@host:22/backup"

    def test_invalid_name(self):
        store = ActionStore()
        with pytest.raises(ActionPolicyError, match="invalid"):
            store._validate_and_create(
                "bad name!",
                {
                    "type": "nextcloud_aio_backup",
                    "remote_repo": "ssh://user@host:22/backup",
                },
            )

    def test_invalid_type(self):
        store = ActionStore()
        with pytest.raises(ActionPolicyError, match="not allowed"):
            store._validate_and_create(
                "test",
                {
                    "type": "dangerous_action",
                    "remote_repo": "ssh://user@host:22/backup",
                },
            )

    def test_missing_target(self):
        store = ActionStore()
        with pytest.raises(ActionPolicyError, match="exactly one"):
            store._validate_and_create(
                "test",
                {
                    "type": "nextcloud_aio_backup",
                },
            )

    def test_invalid_ssh_url(self):
        store = ActionStore()
        with pytest.raises(ActionPolicyError, match="SSH URL"):
            store._validate_and_create(
                "test",
                {
                    "type": "nextcloud_aio_backup",
                    "remote_repo": "ftp://bad-url",
                },
            )

    def test_target_display_masks_credentials(self):
        policy = ActionPolicy(
            name="test",
            type="nextcloud_aio_backup",
            remote_repo="ssh://user@secret-host:22/backup",
        )
        display = policy.target_display
        assert "user" in display
        assert "secret-host" not in display


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------
class TestAuditLogger:
    def test_audit_logger_writes_to_stdout(self, caplog):
        caplog.set_level("INFO")
        logger = AuditLogger(stdout=True)
        logger.log_action_start(
            action_name="test",
            source_ip="127.0.0.1",
            token_role="action",
            job_id="job-123",
            target_repo="ssh://***:22/backup",
        )
        assert "[AUDIT]" in caplog.text

    def test_audit_logger_writes_to_file(self, tmp_path):
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(log_path=log_file, stdout=False)
        logger.log_action_start(
            action_name="test",
            source_ip="127.0.0.1",
            token_role="action",
            job_id="job-123",
            target_repo="ssh://***:22/backup",
        )
        logger.log_action_complete(
            job_id="job-123",
            result="success",
            exit_code=0,
            duration_sec=1.5,
        )
        logger.close()
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2
        import json

        entry = json.loads(lines[0])
        assert entry["event"] == "action_start"
        assert entry["action_name"] == "test"
