"""测试 cli.py: 斜杠命令 + 补全 + 分发。"""

from secagent.cli import (
    SLASH_COMMANDS, SLASH_HELP, build_completer,
    parse_and_execute, BANNER,
)
from prompt_toolkit.completion import NestedCompleter


class TestSlashCommands:
    def test_all_commands_present(self):
        expected = ["/analyze", "/batch", "/skills", "/memory",
                    "/history", "/config", "/monitor", "/help", "/exit", "/quit"]
        for cmd in expected:
            assert cmd in SLASH_COMMANDS, f"missing {cmd}"

    def test_help_has_all_commands(self):
        for cmd in SLASH_COMMANDS:
            assert cmd in SLASH_HELP, f"missing help for {cmd}"

    def test_monitor_subcommands(self):
        assert "list" in SLASH_COMMANDS["/monitor"]
        assert "add" in SLASH_COMMANDS["/monitor"]
        assert "run" in SLASH_COMMANDS["/monitor"]

    def test_build_completer(self):
        completer = build_completer()
        assert isinstance(completer, NestedCompleter)


class TestParseAndExecute:
    def test_exit_returns_true(self, mock_config):
        from secagent.agent import SecurityAgent
        agent = SecurityAgent(mock_config)
        assert parse_and_execute(agent, "/exit") is True
        assert parse_and_execute(agent, "/quit") is True

    def test_empty_input(self, mock_config):
        from secagent.agent import SecurityAgent
        agent = SecurityAgent(mock_config)
        assert parse_and_execute(agent, "") is False

    def test_unknown_command(self, mock_config):
        from secagent.agent import SecurityAgent
        agent = SecurityAgent(mock_config)
        assert parse_and_execute(agent, "/nonexistent") is False

    def test_help_returns_false(self, mock_config):
        from secagent.agent import SecurityAgent
        agent = SecurityAgent(mock_config)
        assert parse_and_execute(agent, "/help") is False
