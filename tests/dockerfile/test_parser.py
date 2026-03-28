"""Tests for the Dockerfile parser."""

from prithvi.dockerfile.parser import parse_dockerfile


class TestParser:
    def test_basic_instructions(self):
        content = "FROM python:3.12\nRUN echo hello\nCMD ['python']\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 3
        assert instructions[0].keyword == "FROM"
        assert instructions[0].arguments == "python:3.12"
        assert instructions[0].line_number == 1

    def test_comments_ignored(self):
        content = "# This is a comment\nFROM alpine\n# Another comment\nRUN echo hi\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 2

    def test_blank_lines_ignored(self):
        content = "FROM alpine\n\n\nRUN echo hi\n\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 2

    def test_continuation_lines(self):
        content = "RUN apt-get update && \\\n    apt-get install -y curl && \\\n    rm -rf /var/lib/apt/lists/*\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1
        assert "apt-get update" in instructions[0].arguments
        assert "rm -rf" in instructions[0].arguments
        assert instructions[0].line_number == 1

    def test_case_insensitive_keywords(self):
        content = "from alpine\nrun echo hi\n"
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "FROM"
        assert instructions[1].keyword == "RUN"

    def test_empty_dockerfile(self):
        instructions = parse_dockerfile("")
        assert instructions == []

    def test_expose_multiple_ports(self):
        content = "EXPOSE 80 443 8080\n"
        instructions = parse_dockerfile(content)
        assert instructions[0].arguments == "80 443 8080"

    def test_env_with_equals(self):
        content = "ENV MY_VAR=hello\n"
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "ENV"
        assert instructions[0].arguments == "MY_VAR=hello"
