"""Edge case tests for the Dockerfile parser."""

from prithvi.dockerfile.parser import parse_dockerfile


class TestParserEdgeCases:
    def test_inline_comment_preserved(self):
        """Inline comments are part of the shell command, not stripped."""
        content = "RUN echo hi # this is a comment\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1
        assert "# this is a comment" in instructions[0].arguments

    def test_continuation_at_eof(self):
        """Backslash at end of file doesn't crash."""
        content = "RUN echo hi \\"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1

    def test_keyword_only_no_args(self):
        """Instruction with keyword but no arguments."""
        content = "ARG\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1
        assert instructions[0].keyword == "ARG"
        assert instructions[0].arguments == ""

    def test_long_continuation_chain(self):
        content = (
            "RUN echo a && \\\n"
            "    echo b && \\\n"
            "    echo c && \\\n"
            "    echo d && \\\n"
            "    echo e\n"
        )
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1
        assert "echo e" in instructions[0].arguments

    def test_tab_indentation(self):
        """Tabs should be handled like spaces."""
        content = "FROM\talpine\n"
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "FROM"
        assert instructions[0].arguments == "alpine"

    def test_multiple_from_instructions(self):
        """Multi-stage builds have multiple FROM."""
        content = (
            "FROM golang:1.21 AS builder\n"
            "RUN go build\n"
            "FROM alpine\n"
            "COPY --from=builder /app /app\n"
        )
        instructions = parse_dockerfile(content)
        froms = [i for i in instructions if i.keyword == "FROM"]
        assert len(froms) == 2

    def test_empty_lines_between_continuations(self):
        """Empty line after continuation should not break."""
        content = "RUN echo hi \\\n\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 1

    def test_comment_between_instructions(self):
        content = "FROM alpine\n# comment\nRUN echo hi\n"
        instructions = parse_dockerfile(content)
        assert len(instructions) == 2

    def test_all_caps_and_lowercase_mixed(self):
        content = "From Alpine\nrun echo hi\nCOPY . .\n"
        instructions = parse_dockerfile(content)
        assert all(
            i.keyword == i.keyword.upper() for i in instructions
        )

    def test_label_instruction(self):
        content = 'LABEL maintainer="test@test.com"\n'
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "LABEL"
        assert (
            'maintainer="test@test.com"'
            in instructions[0].arguments
        )

    def test_shell_instruction(self):
        content = 'SHELL ["/bin/bash", "-c"]\n'
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "SHELL"

    def test_stopsignal_instruction(self):
        content = "STOPSIGNAL SIGTERM\n"
        instructions = parse_dockerfile(content)
        assert instructions[0].keyword == "STOPSIGNAL"
        assert instructions[0].arguments == "SIGTERM"
