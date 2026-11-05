"""Here-documents in the shared reader (``read_commands(heredocs=True)``) and the rm
floor shapes that need them: a heredoc fed to a shell, a command after a heredoc, a
substitution in an unquoted body, and a decoded newline in ``$'...'`` given to ``-c``.

The wipe is spelled so the regex rows miss it and only the floor can refuse it.
"""

from __future__ import annotations

import pytest

from kiro_crew.security import rm_floor
from kiro_crew.security.deny_gate import is_denied
from kiro_crew.security.shell_commands import read_commands

RM = "r" + "m"
ROOT = f"{RM} -r --force /"
HOME = f"{RM} --recursive -f ~"


def _docs(text: str) -> "list[tuple[str, list[tuple[str, bool]]]]":
    return [
        (" ".join(word.raw for word in cmd.argv), [(d.body, d.quoted) for d in cmd.heredocs])
        for cmd in read_commands(text, heredocs=True)
    ]


class TestReader:
    def test_default_read_still_stops_at_a_heredoc(self):
        cmds = read_commands("cat <<EOF\nbody\nEOF\nnext")
        assert [c.separator for c in cmds] == ["<<"]
        assert all(c.heredocs == () for c in cmds)

    def test_bodies_go_to_their_command_and_the_read_goes_on(self):
        assert _docs("cat <<EOF | bash\nA\nB\nEOF\necho after") == [
            ("cat", [("A\nB\n", False)]),
            ("bash", []),
            ("echo after", []),
        ]

    def test_quoted_tags_strip_tabs_and_two_bodies_on_one_line(self):
        assert _docs("cat <<A <<\\B\n1\nA\n2\nB\nz")[0] == ("cat", [("1\n", False), ("2\n", True)])
        assert _docs("bash <<-EOF\n\tA\n\tEOF\ndone") == [
            ("bash", [("\tA\n", False)]),
            ("done", []),
        ]
        assert _docs("cat <<'EOF'\n$(x)\nEOF\nnext") == [
            ("cat", [("$(x)\n", True)]),
            ("next", []),
        ]

    def test_offsets_index_the_raw_text(self):
        text = "x; cat <<EOF\nhello\nEOF\n"
        doc = read_commands(text, heredocs=True)[1].heredocs[0]
        assert text[doc.start : doc.end] == doc.body == "hello\n"

    def test_an_unquoted_body_reads_each_substitution_once_with_literal_quotes(self):
        argvs = [a for a, _ in _docs("cat <<EOF\nit's $(id; who) and `date`\nEOF")]
        assert argvs[:4] == ["cat", "id", "who", "date"]

    def test_an_unclosed_body_runs_to_the_end(self):
        assert _docs("bash <<EOF\nA") == [("bash", [("A", False)]), ("", [])]


@pytest.mark.parametrize(
    "cmd",
    [
        pytest.param(f"bash <<EOF\n{ROOT}\nEOF", id="bash-heredoc"),
        pytest.param(f"bash <<'EOF'\n{ROOT}\nEOF", id="bash-quoted-heredoc"),
        pytest.param(f"bash <<-EOF\n\t{ROOT}\n\tEOF", id="bash-tab-heredoc"),
        pytest.param(f"bash -s <<EOF\n{HOME}\nEOF", id="bash-s-heredoc"),
        pytest.param(f"cat <<EOF | bash\n{ROOT}\nEOF", id="cat-heredoc-into-bash"),
        pytest.param(f"cat <<EOF\n$({ROOT})\nEOF", id="substitution-in-body"),
        pytest.param(f"cat <<EOF\n$(bash -c '{ROOT}')\nEOF", id="nested-shell-in-body"),
        pytest.param(f"cat <<EOF\nx\nEOF\n{ROOT}", id="command-after-heredoc"),
        pytest.param(f"bash -c $'echo\\n{ROOT}'", id="ansi-c-newline"),
        pytest.param(f"sudo -u root bash <<EOF\n{ROOT}\nEOF", id="wrapper-with-option-value"),
        pytest.param(f"bash -o posix -s <<EOF\n{ROOT}\nEOF", id="shell-option-with-value"),
        pytest.param(f"bash -euo pipefail <<'EOF'\n{ROOT}\nEOF", id="option-cluster-with-value"),
        pytest.param(f"cat <<EOF | chroot / sh\n{ROOT}\nEOF", id="piped-into-a-chroot-shell"),
        pytest.param(f"busybox sh <<EOF\n{ROOT}\nEOF", id="busybox-shell"),
        pytest.param(
            f"cat <<EOF\n$(cat <<X\nyyyyyyyyyyyy\nX\n)\nEOF\nbash -c '{ROOT}'",
            id="command-after-nested-heredoc",
        ),
        # already refused before here-documents were read: kept so they stay refused
        pytest.param(f"bash -c -e '{ROOT}'", id="option-after-c"),
        pytest.param(f"bash -c -o posix '{ROOT}'", id="option-with-value-after-c"),
        pytest.param(f"bash -ce +c '{ROOT}'", id="option-cluster-after-c"),
        pytest.param(f"echo hi # x\\\nbash -c '{ROOT}'", id="comment-ending-in-backslash"),
        pytest.param(f"echo hi &# \\\nbash -c '{ROOT}'", id="background-comment-backslash"),
    ],
)
def test_the_floor_refuses(cmd):
    assert rm_floor._rm_wipe_targets_nested(cmd)
    assert is_denied(cmd) is not None


@pytest.mark.parametrize(
    "cmd",
    [
        pytest.param(f"cat <<EOF\nbash -c '{ROOT}'\nEOF", id="body-given-to-cat"),
        pytest.param(f"cat > s.sh <<'EOF'\nbash -c '{ROOT}'\nEOF", id="script-written-to-a-file"),
        pytest.param(f"git commit -F - <<'EOF'\nnote: {ROOT} is refused\nEOF", id="commit-message"),
        pytest.param(f"cat <<'EOF'\n$({ROOT})\nEOF", id="quoted-body-substitution"),
        pytest.param(f"echo $'{ROOT}'", id="ansi-c-echo"),
        pytest.param(f"bash -c cat <<'EOF'\n{ROOT}\nEOF", id="shell-c-runs-cat"),
        pytest.param(f"tee bash <<'EOF'\n{ROOT}\nEOF", id="shell-name-as-a-file"),
        pytest.param(f"bash script.sh <<'EOF'\n{ROOT}\nEOF", id="shell-runs-a-script-file"),
    ],
)
def test_the_floor_allows_body_data(cmd):
    assert rm_floor._rm_wipe_targets_nested(cmd) == set()
    assert is_denied(cmd) is None
