from harness_aibom.paths import is_symlink_outside_home, relative_to_or_none


def test_relative_to_or_none_returns_relative_path_when_inside_base(tmp_path):
    inside = tmp_path / "a" / "b.txt"
    assert relative_to_or_none(inside, tmp_path) == "a/b.txt"


def test_relative_to_or_none_returns_none_when_outside_base(tmp_path):
    outside = tmp_path.parent / "elsewhere" / "b.txt"
    assert relative_to_or_none(outside, tmp_path) is None


def test_plain_file_is_never_flagged(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("x")
    assert is_symlink_outside_home(target, tmp_path) is False


def test_symlink_pointing_inside_home_is_not_flagged(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    assert is_symlink_outside_home(link, tmp_path) is False


def test_symlink_escaping_home_is_flagged(tmp_path):
    outside_dir = tmp_path.parent / "outside"
    outside_dir.mkdir(exist_ok=True)
    target = outside_dir / "payload.txt"
    target.write_text("evil")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert is_symlink_outside_home(link, tmp_path) is True


def test_home_resolution_mismatch_does_not_cause_a_false_positive(tmp_path):
    # Regression guard: pytest's tmp_path is not always fully resolved on
    # every platform (macOS's /tmp -> /private/tmp is a real example) --
    # a naive implementation comparing a resolved file against an
    # unresolved `home` would misreport an in-tree symlink as escaping.
    real = tmp_path / "real.txt"
    real.write_text("x")
    link = tmp_path / "link.txt"
    link.symlink_to(real)

    unresolved_home = tmp_path  # deliberately not pre-resolved by the caller
    assert is_symlink_outside_home(link, unresolved_home) is False
