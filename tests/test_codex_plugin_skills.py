from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = PROJECT_ROOT / "plugins" / "fortipam-security-copilot"


def _skill_text(name: str) -> str:
    return (PLUGIN_ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")


def test_plugin_manifest_and_marketplace_package_the_controlled_v4_surface() -> None:
    manifest = json.loads(
        (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    marketplace = json.loads(
        (PROJECT_ROOT / ".agents" / "plugins" / "marketplace.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["name"] == "fortipam-security-copilot"
    assert manifest["version"] == "1.10.0"
    assert manifest["skills"] == "./skills/"
    assert "conditionally advertised bounded actions" in manifest["description"]
    assert "Controlled bounded FortiPAM actions" in manifest["interface"][
        "capabilities"
    ]
    entry = next(
        item for item in marketplace["plugins"] if item["name"] == manifest["name"]
    )
    assert entry["source"] == {
        "source": "local",
        "path": "./plugins/fortipam-security-copilot",
    }
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_USE",
    }


def test_governed_skills_preserve_confirmation_and_controlled_action_boundary() -> None:
    names = (
        "fortipam-administrator-router",
        "fortipam-governed-administration-workflow",
        "fortipam-ztna-access-and-secret-launch-control",
        "fortipam-child-folder-create",
    )
    for name in names:
        text = _skill_text(name)
        assert "Current State" in text
        assert "Proposed Changes" in text
        assert "Expected State" in text
        assert "confirm" in text.lower()
        assert "re-read" in text
        assert "readback" in text

    child = _skill_text("fortipam-child-folder-create")
    assert "folder-create@3.2.0" in child
    assert "execution_state=plan_only" in child
    assert "device_write_executed=false" in child
    assert "execute_confirmed_v4_child_folder" in child
    assert "authorization_ref" in child
    assert "disabled by default" in child
    assert "root Folder" in child

    router = " ".join(_skill_text("fortipam-administrator-router").split())
    assert "FPA-BP-005" in router
    assert "FPA-SK-005" in router
    assert "one parent Plan" in router
    assert "one parent interaction in manual mode" in router
    assert "Do not add human review, per-child, or per-revision chat approval" in router

    workflow = _skill_text("fortipam-governed-administration-workflow")
    normalized = " ".join(workflow.split())
    assert "current discovery" in normalized
    assert "exact registered schema" in normalized
    assert "one explicit requester confirmation" in normalized
    assert "Do not ask for, simulate, or wait on human review" in normalized
    assert "it is not a human approval" in normalized
    assert (
        "Ask the authenticated requester for an explicit affirmative confirmation"
        not in workflow
    )
    assert "plan_ref" in normalized
    assert "scheme_draft_ref" in normalized
    assert "exact executor or required authorization/Gate" in normalized


def test_access_domain_onboarding_skill_uses_one_parent_workflow() -> None:
    text = " ".join(_skill_text("fortipam-access-domain-onboarding").split())

    assert "FPA-BP-004" in text
    assert "FPA-BP-005" in text
    assert "FPA-SK-005" in text
    assert "one parent interaction in manual mode" in text
    assert "Never request a human review or separate chat approval" in text
    assert "execute_v4_secret_onboarding_workflow" in text
    assert "Never call or retry child actions directly" in text
    assert "fortipam-mcp-v4-linux-onboarding-prepare" in text
    assert "do not ask the administrator to handcraft" in text.lower()
    assert "never ask the administrator to calculate or paste" in text
    assert "Passwords, keys, tokens, and credential values never enter" in text


def test_profile_onboarding_skills_route_without_child_approval() -> None:
    router = " ".join(_skill_text("fortipam-administrator-router").split())
    profiles = (
        (
            "fortipam-windows-rdp-onboarding",
            "FPA-BP-006",
            "FPA-SK-006",
            "native-RDP Launcher",
        ),
        (
            "fortipam-web-account-onboarding",
            "FPA-BP-007",
            "FPA-SK-007",
            "Web Account",
        ),
    )
    for name, blueprint, sku, fixed_relation in profiles:
        text = " ".join(_skill_text(name).split())
        assert blueprint in text
        assert sku in text
        assert fixed_relation in text
        assert "Current State / Proposed Changes / Expected State" in text
        assert "one parent interaction in manual mode" in text
        assert "Do not request a human review" in text
        assert "fortipam-mcp-v4-secret-onboarding-prepare" in text
        assert "execute_v4_secret_onboarding_workflow" in text
        assert "retry a consumed dispatch" in text
        assert name in router
        assert blueprint in router
        assert sku in router


def test_approval_workflow_skill_routes_only_the_supported_bp008_profile() -> None:
    text = " ".join(_skill_text("fortipam-approval-workflow-design").split())
    router = " ".join(_skill_text("fortipam-administrator-router").split())

    assert "FPA-BP-008" in text
    assert "FPA-SK-008" in text
    assert "ApprovalAndObserveScheme" in text
    assert "Current / Proposed / Expected" in text
    assert "direct authenticated execution under standing owner-authorized lab authority" in text
    assert "do not add a human-review or conversational-approval gate" in text
    assert "execute_v4_approval_and_observe_workflow" in text
    assert "fortipam-mcp-v4-approval-workflow-prepare" in text
    assert "v4_approval_workflow_mcp_oauth_acceptance.py" in text
    assert "Unless the live server advertises" in text
    assert "Never infer or submit a Secret-request POST body" in text
    assert "fortipam-approval-workflow-design" in router


def test_temporary_access_skill_routes_bp015_without_inferred_execution() -> None:
    text = " ".join(_skill_text("fortipam-temporary-access-management").split())
    router = " ".join(_skill_text("fortipam-administrator-router").split())

    assert "FPA-BP-015" in text
    assert "FPA-SK-015" in text
    assert "IdentityLifecycleScheme" in text
    assert "ApprovalAndObserveScheme" in text
    assert "AccessReviewScheme" in text
    assert "Current State / Proposed Changes / Expected State" in text
    assert "sponsor visibility" in text
    assert "denied-after-expiry or explicit-revoke test" in text
    assert "sponsored-and-temporary-access-plan" in text
    assert "Return `plan_only`" in text
    assert "must not be replayed" in text
    assert "fortipam-temporary-access-management" in router
    assert "do not compose accepted child actions" in router


def test_every_packaged_skill_has_matching_frontmatter_name() -> None:
    for skill_path in sorted((PLUGIN_ROOT / "skills").glob("*/SKILL.md")):
        text = skill_path.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert f"\nname: {skill_path.parent.name}\n" in text
        assert "[TODO:" not in text
