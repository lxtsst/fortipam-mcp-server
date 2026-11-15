import pytest

import scripts.ci_verify_release as ci_verify_release
from scripts.ci_verify_release import summarize_pytest


def test_ci_summary_omits_parameters_and_raw_failure_output() -> None:
    summary = summarize_pytest(
        "FAILED tests/test_flow.py::test_boundary[SYNTHETIC_PRIVATE_PARAMETER]\n"
        "E AssertionError: SYNTHETIC_RAW_RESPONSE\n"
        "1 failed, 12 passed, 2 skipped in 3.25s\n"
    )
    assert summary == {
        "counts": {"failed": 1, "passed": 12, "skipped": 2},
        "failed_tests": ["tests/test_flow.py::test_boundary"],
    }
    assert "SYNTHETIC_PRIVATE_PARAMETER" not in str(summary)
    assert "SYNTHETIC_RAW_RESPONSE" not in str(summary)


def test_ci_summary_rejects_non_test_paths_and_deduplicates_parameter_cases() -> None:
    summary = summarize_pytest(
        "ERROR /operator/private/state\n"
        "FAILED tests/test_flow.py::TestFlow::test_boundary[first]\n"
        "FAILED tests/test_flow.py::TestFlow::test_boundary[second]\n"
        "2 failed, 4 passed, 1 error in 2.10s\n"
    )
    assert summary == {
        "counts": {"failed": 2, "passed": 4, "error": 1},
        "failed_tests": ["tests/test_flow.py::TestFlow::test_boundary"],
    }


def test_native_scope_refuses_a_non_macos_runner(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(ci_verify_release.sys, "platform", "linux")
    monkeypatch.setattr(ci_verify_release.sys, "argv", [
        "ci_verify_release", "--scope", "native-macos", "--log-directory", str(tmp_path),
    ])
    with pytest.raises(SystemExit) as error:
        ci_verify_release.main()
    assert error.value.code == 2


def test_failure_phase_exposes_only_known_check_names() -> None:
    assert ci_verify_release.failure_phase(
        "Release verification check 'mypy' failed with exit code 1.\nSYNTHETIC_RAW_OUTPUT"
    ) == "mypy"
    assert ci_verify_release.failure_phase(
        "Release verification check 'synthetic_private_value' failed with exit code 1."
    ) is None


def test_failure_diagnostics_excludes_exception_values_and_private_paths() -> None:
    result = ci_verify_release.failure_diagnostics(
        "tests/test_flow.py:42: AssertionError\n"
        "E BrokenPipeError: SYNTHETIC_PRIVATE_VALUE\n"
        "/operator/private/state:19: Permission denied\n"
    )
    assert result == {
        "failure_signals": ["Permission denied", "BrokenPipeError", "AssertionError"],
        "failure_locations": ["tests/test_flow.py:42"],
    }
    assert "SYNTHETIC_PRIVATE_VALUE" not in str(result)
    assert "/operator/private" not in str(result)


def test_ci_shards_partition_all_cases_without_overlap() -> None:
    cases = [f"tests/test_flow.py::test_boundary[{index}]" for index in range(1000)]
    shards = [{case for case in cases if ci_verify_release.shard_for_test(case, 4) == shard}
              for shard in range(1, 5)]
    assert set.union(*shards) == set(cases)
    assert sum(map(len, shards)) == len(cases)
    assert all(shards)
    assert all(ci_verify_release.shard_for_test(case, 1) == 1 for case in cases)


def test_ci_worker_exit_diagnostic_accepts_only_the_fixed_exit_assertion() -> None:
    result = ci_verify_release.failure_diagnostics(
        'assert handles[0]._process.returncode == expected_exit[fault]\nE assert -9 == 16\n'
    )
    assert result['worker_exit'] == {'actual': -9, 'expected': 16}
    assert 'worker_exit' not in ci_verify_release.failure_diagnostics('E assert 12345 == 16')
