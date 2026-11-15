"""Value-minimized contract types for one Target Classification Tag assignment."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClassificationTagAssignInspection:
    """Private preflight evidence for the exact Target and Tag pair."""

    target_exists: bool
    classification_tag_exists: bool
    current_class_is_other: bool
    target_non_class_state_digest: str
    classification_tag_state_digest: str
    state_digest: str
    current_class_matches_tag: bool = False


@dataclass(frozen=True, slots=True)
class ClassificationTagAssignReadback:
    """Categorical post-write evidence without Target or Tag payloads."""

    target_exists: bool
    classification_tag_exists: bool
    target_class_matches: bool
    target_non_class_state_preserved: bool
    classification_tag_state_preserved: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.target_exists,
                self.classification_tag_exists,
                self.target_class_matches,
                self.target_non_class_state_preserved,
                self.classification_tag_state_preserved,
            )
        )


__all__ = [
    "ClassificationTagAssignInspection",
    "ClassificationTagAssignReadback",
]
