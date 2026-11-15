"""Closed native metadata frames with no source or execution authority."""
from dataclasses import replace

import pytest

from fortipam_mcp.windows_service_credential_associations import (
    ServiceAssociationDependency, WindowsServiceAssociationError, project_service_association_columns,
)


def frame(*, associated=True, dependency=True):
    rows = [b'config secret database', b'    edit 11', b'        set name "Synthetic One"',
        b'        set target "Existing Windows"', b'        set target-privilege-account disable']
    if associated:
        rows.append(b'        set associated-secret 12')
    rows += [b'        config field', b'            edit 1', b'            next', b'        end']
    if dependency:
        rows += [b'        config dependency', b'            edit 1', b'                set target "Other Target"',
            b'                set updater "Synthetic Updater"', b'            next', b'        end']
    return tuple(rows + [b'    next', b'    edit 12', b'        set name "Synthetic Two"',
        b"        set target ''", b'        set associated-secret 0', b'        set target-privilege-account disable',
        b'        config dependency', b'        end', b'    next', b'end'])


def test_grouped_frames_preserve_exact_object_relations_and_omitted_values_remain_unknown():
    rows = project_service_association_columns(frame())
    assert (rows[0].identifier, rows[0].associated_secret_id, rows[0].privileged) == (11, 12, False)
    assert rows[0].dependencies == (ServiceAssociationDependency(1, 'Other Target', 'Synthetic Updater'),)
    assert rows[1].target == '' and rows[1].dependencies == ()
    omitted = project_service_association_columns(frame(associated=False, dependency=False))[0]
    assert omitted.associated_secret_id is None and omitted.dependencies is None
    assert 'Synthetic' not in repr(rows[0]) and not hasattr(rows[0], 'execute')
    assert replace(rows[0], target='different') != rows[0]


@pytest.mark.parametrize('before,after', [
    (b'    edit 11', b'    edit 0'),
    (b'    edit 12', b'    edit 11'),
    (b'        set name "Synthetic Two"', b'        set name "Synthetic One"'),
    (b'        set target-privilege-account disable', b'        set target-privilege-account unexpected'),
    (b'        set associated-secret 12', b'        set associated-secret -1'),
    (b'            edit 1', b'            edit 65'),
    (b'                set target "Other Target"', b'                set target ""'),
    (b'                set updater "Synthetic Updater"', b'                set updater ""'),
    (b'                set updater "Synthetic Updater"', b'                set password "PRIVATE_SENTINEL"'),
    (b'        set name "Synthetic One"', b'        set name "escaped\\name"'),
])
def test_malformed_or_unselected_content_never_produces_partial_relations(before, after):
    lines = tuple(after if line == before else line for line in frame())
    with pytest.raises(WindowsServiceAssociationError) as error:
        project_service_association_columns(lines)
    assert 'PRIVATE_SENTINEL' not in str(error.value)


@pytest.mark.parametrize('line', [b'    next', b'            next', b'        end', b'end',
    b'                set updater "Synthetic Updater"', b'        set name "Synthetic One"'])
def test_missing_structure_and_required_dependency_members_refuse(line):
    rows = list(frame()); rows.remove(line)
    with pytest.raises(WindowsServiceAssociationError):
        project_service_association_columns(tuple(rows))


def test_duplicate_fields_or_misplaced_nested_values_refuse():
    for extra in (b'        set target "second"', b'                set updater "outside"'):
        rows = list(frame()); rows.insert(4, extra)
        with pytest.raises(WindowsServiceAssociationError):
            project_service_association_columns(tuple(rows))


def test_row_and_input_bounds_refuse():
    rows = [b'config secret database']
    for index in range(1, 130):
        rows += [f'    edit {index}'.encode(), f'        set name "Synthetic {index}"'.encode(),
            b'        set target ""', b'    next']
    with pytest.raises(WindowsServiceAssociationError):
        project_service_association_columns(tuple(rows + [b'end']))
    with pytest.raises(WindowsServiceAssociationError):
        project_service_association_columns(tuple([b'config secret database', b'x' * 262145, b'end']))
