# Password Lifecycle Compatibility Routes

## Evidence order

1. Password Changer definition inventory.
2. Product and target version band.
3. Target/template/changer assignment and procedure compatibility.
4. Approved transport path.
5. Target password policy and account state.
6. Changer, verification, reconciliation, and dependency result.

Use a result from a later layer only after the prior layer is established. This
avoids interpreting a known procedure mismatch as an authentication outage.

## FortiOS 7.6.3+ gate

The [FortiOS 7.6.3+ password-changer Community technical tip](https://community.fortinet.com/fortipam-52/technical-tip-fortipam-password-changer-for-fortios-v7-6-3-and-above-228919)
identifies a target-side administrator prompt change. Treat it as a precise
compatibility lead, not a universal FortiOS rule. Confirm the exact target and
FortiPAM build against the current [FortiPAM password-changer documentation](https://docs.fortinet.com/document/fortipam/latest/administration-guide/485608/password-changers)
before recommending an operational procedure.

`get_password_changer_configuration_posture_summary` may establish only that a
definition label matches a documented FortiOS 7.6.3+ label. The matching entry
could be custom, renamed, or associated with a modified procedure, so the
signal is not proof of a vendor default or compatibility. The tool does not
inspect the definition body, target, template, secret assignment, job,
verification, reconciliation, or dependency state. Report `not_observed` as an
evidence gap, never as incompatibility.

The [FortiPAM 1.9.1 Release Notes](https://docs.fortinet.com/product/fortipam/1.9)
remain the authority for FortiPAM release-specific fixes. No Community article,
API catalog entry, or MCP scenario authorizes a real password action.
