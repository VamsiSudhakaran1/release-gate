"""Optional organisation configuration. JSON, never YAML, and never required.

Release-gate works with nothing configured: `release-gate assure run.json`, or
open a session and post records, and a decision comes back. This module is what
an organisation adds *on top of* that — and the word that governs every line
below is **on top of**. Configuration improves assurance; it does not constitute
the product, and nothing here is on the path a first run takes.

Seven things an organisation may state:

    risk appetite          a floor on the assurance level every decision must reach
    domain requirements    extra requirements, in addition to the methodology's
    required verifiers     verifier identities that must appear for a case to pass
    approval roles         who may authorise, by role
    custom capabilities    capability names this organisation's tools expose
    methodology selection  which yardstick applies, by reference
    override rules         what may be waived, by whom, on what terms

**Configuration can only tighten.** It is applied through
`AssuranceMethodology.extend()`, which already enforces that an extension
inherits every requirement and non-overridable condition and may only narrow
what it credits. So an organisation can demand more; it cannot quietly demand
less, and "we extend the regulated methodology" cannot mean "minus the parts we
found inconvenient". An organisation that wants a looser bar writes its own
methodology and owns that fact.

Three things configuration can never do, enforced rather than documented:

* **Lower a structural finding.** `decide()` reads analysis findings directly and
  this never touches them. A case whose own evidence refutes it is not made
  sound by configuration.
* **Waive a non-overridable condition.** `extend()` drops a permissive override
  rule that names an inherited non-overridable condition.
* **Be necessary.** Every field is optional and an empty config is a no-op that
  returns the methodology it was given, unchanged and with the same digest.

No YAML. `governance.yaml` remains supported as an *evidence producer* — its
contents become DECLARED evidence, which is the right epistemic status for a
file in which a team wrote down what it intends — but it is never policy input
here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from release_gate.assurance.level import AssuranceLevel
from release_gate.assurance.methodology import (
    AssuranceMethodology, MethodologyError, OverrideRule, Requirement,
)

ORGANISATION_SCHEMA_VERSION = 1


class OrganisationConfigError(ValueError):
    """Configuration that could not be read, or that tried to loosen the bar."""


def _level(value: Any) -> Optional[AssuranceLevel]:
    if value is None or value == "":
        return None
    if isinstance(value, AssuranceLevel):
        return value
    if isinstance(value, bool):
        raise OrganisationConfigError("risk_appetite must be a level, not a boolean")
    if isinstance(value, int):
        try:
            return AssuranceLevel(value)
        except ValueError as exc:
            raise OrganisationConfigError(
                f"risk_appetite {value} is not a level between 0 and 4") from exc
    name = str(value).strip().upper()
    for level in AssuranceLevel:
        if name in (level.name, f"L{int(level)}", str(int(level))):
            return level
    raise OrganisationConfigError(
        f"risk_appetite {value!r} is not a level; use a name "
        f"({', '.join(l.name for l in AssuranceLevel)}) or 0-4")


@dataclass(frozen=True)
class OrganisationConfig:
    """What an organisation adds to the default experience. All of it optional."""

    #: A floor on `LevelAssessment.required`. Raising the floor makes a decision
    #: demand more; there is deliberately no way to lower one, because an
    #: organisation declaring that irreversible actions are a Level 0 question
    #: would be configuring away the analysis rather than configuring it.
    risk_appetite: Optional[AssuranceLevel] = None
    domain_requirements: Tuple[Requirement, ...] = ()
    required_verifiers: Tuple[str, ...] = ()
    approval_roles: Tuple[str, ...] = ()
    custom_capabilities: Tuple[str, ...] = ()
    #: A methodology reference (`id` or `id@version`), resolved against a
    #: registry by the caller. Selection, never definition.
    methodology: Optional[str] = None
    override_rules: Tuple[OverrideRule, ...] = ()
    organisation_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "risk_appetite", _level(self.risk_appetite))
        for name in ("domain_requirements", "required_verifiers", "approval_roles",
                     "custom_capabilities", "override_rules"):
            object.__setattr__(self, name, tuple(getattr(self, name) or ()))
        for name in ("required_verifiers", "approval_roles", "custom_capabilities"):
            object.__setattr__(self, name, tuple(
                sorted({str(v).strip() for v in getattr(self, name) if str(v).strip()})))
        permissive = [r.requirement_id for r in self.override_rules if r.permitted]
        if permissive and not self.organisation_id:
            raise OrganisationConfigError(
                "an organisation permitting an override must identify itself: a "
                f"waiver of {permissive[0]} that names nobody cannot be reviewed")

    @property
    def is_empty(self) -> bool:
        """True when this configures nothing, and is therefore a no-op."""
        return not (self.risk_appetite is not None or self.domain_requirements
                    or self.required_verifiers or self.approval_roles
                    or self.custom_capabilities or self.methodology
                    or self.override_rules)

    # ── reading ─────────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OrganisationConfig":
        if not isinstance(data, Mapping):
            raise OrganisationConfigError(
                "organisation configuration must be a JSON object")
        # `record_type` and `schema_version` are the self-describing markers
        # `to_dict` emits, so a config written by release-gate reads back in.
        unknown = set(data) - {
            "risk_appetite", "domain_requirements", "required_verifiers",
            "approval_roles", "custom_capabilities", "methodology",
            "override_rules", "organisation_id", "schema_version", "record_type"}
        if unknown:
            # Refused rather than ignored: a misspelled key in a file whose whole
            # job is to tighten a gate would silently not tighten it.
            raise OrganisationConfigError(
                f"unknown configuration key(s): {', '.join(sorted(unknown))}")
        try:
            requirements = tuple(Requirement.from_dict(r)
                                 for r in data.get("domain_requirements", ()))
            overrides = tuple(OverrideRule.from_dict(r)
                              for r in data.get("override_rules", ()))
        except (MethodologyError, KeyError, TypeError) as exc:
            raise OrganisationConfigError(f"unreadable configuration: {exc}") from exc
        return cls(
            risk_appetite=data.get("risk_appetite"),
            domain_requirements=requirements,
            required_verifiers=tuple(data.get("required_verifiers", ())),
            approval_roles=tuple(data.get("approval_roles", ())),
            custom_capabilities=tuple(data.get("custom_capabilities", ())),
            methodology=(data.get("methodology") or None),
            override_rules=overrides,
            organisation_id=str(data.get("organisation_id") or ""))

    @classmethod
    def from_json(cls, text: str) -> "OrganisationConfig":
        try:
            return cls.from_dict(json.loads(text))
        except json.JSONDecodeError as exc:
            raise OrganisationConfigError(
                f"organisation configuration is not valid JSON: {exc}") from exc

    @classmethod
    def from_path(cls, path: str | Path) -> "OrganisationConfig":
        """Read a config file the caller explicitly named.

        Deliberately not a search. Nothing walks the filesystem looking for
        configuration, because a gate that behaves differently depending on which
        directory it ran from is a gate whose verdict cannot be reproduced.
        """
        target = Path(path)
        if target.suffix.lower() in (".yaml", ".yml"):
            raise OrganisationConfigError(
                f"{target.name}: organisation configuration is JSON. YAML is not "
                "policy input on this surface — a governance.yaml is read as "
                "DECLARED evidence, which is what a file of stated intentions is.")
        try:
            return cls.from_json(target.read_text(encoding="utf-8"))
        except OSError as exc:
            raise OrganisationConfigError(f"cannot read {target}: {exc}") from exc

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": "organisation_config",
            "organisation_id": self.organisation_id,
            "risk_appetite": (self.risk_appetite.name
                              if self.risk_appetite is not None else None),
            "domain_requirements": [r.to_dict() for r in self.domain_requirements],
            "required_verifiers": list(self.required_verifiers),
            "approval_roles": list(self.approval_roles),
            "custom_capabilities": list(self.custom_capabilities),
            "methodology": self.methodology,
            "override_rules": [r.to_dict() for r in self.override_rules],
            "schema_version": ORGANISATION_SCHEMA_VERSION,
        }

    # ── applying ────────────────────────────────────────────────────────────

    def level_floor(self, required: AssuranceLevel) -> AssuranceLevel:
        """Raise the required level to the organisation's appetite, never lower it."""
        if self.risk_appetite is None:
            return required
        return max(required, self.risk_appetite)

    def apply_to(self, methodology: Optional[AssuranceMethodology]
                 ) -> Optional[AssuranceMethodology]:
        """Return the methodology this organisation actually requires.

        An empty configuration returns the methodology unchanged — the same
        object, so the digest is identical and a case decided with an empty
        config is byte-identical to one decided with none. That is asserted by a
        test rather than left as an intention: the moment configuration changes
        an unconfigured run, configuration has started constituting the product.

        With nothing to extend, configuration cannot invent a yardstick. A
        methodology is selected or supplied; `domain_requirements` add to one
        that exists. Returning a methodology assembled from config alone would
        let an organisation's extras become the whole standard while looking
        like an addition to it.
        """
        if methodology is None or self.is_empty:
            return methodology
        if not (self.domain_requirements or self.override_rules
                or self.required_verifiers):
            return methodology

        extras = list(self.domain_requirements)
        if self.required_verifiers:
            extras.append(self._verifier_requirement())
        suffix = self.organisation_id or "organisation"
        return methodology.extend(
            methodology_id=f"{methodology.methodology_id}+{suffix}",
            version=methodology.version,
            add_requirements=extras,
            add_override_rules=self.override_rules,
            provenance="organization",
            description=(f"{methodology.description}\n\nExtended by {suffix}: "
                         f"{len(extras)} additional requirement(s)."),
            metadata={"organisation_id": self.organisation_id,
                      "extends": methodology.ref_string,
                      "approval_roles": list(self.approval_roles)})

    def _verifier_requirement(self) -> Requirement:
        """Every named verifier must appear among the case's verification attempts."""
        from release_gate.assurance.methodology import RequirementEffect, VerifierRequired
        return Requirement(
            requirement_id="org.verifiers",
            description=("every verifier this organisation requires has run: "
                         + ", ".join(self.required_verifiers)),
            predicate=VerifierRequired(verifiers=self.required_verifiers),
            effect=RequirementEffect.HOLD,
            remedy=("run the missing verifier and submit its report, or record why "
                    "it does not apply to this case"),
            rationale=("An organisation that names required verifiers is stating "
                       "which checks it does not consider optional. A case that "
                       "skipped one has not met that bar, whatever else it carries."))
