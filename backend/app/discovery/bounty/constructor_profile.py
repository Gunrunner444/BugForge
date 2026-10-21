"""Trusted constructor profiles.

A profile is a typed, campaign-supplied configuration for one constructor argument.
It can name roles, integers, booleans, bounded arrays, nested structs, and a fixed
set of local fixtures. It cannot carry Solidity source. Values are checked against
the struct declarations in the bound source closure, including integer width.
A profile binds to those file hashes, so a changed dependency cannot reuse it.
With no profile, the harness still refuses to invent a struct.

The schema parser resolves elementary types, arrays, and structs declared in the
bound files. It does not resolve enums or user-defined value types, and it says
so with ``profile_type_unsupported`` instead of accepting a value that merely
compiles.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.discovery.bounty.vfcs import (
    ATTACKER,
    SequenceIdentity,
    Vfcs,
    VfcsCall,
    sequence_id_of,
    stamp_source_identity,
)
from app.parsing.solidity_research import (
    ResearchModel,
    SemanticCandidate,
    build_research_model,
    normalize_type,
    split_top,
)

_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,4}(?:\[\])?$")
_UINT = re.compile(r"^[0-9]{1,78}$")
_PATH = re.compile(r"^[A-Za-z0-9_./+-]{1,180}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_FIELDS = 32
MAX_DEPTH = 4
MAX_ARRAY = 24
MAX_FIXTURES = 8
MAX_BOUND_FILES = 24

# Harness addresses. The attacker is the existing probe actor and cannot be a
# privileged role. These are local labels, not live accounts.
ROLE_EXPRESSION = {
    "governor": "address(0xC0FE)",
    "pause_guardian": "address(0x6A2D)",
    "attacker": "address(0xA11CE)",
    "victim": "address(0xB0B)",
}
PRIVILEGED_ROLES = frozenset({"governor", "pause_guardian"})
_KINDS = frozenset({"uint", "bool", "role", "fixture", "struct", "array", "bytes32"})
_FIXTURE_KINDS = frozenset(
    {
        "decimals_token",
        "decimals_feed",
        "asset_list_factory",
        "factory_holder",
        "source_contract",
        # The harness's own BugForgeFixtureToken. No contract is deployed for it.
        "harness_token",
    }
)
_ADDRESS_FIXTURES = _FIXTURE_KINDS
_PROPERTY_TEMPLATES = frozenset(
    {"unauthorized-call", "configured-asset", "custody", "initialization-asset"}
)
_ADDRESS_WORD = re.compile(r"0x[0-9a-fA-F]{40}")
HARNESS_TOKEN_DECIMALS = 18  # BugForgeFixtureToken.decimals()
HARNESS_TOKEN_VARIABLE = "bfToken"

COMET_CONTRACT = "CometWithExtendedAssetList"
COMET_FILE = "contracts/CometWithExtendedAssetList.sol"
COMET_CONFIGURATION = "contracts/CometConfiguration.sol"
COMET_CORE = "contracts/CometCore.sol"
COMET_PIN = "f766f51583c23acc33b2a7824654ef2029a96804"
PAUSE_SIGNATURE = "pause(bool,bool,bool,bool,bool)"
PAUSE_STATEMENT = (
    "an account that is neither the configured governor nor the configured "
    "pause guardian must not change the protocol pause flags"
)


class ProfileError(ValueError):
    """A profile is malformed or does not bind to the source it names."""

    def __init__(self, code: str, reason: str) -> None:
        self.code = code
        self.reason = reason
        super().__init__(f"{code}: {reason}")


@dataclass(frozen=True)
class ProfileValue:
    kind: str
    value: str = ""
    type_name: str = ""
    fields: tuple[tuple[str, ProfileValue], ...] = ()
    items: tuple[ProfileValue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "struct":
            return {
                "kind": "struct",
                "type_name": self.type_name,
                "fields": [{"name": name, "value": child.to_dict()} for name, child in self.fields],
            }
        if self.kind == "array":
            return {
                "kind": "array",
                "type_name": self.type_name,
                "items": [item.to_dict() for item in self.items],
            }
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class ProfileFixture:
    fixture_id: str
    kind: str
    decimals: int | None = None
    depends_on: str = ""
    contract: str = ""
    arguments: tuple[ProfileValue, ...] = ()
    # Runtime code is copied to this address after deployment. It must be a literal
    # already present in the bound source; the profile does not choose an address.
    place_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {"fixture_id": self.fixture_id, "kind": self.kind}
        if self.decimals is not None:
            body["decimals"] = self.decimals
        if self.depends_on:
            body["depends_on"] = self.depends_on
        if self.contract:
            body["contract"] = self.contract
        if self.arguments:
            body["arguments"] = [item.to_dict() for item in self.arguments]
        if self.place_at:
            body["place_at"] = self.place_at
        return body


@dataclass(frozen=True)
class ConstructorProfile:
    """One approved constructor argument for one source snapshot."""

    profile_id: str
    contract: str
    source_file: str
    source_sha256: str
    parameter: str
    model_type: str
    solidity_type: str
    struct_file: str
    struct_name: str
    value: ProfileValue
    fixtures: tuple[ProfileFixture, ...]
    imports: tuple[str, ...]
    bound_files: tuple[tuple[str, str], ...]
    assumptions: tuple[str, ...]
    property_function: str
    property_statement: str
    property_getter: str
    source_commit: str = ""
    property_template: str = "unauthorized-call"
    probe_argument: str = ""
    observed_fixture: str = ""
    # ABI signature of a one-address setup call, when the token is not a constructor argument.
    initialization_function: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "contract": self.contract,
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "parameter": self.parameter,
            "model_type": self.model_type,
            "solidity_type": self.solidity_type,
            "struct_file": self.struct_file,
            "struct_name": self.struct_name,
            "value": self.value.to_dict(),
            "fixtures": [item.to_dict() for item in self.fixtures],
            "imports": list(self.imports),
            "bound_files": [{"path": path, "sha256": digest} for path, digest in self.bound_files],
            "assumptions": list(self.assumptions),
            "property_function": self.property_function,
            "property_statement": self.property_statement,
            "property_getter": self.property_getter,
            "source_commit": self.source_commit,
            "property_template": self.property_template,
            "probe_argument": self.probe_argument,
            "observed_fixture": self.observed_fixture,
            "initialization_function": self.initialization_function,
        }

    def public_dict(self) -> dict[str, Any]:
        """Provenance safe to persist. Local fixtures are not a deployment."""
        return {
            "profile_id": self.profile_id,
            "validation": "accepted",
            "contract": self.contract,
            "source_file": self.source_file,
            "source_sha256": self.source_sha256,
            "parameter": self.parameter,
            "model_type": self.model_type,
            "solidity_type": self.solidity_type,
            "bound_files": [{"path": path, "sha256": digest} for path, digest in self.bound_files],
            "fixtures": [item.to_dict() for item in self.fixtures],
            "assumptions": list(self.assumptions),
            "property_function": self.property_function,
            "property_statement": self.property_statement,
            "property_getter": self.property_getter,
            "source_commit": self.source_commit,
            "property_template": self.property_template,
            "observed_fixture": self.observed_fixture,
            "initialization_function": self.initialization_function,
            "configuration": self.value.to_dict(),
            "local_environment": True,
            "establishes_deployed_state": False,
        }


@dataclass(frozen=True)
class PreparedProfile:
    expression: str
    deploy_lines: tuple[str, ...]
    contracts: str
    import_paths: tuple[str, ...]
    provenance: dict[str, Any]
    # Fixture id of the harness token and the struct fields it is assigned to.
    harness_token: str = ""
    harness_token_fields: tuple[str, ...] = ()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_profile(raw: Mapping[str, Any] | None) -> ConstructorProfile:
    """Validate a profile document. Rejects anything that is not a typed value."""
    if not isinstance(raw, Mapping):
        raise ProfileError("profile_malformed", "a constructor profile must be an object")
    allowed = {
        "profile_id",
        "contract",
        "source_file",
        "source_sha256",
        "parameter",
        "model_type",
        "solidity_type",
        "struct_file",
        "struct_name",
        "value",
        "fixtures",
        "imports",
        "bound_files",
        "assumptions",
        "property_function",
        "property_statement",
        "property_getter",
        "source_commit",
        "property_template",
        "probe_argument",
        "observed_fixture",
        "initialization_function",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ProfileError("profile_malformed", f"unknown profile fields: {', '.join(unknown)}")
    profile_id = _required_text(raw, "profile_id")
    if not _PROFILE_ID.fullmatch(profile_id):
        raise ProfileError("profile_malformed", "profile_id is not a stable identifier")
    contract = _ident(raw, "contract")
    parameter = _ident(raw, "parameter")
    model_type = _type_name(_required_text(raw, "model_type"), "model_type")
    solidity_type = _type_name(_required_text(raw, "solidity_type"), "solidity_type")
    if solidity_type.endswith("[]"):
        raise ProfileError("profile_malformed", "the constructor type is not an array")
    struct_name = _ident(raw, "struct_name")
    if solidity_type.split(".")[-1] != model_type.split(".")[-1]:
        raise ProfileError("profile_type_mismatch", "solidity_type does not name the model type")
    if struct_name != model_type.split(".")[-1]:
        raise ProfileError("profile_type_mismatch", "struct_name does not match the model type")
    source_file = _path(raw, "source_file")
    struct_file = _path(raw, "struct_file")
    source_sha256 = _sha(raw, "source_sha256")
    fixtures = _fixtures(raw.get("fixtures", []))
    fixture_ids = {item.fixture_id for item in fixtures}
    value = _value(raw.get("value"), fixture_ids, depth=0)
    initialization_function = str(raw.get("initialization_function", "") or "")
    if initialization_function and not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*\(address\)", initialization_function
    ):
        raise ProfileError(
            "profile_malformed", "initialization_function must be a one-address ABI signature"
        )
    address_binding = model_type == "address" and solidity_type == "address"
    if address_binding:
        if struct_name != "address":
            raise ProfileError("profile_type_mismatch", "an address binding names address")
        if value.kind != "fixture":
            raise ProfileError("profile_malformed", "an address profile assigns one fixture")
    elif value.kind != "struct":
        raise ProfileError("profile_malformed", "the profile value must be a struct")
    elif value.type_name != solidity_type:
        raise ProfileError("profile_type_mismatch", "the struct type does not match solidity_type")
    _reject_privileged_attacker(value)
    imports = _paths(raw.get("imports", []), "imports")
    bound = _bound_files(raw.get("bound_files", []))
    if not any(path == source_file and digest == source_sha256 for path, digest in bound):
        raise ProfileError(
            "profile_source_mismatch", "bound_files does not include the target file hash"
        )
    assumptions = _statements(raw.get("assumptions", []))
    property_function = _required_text(raw, "property_function")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\((?:[A-Za-z0-9_,\[\]]*)\)", property_function):
        raise ProfileError("profile_malformed", "property_function is not a signature")
    property_statement = _required_text(raw, "property_statement")
    if len(property_statement) > 400 or any(ch in property_statement for ch in "{};`"):
        raise ProfileError("profile_malformed", "property_statement is not plain text")
    template = str(raw.get("property_template", "unauthorized-call") or "unauthorized-call")
    if template not in _PROPERTY_TEMPLATES:
        raise ProfileError("profile_malformed", "property_template is not supported")
    if address_binding and template != "initialization-asset":
        raise ProfileError(
            "profile_malformed", "an address binding uses the initialization-asset template"
        )
    if template == "initialization-asset" and not address_binding:
        raise ProfileError("profile_malformed", "initialization-asset binds an address")
    if initialization_function and template != "initialization-asset":
        raise ProfileError(
            "profile_malformed",
            "initialization_function requires the initialization-asset template",
        )
    getter_raw = raw.get("property_getter", "")
    if not isinstance(getter_raw, str):
        raise ProfileError("profile_malformed", "property_getter is not text")
    property_getter = getter_raw.strip()
    if template in {"unauthorized-call", "initialization-asset"}:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\(\)", property_getter):
            raise ProfileError(
                "profile_malformed", "property_getter is not a no-argument signature"
            )
    elif property_getter and not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*\((?:[A-Za-z0-9_,\[\]]*)\)", property_getter
    ):
        raise ProfileError("profile_malformed", "property_getter is not a signature")
    source_commit = str(raw.get("source_commit", "") or "")
    if source_commit and not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ProfileError("profile_malformed", "source_commit is not a 40-character revision")
    probe_argument = str(raw.get("probe_argument", "") or "")
    if probe_argument and not _UINT.fullmatch(probe_argument):
        raise ProfileError("profile_malformed", "probe_argument is not a decimal integer")
    observed_fixture = str(raw.get("observed_fixture", "") or "")
    if observed_fixture and not _IDENT.fullmatch(observed_fixture):
        raise ProfileError("profile_malformed", "observed_fixture is not an identifier")
    if template == "configured-asset" and (not observed_fixture or not probe_argument):
        raise ProfileError(
            "profile_malformed", "a configured-asset profile needs a fixture and a probe argument"
        )
    if template == "custody":
        observed = next((item for item in fixtures if item.fixture_id == observed_fixture), None)
        if observed is None or observed.kind != "harness_token":
            raise ProfileError(
                "profile_malformed", "a custody profile observes the harness token fixture"
            )
        if probe_argument:
            raise ProfileError("profile_malformed", "a custody profile takes no probe argument")
        if not fixture_fields(value, observed_fixture):
            raise ProfileError(
                "profile_custody_unbound", "the harness token is not assigned to any field"
            )
    return ConstructorProfile(
        profile_id=profile_id,
        contract=contract,
        source_file=source_file,
        source_sha256=source_sha256,
        parameter=parameter,
        model_type=model_type,
        solidity_type=solidity_type,
        struct_file=struct_file,
        struct_name=struct_name,
        value=value,
        fixtures=fixtures,
        imports=tuple(imports),
        bound_files=bound,
        assumptions=tuple(assumptions),
        property_function=property_function,
        property_statement=property_statement,
        property_getter=property_getter,
        source_commit=source_commit,
        property_template=template,
        probe_argument=probe_argument,
        observed_fixture=observed_fixture,
        initialization_function=initialization_function,
    )


_STRUCT_FIELD = re.compile(
    r"^\s*((?:uint[0-9]*|int[0-9]*|bool|address|bytes[0-9]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?:\[[0-9]*\])?)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*$"
)


def _struct_at(text: str, struct_name: str, open_end: int) -> tuple[tuple[str, str], ...]:
    depth = 1
    index = open_end
    while index < len(text) and depth:
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise ProfileError("profile_type_unparsed", f"{struct_name} is not closed")
    body = _strip_comments(text[open_end : index - 1])
    fields: list[tuple[str, str]] = []
    for piece in body.split(";"):
        if not piece.strip():
            continue
        found = _STRUCT_FIELD.fullmatch(piece)
        if found is None:
            raise ProfileError(
                "profile_type_unparsed",
                f"{struct_name} contains a declaration the schema parser cannot read",
            )
        fields.append((found.group(1), found.group(2)))
    if not fields or len(fields) > MAX_FIELDS:
        raise ProfileError("profile_type_unparsed", f"{struct_name} has no usable fields")
    if len({name for _type_name, name in fields}) != len(fields):
        raise ProfileError("profile_type_unparsed", f"{struct_name} repeats a field name")
    return tuple(fields)


def iter_struct_fields(text: str, struct_name: str) -> tuple[tuple[tuple[str, str], ...], ...]:
    """Every ``struct Name`` in ``text``. An absent name is an empty tuple."""
    if not _IDENT.fullmatch(struct_name):
        return ()
    found: list[tuple[tuple[str, str], ...]] = []
    pattern = re.compile(rf"\bstruct\s+{re.escape(struct_name)}\s*\{{")
    for match in pattern.finditer(text):
        found.append(_struct_at(text, struct_name, match.end()))
    return tuple(found)


def parse_struct_fields(text: str, struct_name: str) -> tuple[tuple[str, str], ...] | None:
    """``(type, name)`` fields, or None when ``struct Name`` is not in ``text``.

    A struct that is present but contains a declaration this parser cannot read
    raises ``profile_type_unparsed``. Two different layouts of the same name in
    one file raise ``profile_type_ambiguous``.
    """
    found = iter_struct_fields(text, struct_name)
    if not found:
        return None
    if any(item != found[0] for item in found):
        raise ProfileError(
            "profile_type_ambiguous",
            f"{struct_name} is declared differently more than once",
        )
    return found[0]


def struct_field_names(text: str, struct_name: str) -> tuple[str, ...] | None:
    """Field names of ``struct Name { ... }``, or None when that struct is absent."""
    try:
        fields = parse_struct_fields(text, struct_name)
    except ProfileError:
        return None
    if fields is None:
        return None
    return tuple(name for _type_name, name in fields)


def _bound_texts(profile: ConstructorProfile, sources: Mapping[str, str]) -> dict[str, str]:
    """The hashed closure, after every bound path and import matches."""
    bound = dict(profile.bound_files)
    if profile.struct_file not in bound:
        raise ProfileError(
            "profile_dependency_unbound",
            f"{profile.struct_file} is not in the hashed dependency set",
        )
    if profile.source_file not in bound:
        raise ProfileError(
            "profile_dependency_unbound",
            f"{profile.source_file} is not in the hashed dependency set",
        )
    for path in profile.imports:
        if path not in sources:
            raise ProfileError("profile_import_missing", f"{path} is not in the source set")
        if path not in bound:
            raise ProfileError(
                "profile_dependency_unbound",
                f"{path} is imported but not in the hashed dependency set",
            )
    texts: dict[str, str] = {}
    for path, digest in profile.bound_files:
        text = sources.get(path)
        if text is None or sha256_text(text) != digest:
            raise ProfileError(
                "profile_source_mismatch",
                f"{path} does not match the hash this profile was bound to",
            )
        texts[path] = text
    return texts


def _classify_type(type_name: str) -> tuple[str, int, str]:
    """``(category, width, nested)``. Unsupported categories stay explicit."""
    text = type_name.strip()
    if text.endswith("[]"):
        return "array", 0, text[:-2]
    if "[" in text:
        return "unsupported", 0, text
    match = re.fullmatch(r"uint([0-9]*)", text)
    if match:
        width = int(match.group(1) or "256")
        if width == 0 or width > 256 or width % 8:
            return "unsupported", 0, text
        return "uint", width, ""
    match = re.fullmatch(r"int([0-9]*)", text)
    if match:
        width = int(match.group(1) or "256")
        if width == 0 or width > 256 or width % 8:
            return "unsupported", 0, text
        return "int", width, ""
    if text == "bool":
        return "bool", 0, ""
    if text == "address":
        return "address", 0, ""
    match = re.fullmatch(r"bytes(3[0-2]|[12][0-9]|[1-9])", text)
    if match:
        return "bytes", int(match.group(1)), ""
    if text == "bytes" or re.fullmatch(r"bytes[0-9]+", text):
        return "unsupported", 0, text
    if _TYPE_NAME.fullmatch(text):
        return "struct", 0, text.split(".")[-1]
    return "unsupported", 0, text


def _lookup_declared(
    texts: Mapping[str, str], short: str
) -> tuple[str, str, tuple[tuple[str, str], ...]]:
    """``(kind, path, fields)`` for a user-defined name in the bound closure."""
    structs: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    enums: list[str] = []
    values: list[str] = []
    enum_re = re.compile(rf"\benum\s+{re.escape(short)}\b")
    value_re = re.compile(rf"\btype\s+{re.escape(short)}\s+is\b")
    for path, text in texts.items():
        for fields in iter_struct_fields(text, short):
            structs.append((path, fields))
        if enum_re.search(text):
            enums.append(path)
        if value_re.search(text):
            values.append(path)
    if enums or values:
        kind = "enum" if enums else "user-defined value type"
        raise ProfileError(
            "profile_type_unsupported",
            f"{short} is a {kind}. The schema parser resolves elementary types, arrays, "
            "and structs in the bound sources, and does not resolve this kind",
        )
    if not structs:
        raise ProfileError(
            "profile_type_unresolved",
            f"{short} is not declared in the bound source closure",
        )
    first = structs[0][1]
    if any(item[1] != first for item in structs):
        raise ProfileError(
            "profile_type_ambiguous",
            f"{short} is declared differently in more than one bound file",
        )
    return "struct", structs[0][0], first


def _types_match(declared: str, supplied: str) -> bool:
    return declared.split(".")[-1] == supplied.split(".")[-1]


def _check_value(
    value: ProfileValue,
    declared_type: str,
    texts: Mapping[str, str],
    fixtures: Mapping[str, ProfileFixture],
    depth: int,
) -> None:
    if depth > MAX_DEPTH:
        raise ProfileError("profile_bound_exceeded", "the configuration is nested too deeply")
    category, width, nested = _classify_type(declared_type)
    if category == "uint":
        if value.kind != "uint":
            raise ProfileError(
                "profile_type_mismatch", f"{declared_type} requires an integer, not {value.kind}"
            )
        if int(value.value) >= 2**width:
            raise ProfileError(
                "profile_integer_bounds",
                f"{value.value} does not fit {declared_type}",
            )
        return
    if category == "int":
        if value.kind != "uint":
            raise ProfileError(
                "profile_type_mismatch", f"{declared_type} requires an integer, not {value.kind}"
            )
        number = int(value.value)
        limit = 2 ** (width - 1)
        if number >= limit:
            raise ProfileError(
                "profile_integer_bounds", f"{value.value} does not fit {declared_type}"
            )
        return
    if category == "bool":
        if value.kind != "bool":
            raise ProfileError("profile_type_mismatch", f"{declared_type} requires a bool")
        return
    if category == "bytes":
        if width != 32 or value.kind != "bytes32":
            raise ProfileError(
                "profile_type_unsupported",
                f"{declared_type} is not a bytes32 value the profile can fill",
            )
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", value.value):
            raise ProfileError("profile_malformed", "a bytes32 value is not 32 bytes of hex")
        return
    if category == "address":
        if value.kind == "fixture":
            fixture = fixtures.get(value.value)
            if fixture is None or fixture.kind not in _ADDRESS_FIXTURES:
                raise ProfileError(
                    "profile_fixture_incompatible",
                    f"{value.value} is not an address fixture",
                )
            return
        if value.kind != "role":
            raise ProfileError(
                "profile_type_mismatch", f"{declared_type} requires a role or a fixture address"
            )
        return
    if category == "array":
        if value.kind != "array":
            raise ProfileError("profile_type_mismatch", f"{declared_type} requires an array")
        if not _types_match(nested, value.type_name):
            raise ProfileError(
                "profile_type_mismatch",
                f"array element {value.type_name} is not {nested}",
            )
        if len(value.items) > MAX_ARRAY:
            raise ProfileError("profile_bound_exceeded", "the array is longer than the bound")
        _classify_element(nested, texts)
        for item in value.items:
            _check_value(item, nested, texts, fixtures, depth + 1)
        return
    if category == "struct":
        _kind, _path, fields = _lookup_declared(texts, nested)
        if value.kind != "struct" or not _types_match(nested, value.type_name):
            raise ProfileError("profile_type_mismatch", f"{declared_type} requires struct {nested}")
        expected = tuple(name for _type_name, name in fields)
        supplied = tuple(name for name, _child in value.fields)
        if supplied != expected:
            raise ProfileError(
                "profile_struct_mismatch",
                f"{nested} fields do not match the declaration in the bound source",
            )
        for (type_name, _name), (_supplied_name, child) in zip(fields, value.fields, strict=True):
            _check_value(child, type_name, texts, fixtures, depth + 1)
        return
    raise ProfileError(
        "profile_type_unsupported",
        f"{declared_type} is outside the schema parser. It resolves elementary types, "
        "arrays, and structs declared in the bound sources",
    )


def _classify_element(type_name: str, texts: Mapping[str, str]) -> None:
    category, _width, nested = _classify_type(type_name)
    if category == "struct":
        _lookup_declared(texts, nested)
        return
    if category in {"uint", "int", "bool", "address"} or (category == "bytes" and _width == 32):
        return
    raise ProfileError(
        "profile_type_unsupported",
        f"array element {type_name} is not a supported element type",
    )


def address_literal(texts: Mapping[str, str], wanted: str) -> str:
    """The bound-source spelling of ``wanted``, when exactly one literal matches."""
    spellings = {
        item
        for text in texts.values()
        for item in _ADDRESS_WORD.findall(text)
        if item.lower() == wanted.lower()
    }
    if len(spellings) != 1:
        raise ProfileError(
            "profile_fixture_unresolved",
            "place_at must match one address literal in the bound source",
        )
    return str(next(iter(spellings)))


def _named_params(params: str) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for part in split_top(params):
        if not part.strip():
            continue
        words = part.replace("\n", " ").split()
        cleaned = [
            word for word in words if word not in {"memory", "calldata", "storage", "payable"}
        ]
        if len(cleaned) < 2 or not _IDENT.fullmatch(cleaned[-1]):
            raise ProfileError("profile_type_unparsed", "a parameter name could not be read")
        found.append((normalize_type(" ".join(cleaned[:-1])), cleaned[-1]))
    return tuple(found)


def _declares_getter(texts: Mapping[str, str], name: str) -> bool:
    function = re.compile(rf"\bfunction\s+{re.escape(name)}\s*\(")
    variable = re.compile(rf"\b(?:public|external)\b[^;{{]*\b{re.escape(name)}\b")
    return any(function.search(text) or variable.search(text) for text in texts.values())


def _require_address_binding(profile: ConstructorProfile, texts: Mapping[str, str]) -> None:
    """The profile's address is a real parameter, and its getter is declared."""
    if profile.initialization_function:
        name = profile.initialization_function.split("(", 1)[0]
        pattern = re.compile(
            rf"\bfunction\s+{re.escape(name)}\s*\(\s*(?:address|[A-Za-z_]\w*)\s+"
            rf"{re.escape(profile.parameter)}\b"
        )
        if not any(pattern.search(text) for text in texts.values()):
            raise ProfileError(
                "profile_type_unresolved",
                f"{profile.initialization_function} is not declared with parameter "
                f"{profile.parameter}",
            )
    else:
        params = _constructor_params(texts.get(profile.source_file, ""), profile.contract)
        if params is None:
            raise ProfileError("profile_type_unparsed", "the constructor could not be read")
        match = next((typ for typ, name in _named_params(params) if name == profile.parameter), "")
        if match != "address":
            raise ProfileError(
                "profile_type_mismatch",
                f"constructor parameter {profile.parameter} is not an address",
            )
    getter = profile.property_getter[:-2]
    if not _declares_getter(texts, getter):
        raise ProfileError(
            "profile_type_unresolved",
            f"{profile.property_getter} is not declared in the bound source",
        )
    for item in profile.fixtures:
        if item.place_at:
            address_literal(texts, item.place_at)


def _validate_tree(profile: ConstructorProfile, texts: Mapping[str, str]) -> None:
    fixtures = {item.fixture_id: item for item in profile.fixtures}
    if profile.property_template == "initialization-asset":
        _check_value(profile.value, "address", texts, fixtures, depth=1)
        token = next(
            (item.fixture_id for item in profile.fixtures if item.kind == "harness_token"), ""
        )
        if profile.value.kind != "fixture" or profile.value.value != token or not token:
            raise ProfileError(
                "profile_custody_unbound",
                "the address binding must be the harness token fixture",
            )
        _source_contracts(profile, texts)
        _require_address_binding(profile, texts)
        return
    _kind, _path, fields = _lookup_declared(texts, profile.struct_name)
    declared_here = parse_struct_fields(texts.get(profile.struct_file, ""), profile.struct_name)
    if declared_here is None or declared_here != fields:
        raise ProfileError(
            "profile_struct_mismatch",
            f"{profile.struct_name} is not declared in {profile.struct_file}",
        )
    if profile.value.type_name.split(".")[-1] != profile.struct_name:
        raise ProfileError(
            "profile_type_mismatch", "the profile struct is not the constructor type"
        )
    expected = tuple(name for _type_name, name in fields)
    supplied = tuple(name for name, _child in profile.value.fields)
    if supplied != expected:
        raise ProfileError(
            "profile_struct_mismatch",
            f"{profile.struct_name} fields do not match the bound source",
        )
    for (type_name, _name), (_supplied, child) in zip(fields, profile.value.fields, strict=True):
        _check_value(child, type_name, texts, fixtures, depth=1)
    _source_contracts(profile, texts)


def _source_contracts(profile: ConstructorProfile, texts: Mapping[str, str]) -> None:
    fixtures = {item.fixture_id: item for item in profile.fixtures}
    for item in profile.fixtures:
        if item.kind != "source_contract":
            continue
        declaring = ""
        for text in texts.values():
            if re.search(rf"\bcontract\s+{re.escape(item.contract)}\b", text):
                declaring = text
                break
        if not declaring:
            raise ProfileError(
                "profile_fixture_unresolved",
                f"{item.contract} is not a contract in the bound source closure",
            )
        own = _constructor_params(declaring, item.contract)
        if own is None:
            raise ProfileError(
                "profile_type_unparsed",
                f"the constructor of {item.contract} could not be read",
            )
        params = _constructor_types(own)
        if len(params) != len(item.arguments):
            if params and not item.arguments:
                raise ProfileError(
                    "profile_fixture_incompatible",
                    f"{item.contract} has constructor arguments the profile does not fill",
                )
            raise ProfileError(
                "profile_fixture_incompatible",
                f"{item.contract} has {len(params)} constructor arguments and the profile "
                f"supplies {len(item.arguments)}",
            )
        for declared, argument in zip(params, item.arguments, strict=True):
            _check_value(argument, declared, texts, fixtures, depth=1)


def _constructor_params(text: str, contract: str) -> str | None:
    """The constructor parameter text, or "" when the contract has none."""
    match = re.search(rf"\bcontract\s+{re.escape(contract)}\b", text)
    if match is None:
        return None
    open_at = text.find("{", match.end())
    if open_at < 0:
        return None
    depth = 0
    index = open_at
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                body = text[open_at + 1 : index]
                found = re.search(r"\bconstructor\s*\(", body)
                if found is None:
                    return ""
                paren = body.find("(", found.start())
                close = _match_paren(body, paren)
                if close < 0:
                    return None
                return body[paren + 1 : close]
        index += 1
    return None


def _constructor_types(params: str) -> tuple[str, ...]:
    """Normalized types of one constructor's parameters, in order."""
    found: list[str] = []
    for part in split_top(params):
        if not part.strip():
            continue
        words = part.replace("\n", " ").split()
        cleaned = [
            word for word in words if word not in {"memory", "calldata", "storage", "payable"}
        ]
        if len(cleaned) >= 2 and _IDENT.fullmatch(cleaned[-1]):
            cleaned = cleaned[:-1]
        if not cleaned:
            raise ProfileError("profile_type_unparsed", "a constructor parameter has no type")
        found.append(normalize_type(" ".join(cleaned)))
    return tuple(found)


def _match_paren(text: str, open_at: int) -> int:
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def prepare_profile(profile: ConstructorProfile, sources: Mapping[str, str]) -> PreparedProfile:
    """Solidity fragments for a profile that still matches ``sources``."""
    texts = _bound_texts(profile, sources)
    _validate_tree(profile, texts)
    variables = _deploy_fixtures(profile.fixtures, texts)
    statements: list[str] = []
    expression = _render(profile.value, variables, statements)
    contracts = _fixture_contracts(profile.fixtures)
    deploy_text = "\n".join(statements)
    if len(expression) > 8_000 or len(contracts) > 8_000 or len(deploy_text) > 8_000:
        raise ProfileError("profile_bound_exceeded", "the rendered configuration is too large")
    deploy = tuple(line for _name, _variable, line in variables if line)
    token = next((item.fixture_id for item in profile.fixtures if item.kind == "harness_token"), "")
    return PreparedProfile(
        expression=expression,
        deploy_lines=(*deploy, *statements),
        contracts=contracts,
        import_paths=profile.imports,
        provenance=profile.public_dict(),
        harness_token=token,
        harness_token_fields=fixture_fields(profile.value, token) if token else (),
    )


def fixture_fields(value: ProfileValue, fixture_id: str, prefix: str = "") -> tuple[str, ...]:
    """Dotted struct paths whose value is ``fixture_id``. Array items are indexed."""
    found: list[str] = []
    if value.kind == "fixture" and value.value == fixture_id:
        return (prefix,)
    if value.kind == "struct":
        for name, child in value.fields:
            found.extend(fixture_fields(child, fixture_id, f"{prefix}.{name}" if prefix else name))
    elif value.kind == "array":
        for index, item in enumerate(value.items):
            found.extend(fixture_fields(item, fixture_id, f"{prefix}[{index}]"))
    return tuple(found)


def comet_pause_profile(sources: Mapping[str, str]) -> ConstructorProfile:
    """The local pause-authorization profile for the pinned Comet source.

    Refuses when the authorization check or the Configuration fields are not the
    ones this profile knows how to fill. It does not rewrite the target.
    """
    target = sources.get(COMET_FILE, "")
    configuration = sources.get(COMET_CONFIGURATION, "")
    core = sources.get(COMET_CORE, "")
    if not target or not configuration or not core:
        raise ProfileError("profile_source_unsupported", "the Comet closure is incomplete")
    compact = _compact(target)
    if "msg.sender!=governor&&msg.sender!=pauseGuardian" not in compact:
        raise ProfileError(
            "profile_source_unsupported",
            "pause() does not have the expected governor and pauseGuardian check",
        )
    if "function pause(" not in target or "bool supplyPaused" not in target:
        raise ProfileError("profile_source_unsupported", "pause() is not the expected function")
    declared = _comet_constructor_checks(target, configuration, core)
    dependencies = (
        COMET_FILE,
        COMET_CONFIGURATION,
        COMET_CORE,
        "contracts/CometMainInterface.sol",
        "contracts/interfaces/IAssetListFactory.sol",
        "contracts/interfaces/IAssetListFactoryHolder.sol",
    )
    bound = _hash_bound(sources, dependencies)
    values = _comet_fields()
    raw = {
        "profile_id": "comet-pause-authorization",
        "contract": COMET_CONTRACT,
        "source_file": COMET_FILE,
        "source_sha256": sha256_text(target),
        "parameter": "config",
        "model_type": "Configuration",
        "solidity_type": "CometConfiguration.Configuration",
        "struct_file": COMET_CONFIGURATION,
        "struct_name": "Configuration",
        "value": {
            "kind": "struct",
            "type_name": "CometConfiguration.Configuration",
            "fields": [{"name": name, "value": values[name]} for name in declared],
        },
        "fixtures": [
            {"fixture_id": "baseToken", "kind": "decimals_token", "decimals": 6},
            {"fixture_id": "baseFeed", "kind": "decimals_feed", "decimals": 8},
            {"fixture_id": "factory", "kind": "asset_list_factory"},
            {"fixture_id": "holder", "kind": "factory_holder", "depends_on": "factory"},
        ],
        "imports": [
            "contracts/CometCore.sol",
            "contracts/interfaces/IAssetListFactory.sol",
            "contracts/interfaces/IAssetListFactoryHolder.sol",
        ],
        "bound_files": [{"path": path, "sha256": digest} for path, digest in bound],
        "assumptions": [
            "governor and pauseGuardian are local harness addresses, distinct from the attacker",
            "base token decimals are 6 so baseScale equals BASE_ACCRUAL_SCALE (1e6)",
            "the base price feed reports 8 decimals, matching PRICE_FEED_DECIMALS",
            "baseMinForRewards is 1 because the constructor rejects 0",
            "storeFrontPriceFactor is 0, which passes the constructor and is not the "
            "FACTOR_SCALE configuration of public issue 1104",
            "interest-rate fields are 0 because the constructor divides those values by SECONDS_PER_YEAR",
            "assetConfigs is empty. Length 0 is within MAX_ASSETS_FOR_ASSET_LIST and pause "
            "does not read collateral",
            "the extension delegate and asset-list factory are local fixtures, not deployed "
            "Compound contracts",
            "this configuration is a local construction environment, not live market state",
        ],
        "property_function": PAUSE_SIGNATURE,
        "property_statement": PAUSE_STATEMENT,
        "property_getter": "isSupplyPaused()",
        "source_commit": COMET_PIN,
        "property_template": "unauthorized-call",
    }
    return parse_profile(raw)


def _comet_constructor_checks(target: str, configuration: str, core: str) -> tuple[str, ...]:
    """The Configuration field order, after the constructor checks this profile relies on."""
    if "config.baseMinForRewards == 0" not in target:
        raise ProfileError("profile_source_unsupported", "the base-minimum check is absent")
    if "config.storeFrontPriceFactor > FACTOR_SCALE" not in target:
        raise ProfileError("profile_source_unsupported", "the storefront check is absent")
    if "PRICE_FEED_DECIMALS = 8" not in core or "MAX_BASE_DECIMALS = 18" not in core:
        raise ProfileError(
            "profile_source_unsupported", "decimal limits are not the expected constants"
        )
    if "BASE_ACCRUAL_SCALE = 1e6" not in core:
        raise ProfileError("profile_source_unsupported", "the accrual scale is not 1e6")
    declared = struct_field_names(configuration, "Configuration")
    if declared is None:
        raise ProfileError("profile_source_unsupported", "Configuration is not declared")
    if tuple(_comet_fields()) != declared:
        raise ProfileError(
            "profile_source_unsupported",
            "Configuration fields are not the set this profile can fill",
        )
    return declared


CUSTODY_SIGNATURE = "supply(address,uint256)"
CUSTODY_STATEMENT = (
    "a supplier that supplies the base token and withdraws its full balance ends with no more "
    "base token than it started with while another supplier's base token is in custody"
)


def _declaring(sources: Mapping[str, str], pattern: str, label: str) -> str:
    """The one closure file whose comment-free text declares ``pattern``."""
    found = sorted(
        path for path, text in sources.items() if re.search(pattern, _strip_comments(text))
    )
    if len(found) != 1:
        raise ProfileError(
            "profile_source_unsupported",
            f"{label} is declared in {len(found)} closure files; the profile needs exactly one",
        )
    return found[0]


def _enclosing(text: str, struct_name: str) -> str:
    """The contract, interface or library that declares ``struct_name``."""
    clean = _strip_comments(text)
    struct = re.search(rf"\bstruct\s+{re.escape(struct_name)}\s*\{{", clean)
    if struct is None:
        raise ProfileError("profile_source_unsupported", f"{struct_name} is not declared")
    owners = list(
        re.finditer(r"\b(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_]\w*)", clean)
    )
    before = [match.group(1) for match in owners if match.start() < struct.start()]
    if not before:
        raise ProfileError(
            "profile_source_unsupported", f"{struct_name} is not declared inside a contract"
        )
    return before[-1]


def comet_custody_profile(sources: Mapping[str, str], *, source_commit: str) -> ConstructorProfile:
    """Bind the Comet base token to the harness token for the custody round trip.

    Declaring files are found in the closure, so a revision that moves the
    interfaces still binds; the constructor checks are the pause profile's. The
    harness token has 18 decimals, so baseScale is 1e18 here, not the 1e6 of
    the deployed USDC market; that difference is recorded as an assumption.
    """
    target = sources.get(COMET_FILE, "")
    if not target:
        raise ProfileError("profile_source_unsupported", f"{COMET_FILE} is not in the closure")
    configuration_file = _declaring(sources, r"\bstruct\s+Configuration\s*\{", "Configuration")
    core_file = _declaring(sources, r"\bcontract\s+CometCore\b", "CometCore")
    main_file = _declaring(sources, r"\bcontract\s+CometMainInterface\b", "CometMainInterface")
    factory_file = _declaring(sources, r"\binterface\s+IAssetListFactory\b", "IAssetListFactory")
    holder_file = _declaring(
        sources, r"\binterface\s+IAssetListFactoryHolder\b", "IAssetListFactoryHolder"
    )
    declared = _comet_constructor_checks(target, sources[configuration_file], sources[core_file])
    if "if (asset == baseToken)" not in target or "function initializeStorage()" not in target:
        raise ProfileError(
            "profile_source_unsupported",
            "supply does not branch on baseToken or initializeStorage() is absent",
        )
    bound = _hash_bound(
        sources, (COMET_FILE, configuration_file, core_file, main_file, factory_file, holder_file)
    )
    values = _comet_fields()
    struct_type = f"{_enclosing(sources[configuration_file], 'Configuration')}.Configuration"
    raw = {
        "profile_id": "comet-base-custody",
        "contract": COMET_CONTRACT,
        "source_file": COMET_FILE,
        "source_sha256": sha256_text(target),
        "parameter": "config",
        "model_type": "Configuration",
        "solidity_type": struct_type,
        "struct_file": configuration_file,
        "struct_name": "Configuration",
        "value": {
            "kind": "struct",
            "type_name": struct_type,
            "fields": [{"name": name, "value": values[name]} for name in declared],
        },
        "fixtures": [
            {"fixture_id": "baseToken", "kind": "harness_token", "decimals": 18},
            {"fixture_id": "baseFeed", "kind": "decimals_feed", "decimals": 8},
            {"fixture_id": "factory", "kind": "asset_list_factory"},
            {"fixture_id": "holder", "kind": "factory_holder", "depends_on": "factory"},
        ],
        "imports": [core_file, factory_file, holder_file],
        "bound_files": [{"path": path, "sha256": digest} for path, digest in bound],
        "assumptions": [
            "the base token is the harness fixture token (18 decimals, no fee, returns true), "
            "so baseScale is 1e18. The deployed cUSDCv3 base token has 6 decimals",
            "governor and pauseGuardian are local harness addresses, distinct from the attacker",
            "the base price feed reports 8 decimals, matching PRICE_FEED_DECIMALS",
            "baseMinForRewards is 1 because the constructor rejects 0. Tracking speeds are 0",
            "interest-rate fields are 0, and no call advances time, so no interest accrues",
            "assetConfigs is empty. The round trip supplies and withdraws only the base token",
            "the extension delegate and asset-list factory are local fixtures, not deployed "
            "Compound contracts",
            "this configuration is a local construction environment, not live market state",
        ],
        "property_function": CUSTODY_SIGNATURE,
        "property_statement": CUSTODY_STATEMENT,
        "property_getter": "balanceOf(address)",
        "source_commit": source_commit,
        "property_template": "custody",
        "observed_fixture": "baseToken",
    }
    return parse_profile(raw)


ASSET_SIGNATURE = "getAssetInfo(uint8)"
ASSET_STATEMENT = "getAssetInfo(0) returns the collateral asset address configured in assetConfigs"
_COLLATERAL_DECIMALS = 18
_BORROW_FACTOR = 500_000_000_000_000_000  # 0.5e18, below the liquidate factor
_LIQUIDATE_FACTOR = 800_000_000_000_000_000  # 0.8e18, at most FACTOR_SCALE
_LIQUIDATION_FACTOR = 900_000_000_000_000_000  # 0.9e18
_SUPPLY_CAP = 1_000_000_000_000_000_000  # 1e18, one whole 18-decimal token after descale


def comet_asset_profile(sources: Mapping[str, str]) -> ConstructorProfile:
    """One local collateral asset against the pinned Comet source.

    The factory is the pinned ``AssetListFactory``, which deploys the pinned
    ``AssetList``. The target source is not modified. Factors are the values
    ``AssetList`` accepts: borrow below liquidate, liquidate within
    ``FACTOR_SCALE``, and the descaled factors still ordered.
    """
    pause = comet_pause_profile(sources)
    asset_list = sources.get("contracts/AssetList.sol", "")
    factory = sources.get("contracts/AssetListFactory.sol", "")
    if "function createAssetList" not in factory or "new AssetList" not in factory:
        raise ProfileError(
            "profile_source_unsupported", "AssetListFactory is not the pinned factory"
        )
    if "borrowCollateralFactor >= assetConfig.liquidateCollateralFactor" not in asset_list:
        raise ProfileError(
            "profile_source_unsupported", "AssetList does not enforce the collateral-factor order"
        )
    if "getAssetInfo(uint8 i)" not in sources.get(COMET_FILE, ""):
        raise ProfileError("profile_source_unsupported", "getAssetInfo(uint8) is not the target")
    configuration = sources.get(COMET_CONFIGURATION, "")
    asset_fields = struct_field_names(configuration, "AssetConfig")
    expected = (
        "asset",
        "priceFeed",
        "decimals",
        "borrowCollateralFactor",
        "liquidateCollateralFactor",
        "liquidationFactor",
        "supplyCap",
    )
    if asset_fields != expected:
        raise ProfileError(
            "profile_source_unsupported", "AssetConfig fields are not the set this profile can fill"
        )
    dependencies = (
        COMET_FILE,
        COMET_CONFIGURATION,
        COMET_CORE,
        "contracts/CometMainInterface.sol",
        "contracts/interfaces/IAssetList.sol",
        "contracts/interfaces/IAssetListFactory.sol",
        "contracts/interfaces/IAssetListFactoryHolder.sol",
        "contracts/interfaces/IERC20NonStandard.sol",
        "contracts/interfaces/IPriceFeed.sol",
        "contracts/AssetList.sol",
        "contracts/AssetListFactory.sol",
    )
    bound = _hash_bound(sources, dependencies)
    values = _comet_fields()
    values["assetConfigs"] = {
        "kind": "array",
        "type_name": "CometConfiguration.AssetConfig",
        "items": [
            {
                "kind": "struct",
                "type_name": "CometConfiguration.AssetConfig",
                "fields": [
                    {"name": "asset", "value": {"kind": "fixture", "value": "collateral"}},
                    {"name": "priceFeed", "value": {"kind": "fixture", "value": "collateralFeed"}},
                    {
                        "name": "decimals",
                        "value": {"kind": "uint", "value": str(_COLLATERAL_DECIMALS)},
                    },
                    {
                        "name": "borrowCollateralFactor",
                        "value": {"kind": "uint", "value": str(_BORROW_FACTOR)},
                    },
                    {
                        "name": "liquidateCollateralFactor",
                        "value": {"kind": "uint", "value": str(_LIQUIDATE_FACTOR)},
                    },
                    {
                        "name": "liquidationFactor",
                        "value": {"kind": "uint", "value": str(_LIQUIDATION_FACTOR)},
                    },
                    {"name": "supplyCap", "value": {"kind": "uint", "value": str(_SUPPLY_CAP)}},
                ],
            }
        ],
    }
    declared = struct_field_names(configuration, "Configuration")
    if declared is None:
        raise ProfileError("profile_source_unsupported", "Configuration is not declared")
    raw = pause.to_dict()
    raw.update(
        {
            "profile_id": "comet-asset-list",
            "source_sha256": sha256_text(sources[COMET_FILE]),
            "value": {
                "kind": "struct",
                "type_name": "CometConfiguration.Configuration",
                "fields": [{"name": name, "value": values[name]} for name in declared],
            },
            "fixtures": [
                {"fixture_id": "baseToken", "kind": "decimals_token", "decimals": 6},
                {"fixture_id": "baseFeed", "kind": "decimals_feed", "decimals": 8},
                {"fixture_id": "collateral", "kind": "decimals_token", "decimals": 18},
                {"fixture_id": "collateralFeed", "kind": "decimals_feed", "decimals": 8},
                {
                    "fixture_id": "factory",
                    "kind": "source_contract",
                    "contract": "AssetListFactory",
                },
                {"fixture_id": "holder", "kind": "factory_holder", "depends_on": "factory"},
            ],
            "imports": [
                "contracts/CometCore.sol",
                "contracts/AssetListFactory.sol",
                "contracts/interfaces/IAssetListFactory.sol",
                "contracts/interfaces/IAssetListFactoryHolder.sol",
            ],
            "bound_files": [{"path": path, "sha256": digest} for path, digest in bound],
            "assumptions": [
                "governor and pauseGuardian are local harness addresses, distinct from the attacker",
                "base token decimals are 6 so baseScale equals BASE_ACCRUAL_SCALE (1e6)",
                "the base price feed and the collateral price feed report 8 decimals",
                "the collateral token reports 18 decimals, matching its AssetConfig",
                "borrow, liquidate, and liquidation factors are 5e17, 8e17, and 9e17",
                "those factors pass the AssetList order checks before and after descaling",
                "supplyCap is 1e18, which fits uint128 and descales to one whole token",
                "the asset-list factory is the pinned AssetListFactory deploying the pinned AssetList",
                "the collateral token and price feed are local fixtures, not live market contracts",
                "this configuration is a local construction environment, not deployed bytecode",
            ],
            "property_function": ASSET_SIGNATURE,
            "property_statement": ASSET_STATEMENT,
            "property_getter": "",
            "source_commit": COMET_PIN,
            "property_template": "configured-asset",
            "probe_argument": "0",
            "observed_fixture": "collateral",
        }
    )
    return parse_profile(raw)


def _hash_bound(sources: Mapping[str, str], paths: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    found: list[tuple[str, str]] = []
    for path in paths:
        text = sources.get(path, "")
        if not text:
            raise ProfileError("profile_source_unsupported", f"{path} is not in the source closure")
        found.append((path, sha256_text(text)))
    return tuple(found)


def seed_sources(
    selection: Any, sources: Mapping[str, str], profile: ConstructorProfile
) -> dict[str, str]:
    """The files a profile sequence is compiled from: the target closure, not extra context."""
    if getattr(selection, "mode", "") == "explicit":
        paths = [path for path in selection.selected if path in sources]
    else:
        paths = [
            path
            for path in selection.selected
            if selection.role_of(path) in {"target", "compile_dependency"} and path in sources
        ]
    if profile.source_file not in paths:
        raise ProfileError(
            "profile_dependency_unreadable",
            f"{profile.source_file} is not in the selected closure",
        )
    for path, _digest in profile.bound_files:
        if path not in paths and path in sources:
            paths.append(path)
        if path not in sources:
            raise ProfileError("profile_dependency_unreadable", f"{path} was not read")
    return {path: sources[path] for path in paths}


def attach_profile_seed(campaign: Any, analysis: Any) -> dict[str, Any] | None:
    """Add the profile's authorization sequence to a campaign analysis, or record why not."""
    raw = campaign.spec.constructor_profile
    if not raw:
        return None
    binding: dict[str, str] = {}
    try:
        profile = parse_profile(raw)
        recorded = getattr(getattr(campaign, "manifest", None), "source_commit", "") or ""
        if profile.source_commit and recorded != profile.source_commit:
            raise ProfileError(
                "profile_source_revision_mismatch",
                "the profile source commit does not match the campaign source revision",
            )
        chosen = seed_sources(campaign.selection, analysis.sources, profile)
        prepared = prepare_profile(profile, chosen)
        if profile.property_template == "custody":
            binding = _custody_binding(profile, prepared, analysis.candidates)
    except ProfileError as exc:
        analysis.sequence_skipped[f"constructor_profile:{raw.get('profile_id', 'unknown')}"] = (
            f"{exc.code}: {exc.reason}"
        )
        record = {"validation": "rejected", "reason_code": exc.code, "reason": exc.reason}
        campaign.cache["constructor_profile"] = record
        return record
    if profile.property_template == "custody":
        # The traced round trip is already planned; the profile only constructs it.
        accepted = {**profile.public_dict(), "custody_binding": binding}
        campaign.cache["constructor_profile"] = accepted
        return accepted
    if profile.property_template == "initialization-asset":
        # Deployment configuration only. It does not add a candidate or a sequence.
        record = profile.public_dict()
        campaign.cache["constructor_profile"] = record
        return record
    model = build_research_model(chosen)
    seeded = _seed_sequence(model, analysis.sequence_identity, profile, chosen)
    if isinstance(seeded, str):
        analysis.sequence_skipped[f"constructor_profile:{profile.profile_id}"] = seeded
        record = {
            "validation": "rejected",
            "reason_code": "profile_property_unsupported",
            "reason": seeded,
        }
        campaign.cache["constructor_profile"] = record
        return record
    sequence, candidate = seeded
    if sequence.sequence_id not in analysis.models:
        analysis.sequences = (*analysis.sequences, sequence)
        analysis.models[sequence.sequence_id] = model
        analysis.sequence_sources[sequence.sequence_id] = dict(chosen)
        analysis.candidates = (*analysis.candidates, candidate)
    record = profile.public_dict()
    campaign.cache["constructor_profile"] = record
    return record


def _custody_binding(
    profile: ConstructorProfile, prepared: PreparedProfile, candidates: Any
) -> dict[str, str]:
    """The traced pair the harness token binds, or the reason it binds nothing."""
    from app.parsing.solidity_conservation import DETECTOR

    traced = [
        item
        for item in candidates
        if item.detector == DETECTOR
        and item.contract == profile.contract
        and item.function == profile.property_function
    ]
    if len(traced) != 1:
        raise ProfileError(
            "profile_custody_unbound",
            f"{len(traced)} traced custody pairs start at {profile.property_function}; "
            "the profile binds exactly one",
        )
    candidate = traced[0]
    binding = candidate.fact("token_binding")
    source = candidate.fact("token_source")
    fields = {f"{profile.parameter}.{path}" for path in prepared.harness_token_fields}
    supplied = next((path for path in sorted(fields) if source.endswith(f" {path}")), "")
    if not binding.startswith("state:") or not supplied:
        raise ProfileError(
            "profile_custody_unbound",
            f"the traced token is {binding or 'unbound'} ({source or 'no source'}); the "
            f"harness token is assigned to {', '.join(sorted(fields))}",
        )
    getter = candidate.fact("credit_getter")
    if profile.property_getter and profile.property_getter != getter:
        raise ProfileError(
            "profile_custody_unbound",
            f"the profile reads {profile.property_getter}; the trace reads {getter or 'none'}",
        )
    return {
        "candidate": f"{candidate.detector}@{candidate.contract}.{candidate.function}",
        "payout_function": candidate.fact("payout_function"),
        "token_binding": binding,
        "token_source": source,
        "harness_token_field": supplied,
        "credit_getter": getter,
    }


def _seed_sequence(
    model: ResearchModel,
    identity: SequenceIdentity,
    profile: ConstructorProfile,
    sources: Mapping[str, str],
) -> tuple[Vfcs, SemanticCandidate] | str:
    function = next(
        (
            item
            for item in model.all_functions()
            if item.contract == profile.contract and item.signature == profile.property_function
        ),
        None,
    )
    if function is None:
        return f"profile_property_unsupported: {profile.property_function} is not in the model"
    if profile.property_template == "configured-asset":
        return _seed_configured(model, identity, profile, sources, function)
    if not _authorizes(function.body):
        return (
            "profile_property_unsupported: the function does not check governor and pauseGuardian"
        )
    getter = next(
        (
            item
            for item in model.all_functions()
            if item.contract == profile.contract and item.signature == profile.property_getter
        ),
        None,
    )
    if getter is None:
        return f"profile_property_unsupported: {profile.property_getter} is not in the model"
    arguments = tuple(
        (param.name, "true" if index == 0 else "false")
        for index, param in enumerate(function.params)
    )
    if not function.params or not all(param.type_name == "bool" for param in function.params):
        return "profile_property_unsupported: the probe parameters are not booleans"
    call = VfcsCall(
        profile.contract,
        function.signature,
        "execute",
        ATTACKER,
        arguments=arguments,
        established_by=f"constructor_profile:{profile.profile_id}",
    )
    sequence = stamp_source_identity(
        Vfcs(
            sequence_id=sequence_id_of(
                (call,),
                "unauthorized-call",
                identity,
                derived_from=f"profile.authorization@{profile.contract}.{function.signature}",
            ),
            template="unauthorized-call",
            origin=f"constructor_profile:{profile.profile_id}",
            calls=(call,),
            property_under_test=profile.property_statement,
            derived_from=f"profile.authorization@{profile.contract}.{function.signature}",
            identity=identity,
        ),
        sources,
    )
    candidate = SemanticCandidate(
        detector="profile.authorization",
        family="access_control",
        title="unauthorized pause",
        summary=profile.property_statement,
        file=profile.source_file,
        line=function.line,
        contract=profile.contract,
        function=function.signature,
        status="profile_seed",
        confidence="source",
    )
    return sequence, candidate


def _seed_configured(
    model: ResearchModel,
    identity: SequenceIdentity,
    profile: ConstructorProfile,
    sources: Mapping[str, str],
    function: Any,
) -> tuple[Vfcs, SemanticCandidate] | str:
    del model
    if len(function.params) != 1 or function.params[0].type_name not in {
        "uint8",
        "uint256",
        "uint",
    }:
        return "profile_property_unsupported: the configured read does not take one integer index"
    call = VfcsCall(
        profile.contract,
        function.signature,
        "read",
        ATTACKER,
        arguments=((function.params[0].name or "arg0", profile.probe_argument),),
        established_by=f"fixture:{profile.observed_fixture}",
    )
    sequence = stamp_source_identity(
        Vfcs(
            sequence_id=sequence_id_of(
                (call,),
                "configured-asset",
                identity,
                derived_from=f"profile.configured_asset@{profile.contract}.{function.signature}",
            ),
            template="configured-asset",
            origin=f"constructor_profile:{profile.profile_id}",
            calls=(call,),
            property_under_test=profile.property_statement,
            derived_from=f"profile.configured_asset@{profile.contract}.{function.signature}",
            identity=identity,
        ),
        sources,
    )
    candidate = SemanticCandidate(
        detector="profile.configured_asset",
        family="accounting",
        title="configured asset preserved",
        summary=profile.property_statement,
        file=profile.source_file,
        line=function.line,
        contract=profile.contract,
        function=function.signature,
        status="profile_seed",
        confidence="source",
    )
    return sequence, candidate


def _authorizes(body: str) -> bool:
    compact = _compact(body)
    return (
        "msg.sender!=governor&&msg.sender!=pauseGuardian" in compact
        or "msg.sender==governor||msg.sender==pauseGuardian" in compact
    )


def _comet_fields() -> dict[str, dict[str, Any]]:
    zero = {"kind": "uint", "value": "0"}
    return {
        "governor": {"kind": "role", "value": "governor"},
        "pauseGuardian": {"kind": "role", "value": "pause_guardian"},
        "baseToken": {"kind": "fixture", "value": "baseToken"},
        "baseTokenPriceFeed": {"kind": "fixture", "value": "baseFeed"},
        "extensionDelegate": {"kind": "fixture", "value": "holder"},
        "supplyKink": zero,
        "supplyPerYearInterestRateSlopeLow": zero,
        "supplyPerYearInterestRateSlopeHigh": zero,
        "supplyPerYearInterestRateBase": zero,
        "borrowKink": zero,
        "borrowPerYearInterestRateSlopeLow": zero,
        "borrowPerYearInterestRateSlopeHigh": zero,
        "borrowPerYearInterestRateBase": zero,
        "storeFrontPriceFactor": zero,
        "trackingIndexScale": {"kind": "uint", "value": "1"},
        "baseTrackingSupplySpeed": zero,
        "baseTrackingBorrowSpeed": zero,
        "baseMinForRewards": {"kind": "uint", "value": "1"},
        "baseBorrowMin": zero,
        "targetReserves": zero,
        "assetConfigs": {
            "kind": "array",
            "type_name": "CometConfiguration.AssetConfig",
            "items": [],
        },
    }


def _deploy_fixtures(
    fixtures: tuple[ProfileFixture, ...], texts: Mapping[str, str]
) -> list[tuple[str, str, str]]:
    by_id = {item.fixture_id: item for item in fixtures}
    ordered: list[ProfileFixture] = []
    pending = list(fixtures)
    while pending:
        ready = [
            item
            for item in pending
            if not item.depends_on or item.depends_on in {done.fixture_id for done in ordered}
        ]
        if not ready:
            raise ProfileError("profile_fixture_cycle", "fixture dependencies do not resolve")
        ordered.extend(ready)
        pending = [item for item in pending if item not in ready]
    rendered: list[tuple[str, str, str]] = []
    names = {
        item.fixture_id: HARNESS_TOKEN_VARIABLE
        if item.kind == "harness_token"
        else f"bf_{item.fixture_id}"
        for item in ordered
    }
    for item in ordered:
        variable = names[item.fixture_id]
        if item.kind == "harness_token":
            rendered.append((item.fixture_id, variable, ""))
            by_id[item.fixture_id] = item
            continue
        contract = _contract_name(item)
        if item.kind == "factory_holder":
            dependency = names[item.depends_on]
            line = f"        {contract} {variable} = new {contract}(address({dependency}));"
        elif item.kind == "source_contract" and item.arguments:
            statements: list[str] = []
            try:
                args = ", ".join(_render(arg, rendered, statements) for arg in item.arguments)
            except StopIteration as exc:
                raise ProfileError(
                    "profile_unresolved_fixture",
                    f"{item.contract} references a fixture that is not deployed before it",
                ) from exc
            rendered_args = "\n".join(statements)
            line = (
                f"{rendered_args}\n        {contract} {variable} = new {contract}({args});"
                if rendered_args
                else f"        {contract} {variable} = new {contract}({args});"
            )
        elif item.kind == "source_contract":
            line = f"        {contract} {variable} = new {contract}();"
        else:
            line = f"        {contract} {variable} = new {contract}();"
        if item.place_at:
            literal = address_literal(texts, item.place_at)
            line = f"{line}\n        vm.etch({literal}, address({variable}).code);"
        rendered.append((item.fixture_id, variable, line))
        by_id[item.fixture_id] = item
    return rendered


def _fixture_contracts(fixtures: tuple[ProfileFixture, ...]) -> str:
    blocks: list[str] = []
    for item in fixtures:
        if item.kind == "harness_token":
            continue
        contract = _contract_name(item)
        if item.kind in {"decimals_token", "decimals_feed"}:
            decimals = item.decimals if item.decimals is not None else 0
            blocks.append(
                f"contract {contract} {{\n"
                f"    uint8 public immutable d;\n"
                f"    constructor() {{ d = {decimals}; }}\n"
                f"    function decimals() external view returns (uint8) {{ return d; }}\n"
                f"}}\n"
            )
        elif item.kind == "asset_list_factory":
            blocks.append(
                f"contract {contract} is IAssetListFactory {{\n"
                "    function createAssetList(CometCore.AssetConfig[] memory)\n"
                "        external\n"
                "        returns (address)\n"
                "    {\n"
                "        return address(this);\n"
                "    }\n"
                "}\n"
            )
        elif item.kind == "factory_holder":
            blocks.append(
                f"contract {contract} is IAssetListFactoryHolder {{\n"
                f"    address public immutable factory;\n"
                f"    constructor(address factory_) {{ factory = factory_; }}\n"
                f"    function assetListFactory() external view returns (address) {{ return factory; }}\n"
                f"}}\n"
            )
    return "\n".join(blocks)


def _contract_name(item: ProfileFixture) -> str:
    if item.kind == "source_contract":
        if not _IDENT.fullmatch(item.contract):
            raise ProfileError(
                "profile_malformed", "a source contract fixture needs a contract name"
            )
        return item.contract
    prefix = {
        "decimals_token": "BugForgeTok",
        "decimals_feed": "BugForgeFeed",
        "asset_list_factory": "BugForgeFactory",
        "factory_holder": "BugForgeHolder",
    }[item.kind]
    return f"{prefix}_{item.fixture_id}"


def _render(
    value: ProfileValue,
    variables: list[tuple[str, str, str]],
    statements: list[str],
) -> str:
    if value.kind == "uint":
        return value.value
    if value.kind == "bytes32":
        return f"bytes32({value.value})"
    if value.kind == "bool":
        return value.value
    if value.kind == "role":
        return ROLE_EXPRESSION[value.value]
    if value.kind == "fixture":
        name = next(variable for fid, variable, _line in variables if fid == value.value)
        return f"address({name})"
    if value.kind == "array":
        if not value.items:
            return f"new {value.type_name}[](0)"
        name = f"bf_arr{len(statements)}"
        statements.append(
            f"        {value.type_name}[] memory {name} = new {value.type_name}[]({len(value.items)});"
        )
        for index, item in enumerate(value.items):
            rendered = _render(item, variables, statements)
            statements.append(f"        {name}[{index}] = {rendered};")
        return name
    fields = ", ".join(
        f"{name}: {_render(child, variables, statements)}" for name, child in value.fields
    )
    return f"{value.type_name}({{ {fields} }})"


def _value(raw: Any, fixture_ids: set[str], depth: int) -> ProfileValue:
    if depth > MAX_DEPTH or not isinstance(raw, Mapping):
        raise ProfileError("profile_malformed", "a profile value is missing or too deep")
    kind = raw.get("kind")
    if kind not in _KINDS:
        raise ProfileError("profile_malformed", "a profile value kind is not supported")
    if kind == "uint":
        text = str(raw.get("value", ""))
        if not _UINT.fullmatch(text):
            raise ProfileError("profile_malformed", "a uint value is not a decimal integer")
        return ProfileValue("uint", text)
    if kind == "bytes32":
        text = str(raw.get("value", ""))
        if not re.fullmatch(r"0x[0-9a-fA-F]{64}", text):
            raise ProfileError("profile_malformed", "a bytes32 value is not 32 bytes of hex")
        return ProfileValue("bytes32", text)
    if kind == "bool":
        text = str(raw.get("value", ""))
        if text not in {"true", "false"}:
            raise ProfileError("profile_malformed", "a bool value is not true or false")
        return ProfileValue("bool", text)
    if kind == "role":
        text = str(raw.get("value", ""))
        if text not in ROLE_EXPRESSION:
            raise ProfileError("profile_malformed", f"unknown address role {text!r}")
        return ProfileValue("role", text)
    if kind == "fixture":
        text = str(raw.get("value", ""))
        if text not in fixture_ids:
            raise ProfileError("profile_unresolved_fixture", f"fixture {text!r} is not declared")
        return ProfileValue("fixture", text)
    if kind == "array":
        type_name = _type_name(str(raw.get("type_name", "")), "array type")
        items = raw.get("items", [])
        if not isinstance(items, list) or len(items) > MAX_ARRAY:
            raise ProfileError("profile_malformed", "an array is missing or too long")
        parsed = tuple(_value(item, fixture_ids, depth + 1) for item in items)
        return ProfileValue("array", type_name=type_name, items=parsed)
    type_name = _type_name(str(raw.get("type_name", "")), "struct type")
    fields_raw = raw.get("fields", [])
    if not isinstance(fields_raw, list) or not fields_raw or len(fields_raw) > MAX_FIELDS:
        raise ProfileError("profile_malformed", "a struct needs its fields")
    fields: list[tuple[str, ProfileValue]] = []
    seen: set[str] = set()
    for item in fields_raw:
        if not isinstance(item, Mapping) or not _IDENT.fullmatch(str(item.get("name", ""))):
            raise ProfileError("profile_malformed", "a struct field name is not an identifier")
        name = str(item["name"])
        if name in seen:
            raise ProfileError("profile_malformed", f"duplicate struct field {name}")
        seen.add(name)
        fields.append((name, _value(item.get("value"), fixture_ids, depth + 1)))
    return ProfileValue("struct", type_name=type_name, fields=tuple(fields))


def _fixtures(raw: Any) -> tuple[ProfileFixture, ...]:
    if not isinstance(raw, list) or len(raw) > MAX_FIXTURES:
        raise ProfileError("profile_malformed", "fixtures must be a bounded list")
    fixture_ids = {
        str(item.get("fixture_id", ""))
        for item in raw
        if isinstance(item, Mapping) and _IDENT.fullmatch(str(item.get("fixture_id", "")))
    }
    found: list[ProfileFixture] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_malformed", "a fixture is not an object")
        unknown = sorted(
            set(item)
            - {"fixture_id", "kind", "decimals", "depends_on", "contract", "arguments", "place_at"}
        )
        if unknown:
            raise ProfileError("profile_malformed", f"unknown fixture fields: {', '.join(unknown)}")
        fixture_id = str(item.get("fixture_id", ""))
        kind = str(item.get("kind", ""))
        if not _IDENT.fullmatch(fixture_id) or kind not in _FIXTURE_KINDS:
            raise ProfileError("profile_malformed", "a fixture id or kind is not allowed")
        if fixture_id in seen:
            raise ProfileError("profile_malformed", f"duplicate fixture {fixture_id}")
        seen.add(fixture_id)
        decimals = item.get("decimals")
        if kind in {"decimals_token", "decimals_feed"}:
            if (
                not isinstance(decimals, int)
                or isinstance(decimals, bool)
                or not 0 <= decimals <= 18
            ):
                raise ProfileError("profile_malformed", "fixture decimals must be an integer 0..18")
        elif kind == "harness_token":
            if decimals != HARNESS_TOKEN_DECIMALS or isinstance(decimals, bool):
                raise ProfileError(
                    "profile_fixture_incompatible",
                    f"the harness token has {HARNESS_TOKEN_DECIMALS} decimals; the profile "
                    "must state that value",
                )
            if any(done.kind == "harness_token" for done in found):
                raise ProfileError("profile_malformed", "a profile binds one harness token")
        elif decimals is not None:
            raise ProfileError("profile_malformed", "this fixture does not take decimals")
        depends = str(item.get("depends_on", ""))
        contract = str(item.get("contract", ""))
        if kind == "factory_holder":
            if not depends:
                raise ProfileError("profile_unresolved_fixture", "a factory holder needs a factory")
        elif kind != "source_contract" and depends:
            raise ProfileError("profile_malformed", "this fixture does not take a dependency")
        if kind == "source_contract":
            if not _IDENT.fullmatch(contract):
                raise ProfileError(
                    "profile_malformed", "a source contract fixture needs a contract name"
                )
        elif contract:
            raise ProfileError("profile_malformed", "this fixture does not name a source contract")
        arguments_raw = item.get("arguments", [])
        if arguments_raw in (None, ""):
            arguments_raw = []
        if not isinstance(arguments_raw, list) or len(arguments_raw) > 8:
            raise ProfileError("profile_malformed", "fixture constructor arguments are not a list")
        if arguments_raw and kind != "source_contract":
            raise ProfileError(
                "profile_malformed", "this fixture does not take constructor arguments"
            )
        arguments = tuple(_value(arg, fixture_ids, depth=1) for arg in arguments_raw)
        place_at = str(item.get("place_at", "") or "")
        if place_at and kind != "source_contract":
            raise ProfileError("profile_malformed", "only a source contract can be placed")
        if place_at and not _ADDRESS_WORD.fullmatch(place_at):
            raise ProfileError("profile_malformed", "place_at is not an address literal")
        found.append(
            ProfileFixture(
                fixture_id,
                kind,
                decimals if isinstance(decimals, int) else None,
                depends,
                contract,
                arguments,
                place_at,
            )
        )
    ids = {item.fixture_id for item in found}
    for item in found:
        if item.depends_on and item.depends_on not in ids:
            raise ProfileError(
                "profile_unresolved_fixture", f"{item.fixture_id} depends on a missing fixture"
            )
    return tuple(found)


def _bound_files(raw: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_BOUND_FILES:
        raise ProfileError("profile_malformed", "bound_files must list the hashed sources")
    found: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise ProfileError("profile_malformed", "a bound file is not an object")
        path = str(item.get("path", ""))
        digest = str(item.get("sha256", ""))
        if not _PATH.fullmatch(path) or ".." in path.split("/"):
            raise ProfileError("profile_malformed", "a bound path is not allowed")
        if not _SHA.fullmatch(digest):
            raise ProfileError("profile_malformed", "a bound hash is not sha256")
        found.append((path, digest))
    return tuple(found)


def _reject_privileged_attacker(value: ProfileValue) -> None:
    if value.kind == "role" and value.value in {"attacker", "victim"}:
        raise ProfileError(
            "profile_role_conflict", "a privileged field cannot be the attacker or the victim"
        )
    if value.kind == "struct":
        for name, child in value.fields:
            if name in {"governor", "pauseGuardian"} and (
                child.kind != "role" or child.value not in PRIVILEGED_ROLES
            ):
                raise ProfileError(
                    "profile_role_conflict",
                    f"{name} must be an explicit governor or pause_guardian role",
                )
            if name in {"governor", "pauseGuardian"}:
                continue
            _reject_privileged_attacker(child)
    if value.kind == "array":
        for item in value.items:
            _reject_privileged_attacker(item)


def _required_text(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProfileError("profile_malformed", f"{key} is required")
    return value.strip()


def _ident(raw: Mapping[str, Any], key: str) -> str:
    value = _required_text(raw, key)
    if not _IDENT.fullmatch(value):
        raise ProfileError("profile_malformed", f"{key} is not an identifier")
    return value


def _type_name(value: str, label: str) -> str:
    if not _TYPE_NAME.fullmatch(value):
        raise ProfileError("profile_malformed", f"{label} is not a type name")
    return value


def _path(raw: Mapping[str, Any], key: str) -> str:
    value = _required_text(raw, key)
    if not _PATH.fullmatch(value) or ".." in value.split("/"):
        raise ProfileError("profile_malformed", f"{key} is not a repository path")
    return value


def _sha(raw: Mapping[str, Any], key: str) -> str:
    value = _required_text(raw, key)
    if not _SHA.fullmatch(value):
        raise ProfileError("profile_malformed", f"{key} is not a sha256 hex digest")
    return value


def _paths(raw: Any, label: str) -> list[str]:
    if not isinstance(raw, list) or len(raw) > MAX_BOUND_FILES:
        raise ProfileError("profile_malformed", f"{label} must be a bounded list")
    found: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not _PATH.fullmatch(item) or ".." in item.split("/"):
            raise ProfileError("profile_malformed", f"{label} contains a path that is not allowed")
        found.append(item)
    return found


def _statements(raw: Any) -> list[str]:
    if not isinstance(raw, list) or len(raw) > 24:
        raise ProfileError("profile_malformed", "assumptions must be a bounded list")
    found: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip() or len(item) > 400:
            raise ProfileError("profile_malformed", "an assumption is not plain text")
        if any(ch in item for ch in "{};`"):
            raise ProfileError("profile_malformed", "an assumption cannot carry code")
        found.append(item.strip())
    return found


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//.*?$", " ", text, flags=re.M)


def _compact(text: str) -> str:
    return re.sub(r"\s+", "", _strip_comments(text))
