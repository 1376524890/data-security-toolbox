"""Value-level validators.

A validator has one of two jobs:

* **hard** - reject a structurally impossible value (an "email" that is really
  the host part of a connection string). ``accepted=False`` drops the match.
* **soft** - keep the match but adjust its confidence with real evidence, such as
  an ID-card checksum or a Luhn digit. Dropping a well-formed-but-unverified
  value would lose real findings; pretending it is certain would overstate them.

Only callables in :data:`BUILTIN_VALIDATORS` may be referenced by a rule: rules
are data, never code, so there is no ``eval``/``exec``/remote-Python path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

_LUHN_DIGITS = {digit: index for index, digit in enumerate("0123456789")}

# Weights and check characters for the PRC resident ID number (GB 11643-1999).
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK_CHARS = "10X98765432"
# 17 digits plus a digit-or-X check character; separators are stripped first.
_ID_CHARS = re.compile(r"^[0-9]{17}[0-9X]$")


@dataclass(slots=True)
class ValidatorOutcome:
    """Result of one value-level check, carrying no matched value."""

    accepted: bool = True
    confidence: float | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    name: str = ""

    @classmethod
    def reject(cls, name: str, reason: str) -> "ValidatorOutcome":
        return cls(accepted=False, facts={"reason": reason}, name=name)


def digits_only(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def luhn_valid(value: str) -> bool:
    """True when a card-number-like string passes the Luhn check digit."""
    digits = digits_only(value)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        digit = _LUHN_DIGITS[character]
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _birth_date_valid(value: str) -> bool:
    digits = digits_only(value)
    if len(digits) < 14:
        return False
    try:
        year, month, day = int(digits[6:10]), int(digits[10:12]), int(digits[12:14])
    except ValueError:
        return False
    if not 1900 <= year <= 2100 or not 1 <= month <= 12:
        return False
    month_lengths = (31, 29 if (year % 4 == 0 and year % 100 != 0) or year % 400 == 0 else 28,
                     31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return 1 <= day <= month_lengths[month - 1]


def _compact_id(value: str) -> str:
    """Strip separators, keeping a trailing ``X`` check character intact."""
    return re.sub(r"[\s\-]", "", str(value or "")).upper()


def _id_checksum_valid(value: str) -> bool:
    compact = _compact_id(value)
    if not _ID_CHARS.match(compact):
        return False
    total = sum(int(digit) * weight
                for digit, weight in zip(compact[:17], _ID_WEIGHTS, strict=True))
    return compact[17] == _ID_CHECK_CHARS[total % 11]


def validate_cn_id_card(value: str) -> ValidatorOutcome:
    """Length, birth date and check digit.

    Structural failures are rejected. A well-formed number with a bad check
    digit stays a finding at reduced confidence and is flagged in the evidence,
    so a report can tell "confirmed pattern" from "format only". The check
    character may legitimately be ``X``, which must not be mistaken for a
    malformed value.
    """
    compact = _compact_id(value)
    if not _ID_CHARS.match(compact):
        return ValidatorOutcome.reject("cn_id_card", "length_or_charset")
    if not _birth_date_valid(compact):
        return ValidatorOutcome.reject("cn_id_card", "birth_date")
    checksum = _id_checksum_valid(compact)
    return ValidatorOutcome(
        accepted=True,
        confidence=0.95 if checksum else 0.7,
        facts={"checksum_valid": checksum, "birth_date_valid": True},
        name="cn_id_card",
    )


def validate_bank_card(value: str) -> ValidatorOutcome:
    """Luhn is the difference between a card number and an arbitrary digit run."""
    digits = digits_only(value)
    if not 12 <= len(digits) <= 19:
        return ValidatorOutcome.reject("luhn", "length_or_charset")
    ok = luhn_valid(digits)
    return ValidatorOutcome(accepted=True, confidence=0.9 if ok else 0.45,
                            facts={"luhn_valid": ok}, name="luhn")


def validate_email(value: str) -> ValidatorOutcome:
    """Reject loose ``user@host`` matches such as ``security@172.18.0.2``.

    Upstream packs match the host part of database connection strings; a real
    address needs a dotted, alphabetic top-level domain.
    """
    if re.fullmatch(r"[^@\s]+@[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,}", value or ""):
        return ValidatorOutcome(accepted=True, confidence=None, name="email_shape")
    return ValidatorOutcome.reject("email_shape", "not_an_address")


#: Punctuation that only appears in source code, never inside a configured
#: secret: a parameter list, an index, a type annotation, a struct/JSON literal.
_CODE_PUNCTUATION = re.compile(r"[()\[\]{}<>,;]|->|=>|::")
#: A bare identifier: a parameter name, a type name, a language keyword.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
#: The rule matches ``keyword <sep> value`` and the engine hands the validator
#: that whole match, so the keyword and separator have to come off before the
#: value is judged. The keywords (``password``/``api_key``/...) contain no ``:``
#: or ``=``, so the first one is always the separator.
_ASSIGNMENT_HEAD = re.compile(r"^[^:=]*[:=]\s*")

#: The rule's own floor (``\S{6,}``); anything shorter never reaches here anyway.
MIN_SECRET_CHARS = 6
#: Word-like values at or above this length are kept as evidence rather than
#: discarded: a long single word is as likely a passphrase as a type name.
WORD_SECRET_CHARS = 12


def validate_secret_value(value: str) -> ValidatorOutcome:
    """Tell a configured secret from an expression that merely mentions one.

    The rule matches ``password <sep> <value>``, which in source code is as often
    a parameter list as it is a credential: ``password: bytes,``,
    ``password = str(password)``, ``password = self.keyring.get_password(url,``
    and ``password: _PasswordType | None = None`` all matched, and every one of
    them was raised at L4/Critical. None of them is a secret, so code punctuation
    rejects outright.

    What survives is judged on shape, and shape is never conclusive: a word-like
    value with no digit in it (``HiddenText``) is a type or parameter name, not a
    credential, so it stays *evidence* at reduced confidence - the same treatment
    a Luhn-failing card number gets. A value that mixes letters and digits, or
    carries symbols, is what a configured secret looks like and is confirmed.
    """
    text = _ASSIGNMENT_HEAD.sub("", str(value or "").strip(), count=1).strip().strip('"\'`')
    if not text:
        return ValidatorOutcome.reject("secret_value", "empty")
    if _CODE_PUNCTUATION.search(text):
        return ValidatorOutcome.reject("secret_value", "code_punctuation")
    if len(text) < MIN_SECRET_CHARS:
        return ValidatorOutcome.reject("secret_value", "too_short")
    if text.isdigit():
        # A pure number after ``password=`` is as likely to be a status code or an
        # id as a password; keep it as evidence, never as a confirmed credential.
        return ValidatorOutcome(accepted=True, confidence=0.5,
                                facts={"secret_shape": "digits"}, name="secret_value")
    if _IDENTIFIER.fullmatch(text) and not any(char.isdigit() for char in text):
        # No digit and no symbol, so the value is a bare word: the shape of a type
        # annotation far more often than the shape of a secret. Length is all the
        # evidence there is, and it only buys a place in the evidence list.
        confidence = 0.55 if len(text) >= WORD_SECRET_CHARS else 0.4
        return ValidatorOutcome(accepted=True, confidence=confidence,
                                facts={"secret_shape": "word"}, name="secret_value")
    return ValidatorOutcome(accepted=True, confidence=0.9,
                            facts={"secret_shape": "value"}, name="secret_value")


def validate_phone(value: str) -> ValidatorOutcome:
    digits = digits_only(value)
    return ValidatorOutcome(accepted=len(digits) == 11 and digits.startswith("1"),
                            confidence=None, facts={"digits": len(digits)}, name="cn_mobile")


# Rule-referenced validator names must come from this table.
BUILTIN_VALIDATORS: dict[str, Callable[[str], ValidatorOutcome]] = {
    "secret_value": validate_secret_value,
    "cn_id_card": validate_cn_id_card,
    "luhn": validate_bank_card,
    "bank_card": validate_bank_card,
    "email_shape": validate_email,
    "cn_mobile": validate_phone,
    "email": validate_email,
}

# Kept for callers that only need a boolean answer (legacy rule stores).
BOOLEAN_VALIDATORS: dict[str, Callable[[str], bool]] = {
    name: (lambda value, function=function: function(value).accepted)
    for name, function in BUILTIN_VALIDATORS.items()
}


def get_validator(name: object) -> Callable[[str], ValidatorOutcome] | None:
    return BUILTIN_VALIDATORS.get(str(name or "").strip().lower())


def validator_names() -> tuple[str, ...]:
    return tuple(sorted(BUILTIN_VALIDATORS))
