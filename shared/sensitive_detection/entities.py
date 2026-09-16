"""Canonical entity names, aliases and the L1..L4 / severity mapping.

Every caller reports the canonical entity so the same sensitive type cannot
split into several statistics: ``phone``, ``PHONE_NUMBER`` and ``PHONE`` are one
type. Unknown entity names are preserved (upper-cased) instead of dropped, so
analyst-authored rules such as ``INTERNAL`` keep working.
"""
from __future__ import annotations

# --- canonical entities -----------------------------------------------------
PHONE = "PHONE"
ID_CARD = "ID_CARD"
BANK_CARD = "BANK_CARD"
EMAIL = "EMAIL"
API_KEY = "API_KEY"
TOKEN = "TOKEN"
CREDENTIAL = "CREDENTIAL"
NAME = "NAME"
ADDRESS = "ADDRESS"
USER_ID = "USER_ID"
MEDICAL_RECORD = "MEDICAL_RECORD"

# Infrastructure metadata, not protected data. Useful as transfer evidence but
# never allowed to make a stream, file or column "sensitive".
IP_ADDRESS = "IP_ADDRESS"
MAC_ADDRESS = "MAC_ADDRESS"
DATE_TIME = "DATE_TIME"
URL = "URL"
NRP = "NRP"
LOCATION = "LOCATION"
DOMAIN = "DOMAIN"

STRUCTURAL_ENTITIES = frozenset({IP_ADDRESS, MAC_ADDRESS, DATE_TIME, URL, NRP, LOCATION, DOMAIN})

# P0 has no NER: these types only ever carry field-name / keyword evidence and
# must be reported as low confidence instead of pretending to be recognised.
FIELD_ONLY_ENTITIES = frozenset({NAME, ADDRESS, MEDICAL_RECORD, USER_ID})

# --- classification ---------------------------------------------------------
# L1..L4 is a *data* classification and is deliberately a different dimension
# from the legacy Critical/High/Medium/Low risk severity used by the existing
# pages. They are linked by a central, configurable map - never overwritten.
L1, L2, L3, L4 = "L1", "L2", "L3", "L4"
LEVELS = (L1, L2, L3, L4)

_SEVERITY_BY_LEVEL = {L4: "Critical", L3: "High", L2: "Medium", L1: "Low"}

_LEVEL_BY_ENTITY = {
    API_KEY: L4,
    TOKEN: L4,
    CREDENTIAL: L4,
    ID_CARD: L3,
    BANK_CARD: L3,
    MEDICAL_RECORD: L3,
    PHONE: L2,
    EMAIL: L2,
    ADDRESS: L2,
    NAME: L1,
    USER_ID: L1,
}

# --- aliases ----------------------------------------------------------------
# Keyed by the upper-cased name a rule or an upstream pack may use.
_ALIASES = {
    "PHONE": PHONE,
    "PHONE_NUMBER": PHONE,
    "CN_PHONE": PHONE,
    "MOBILE": PHONE,
    "MOBILE_NUMBER": PHONE,
    "ID_CARD": ID_CARD,
    "IDCARD": ID_CARD,
    "ID_NUMBER": ID_CARD,
    "IDENTITY_CARD": ID_CARD,
    "CN_ID_CARD": ID_CARD,
    "NATIONAL_ID": ID_CARD,
    "BANK_CARD": BANK_CARD,
    "BANKCARD": BANK_CARD,
    "CREDIT_CARD": BANK_CARD,
    "CARD_NUMBER": BANK_CARD,
    "PAYMENT_CARD": BANK_CARD,
    "EMAIL": EMAIL,
    "EMAIL_ADDRESS": EMAIL,
    "MAIL": EMAIL,
    "API_KEY": API_KEY,
    "APIKEY": API_KEY,
    "SECRET_KEY": API_KEY,
    "ACCESS_KEY": API_KEY,
    "TOKEN": TOKEN,
    "BEARER_TOKEN": TOKEN,
    "ACCESS_TOKEN": TOKEN,
    "CREDENTIAL": CREDENTIAL,
    "CREDENTIALS": CREDENTIAL,
    "PASSWORD": CREDENTIAL,
    "PASSWD": CREDENTIAL,
    "SECRET": CREDENTIAL,
    "NAME": NAME,
    "PERSON": NAME,
    "PERSON_NAME": NAME,
    "FULL_NAME": NAME,
    "ADDRESS": ADDRESS,
    "LOCATION_ADDRESS": ADDRESS,
    "USER_ID": USER_ID,
    "USERID": USER_ID,
    "UID": USER_ID,
    "ACCOUNT": USER_ID,
    "MEDICAL_RECORD": MEDICAL_RECORD,
    "MEDICAL": MEDICAL_RECORD,
    "HEALTH_RECORD": MEDICAL_RECORD,
    "IP_ADDRESS": IP_ADDRESS,
    "IPV4": IP_ADDRESS,
    "IPV6": IP_ADDRESS,
    "MAC_ADDRESS": MAC_ADDRESS,
    "DATE_TIME": DATE_TIME,
    "DATE": DATE_TIME,
    "URL": URL,
    "URI": URL,
    "NRP": NRP,
    "LOCATION": LOCATION,
    "DOMAIN": DOMAIN,
}

# Legacy lowercase names used by the existing probe report and platform columns.
_LEGACY_NAMES = {
    PHONE: "phone",
    ID_CARD: "id_card",
    BANK_CARD: "bank_card",
    EMAIL: "email",
    API_KEY: "api_key",
    TOKEN: "token",
    CREDENTIAL: "credential",
    NAME: "name",
    ADDRESS: "address",
    USER_ID: "user_id",
    MEDICAL_RECORD: "medical_record",
}


def canonical_entity(name: object) -> str:
    """Canonical name for a rule/recognizer entity, or the upper-cased original."""
    text = str(name or "").strip().upper().replace("-", "_").replace(" ", "_")
    if not text:
        return "UNKNOWN"
    return _ALIASES.get(text, text)


def legacy_name(entity: object) -> str:
    """Existing lowercase category name for a canonical entity, else ``""``."""
    return _LEGACY_NAMES.get(canonical_entity(entity), "")


def is_structural(entity: object) -> bool:
    return canonical_entity(entity) in STRUCTURAL_ENTITIES


def is_field_only(entity: object) -> bool:
    return canonical_entity(entity) in FIELD_ONLY_ENTITIES


def level_of(entity: object) -> str:
    return _LEVEL_BY_ENTITY.get(canonical_entity(entity), L2)


def severity_of(entity: object) -> str:
    return _SEVERITY_BY_LEVEL[level_of(entity)]


def severity_of_level(level: object) -> str:
    """The legacy severity of an L1..L4 code; an unknown code falls back to L2."""
    return _SEVERITY_BY_LEVEL.get(str(level or "").strip().upper(), _SEVERITY_BY_LEVEL[L2])


def known_entities() -> tuple[str, ...]:
    """Canonical entities that carry a classification of their own."""
    return tuple(sorted(_LEVEL_BY_ENTITY))
