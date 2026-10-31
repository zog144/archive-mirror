"""Archive-mirror credential inventory and fail-closed configuration boundary."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from zog.host_identify import archive_credentials

SCHEMA = "zog-archive-mirror-credential-inventory-v1"
_ALLOWED_CONFIGURATION = frozenset({
    "root", "collections", "host_id", "intent_file", "endpoint", "issuer",
    "audience", "keyring", "maximum_archive_bytes", "sources",
})
_SECRET_KEYS = frozenset({
    "credential", "credentials", "password", "secret", "token",
    "private_key", "private-key", "signing_key", "signing-key",
    "api_key", "api-key", "access_key", "access-key",
    "session_token", "session-token", "authorization",
})


class ArchiveCredentialConfigurationError(ValueError):
    pass


def _secret_key(name):
    return isinstance(name,str) and name.lower() in _SECRET_KEYS


def _walk(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if _secret_key(key):
                raise ArchiveCredentialConfigurationError(
                    "archive-mirror configuration must not contain secret credentials"
                )
            _walk(item)
    elif isinstance(value,list):
        for item in value:
            _walk(item)


def _public_origin(value, field):
    if not isinstance(value,str):
        raise ArchiveCredentialConfigurationError("invalid "+field)
    parts=urlsplit(value)
    if (parts.scheme!="https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        raise ArchiveCredentialConfigurationError(
            field+" must be credential-free HTTPS origin"
        )


def validate_configuration(value):
    """Reject archive-owned durable secret configuration.

    Short-lived consumer JWTs are not server configuration, and the token
    signing private key belongs only to the authority. Durable upstream-provider
    secrets are installed only through the reviewed common-HTTPS provider
    adapter and must never appear in configuration.json.
    """
    if not isinstance(value,dict) or set(value)-_ALLOWED_CONFIGURATION:
        raise ArchiveCredentialConfigurationError("unknown archive configuration field")
    _walk(value)
    if "endpoint" in value:
        _public_origin(value["endpoint"],"endpoint")
    if "issuer" in value:
        _public_origin(value["issuer"],"issuer")
    if "keyring" in value:
        keyring=value["keyring"]
        if (not isinstance(keyring,str) or not keyring.startswith("/")
                or re.search(r"(private|secret|signing)",keyring,re.I)):
            raise ArchiveCredentialConfigurationError(
                "archive verification keyring must be an explicit public-key path"
            )
    sources=value.get("sources",[])
    if not isinstance(sources,list):
        raise ArchiveCredentialConfigurationError("sources must be a list")
    for source in sources:
        if not isinstance(source,dict):
            raise ArchiveCredentialConfigurationError("invalid source definition")
        _walk(source)
        url=source.get("url")
        if url is not None:
            parts=urlsplit(url)
            if parts.scheme=="https" and (parts.username or parts.password):
                raise ArchiveCredentialConfigurationError(
                    "upstream source URL must not contain credentials"
                )
    return value


def inventory(value):
    validate_configuration(value)
    required={"endpoint","issuer","audience","collections","keyring"}
    if not required <= set(value):
        raise ArchiveCredentialConfigurationError(
            "complete serving configuration required for credential inventory"
        )
    policy=archive_credentials.inventory()
    return {
        "schema":SCHEMA,
        "access_authorization":{
            "format":"zog-archive-jwt-v1",
            "issuer":value["issuer"],
            "audience":value["audience"],
            "collections":sorted(set(value["collections"])),
            "operations":["download","list"],
            "lifetime":"short-lived",
            "delivery":"existing-authenticated-host-response",
        },
        "provider":{
            "endpoint":value["endpoint"],
            "verification_keyring":"public-only",
            "archive_owned_service_secret":False,
            "provider_secret_supported":True,
            "provider_secret_in_configuration":False,
            "upstream_credentials_configured":False,
            "https_delivery_purposes":list(
                archive_credentials.enabled_https_purposes()
            ),
            "provider_scope_schema":archive_credentials.PROVIDER_SCOPE_SCHEMA,
            "provider_role":archive_credentials.PROVIDER_ROLE,
            "provider_operations":[archive_credentials.PROVIDER_OPERATION],
        },
        "classes":policy["classes"],
    }
