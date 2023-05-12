from typing import Any, ClassVar

import ldap
__version__: str
API_VERSION: int
AUTH_NONE: int
AUTH_SIMPLE: int
AVA_BINARY: int
AVA_NONPRINTABLE: int
AVA_NULL: int
AVA_STRING: int
CONTROL_ASSERT: str
CONTROL_MANAGEDSAIT: str
CONTROL_PAGEDRESULTS: str
CONTROL_PASSWORDPOLICYREQUEST: str
CONTROL_PASSWORDPOLICYRESPONSE: str
CONTROL_POST_READ: str
CONTROL_PRE_READ: str
CONTROL_PROXY_AUTHZ: str
CONTROL_RELAX: str
CONTROL_SORTREQUEST: str
CONTROL_SORTRESPONSE: str
CONTROL_SUBENTRIES: str
CONTROL_SYNC: str
CONTROL_SYNC_DONE: str
CONTROL_SYNC_STATE: str
CONTROL_VALUESRETURNFILTER: str
DEREF_ALWAYS: int
DEREF_FINDING: int
DEREF_NEVER: int
DEREF_SEARCHING: int
DN_FORMAT_AD_CANONICAL: int
DN_FORMAT_DCE: int
DN_FORMAT_LDAP: int
DN_FORMAT_LDAPV2: int
DN_FORMAT_LDAPV3: int
DN_FORMAT_MASK: int
DN_FORMAT_UFN: int
DN_PEDANTIC: int
DN_PRETTY: int
DN_P_NOLEADTRAILSPACES: int
DN_P_NOSPACEAFTERRDN: int
DN_SKIP: int
INIT_FD_AVAIL: int
LIBLDAP_R: int
MOD_ADD: int
MOD_BVALUES: int
MOD_DELETE: int
MOD_INCREMENT: int
MOD_REPLACE: int
MSG_ALL: int
MSG_ONE: int
MSG_RECEIVED: int
NO_LIMIT: int
OPT_API_FEATURE_INFO: int
OPT_API_INFO: int
OPT_CLIENT_CONTROLS: int
OPT_CONNECT_ASYNC: int
OPT_DEBUG_LEVEL: int
OPT_DEFBASE: int
OPT_DEREF: int
OPT_DESC: int
OPT_DIAGNOSTIC_MESSAGE: int
OPT_ERROR_NUMBER: int
OPT_ERROR_STRING: int
OPT_HOST_NAME: int
OPT_MATCHED_DN: int
OPT_NETWORK_TIMEOUT: int
OPT_OFF: int
OPT_ON: int
OPT_PROTOCOL_VERSION: int
OPT_REFERRALS: int
OPT_REFHOPLIMIT: int
OPT_RESTART: int
OPT_RESULT_CODE: int
OPT_SERVER_CONTROLS: int
OPT_SIZELIMIT: int
OPT_SUCCESS: int
OPT_TCP_USER_TIMEOUT: int
OPT_TIMELIMIT: int
OPT_TIMEOUT: int
OPT_URI: int
OPT_X_KEEPALIVE_IDLE: int
OPT_X_KEEPALIVE_INTERVAL: int
OPT_X_KEEPALIVE_PROBES: int
OPT_X_SASL_AUTHCID: int
OPT_X_SASL_AUTHZID: int
OPT_X_SASL_MECH: int
OPT_X_SASL_NOCANON: int
OPT_X_SASL_REALM: int
OPT_X_SASL_SECPROPS: int
OPT_X_SASL_SSF: int
OPT_X_SASL_SSF_EXTERNAL: int
OPT_X_SASL_SSF_MAX: int
OPT_X_SASL_SSF_MIN: int
OPT_X_SASL_USERNAME: int
OPT_X_TLS: int
OPT_X_TLS_ALLOW: int
OPT_X_TLS_CACERTDIR: int
OPT_X_TLS_CACERTFILE: int
OPT_X_TLS_CERTFILE: int
OPT_X_TLS_CIPHER: int
OPT_X_TLS_CIPHER_SUITE: int
OPT_X_TLS_CRLCHECK: int
OPT_X_TLS_CRLFILE: int
OPT_X_TLS_CRL_ALL: int
OPT_X_TLS_CRL_NONE: int
OPT_X_TLS_CRL_PEER: int
OPT_X_TLS_CTX: int
OPT_X_TLS_DEMAND: int
OPT_X_TLS_DHFILE: int
OPT_X_TLS_ECNAME: int
OPT_X_TLS_HARD: int
OPT_X_TLS_KEYFILE: int
OPT_X_TLS_NEVER: int
OPT_X_TLS_NEWCTX: int
OPT_X_TLS_PACKAGE: int
OPT_X_TLS_PEERCERT: int
OPT_X_TLS_PROTOCOL_MAX: int
OPT_X_TLS_PROTOCOL_MIN: int
OPT_X_TLS_PROTOCOL_SSL3: int
OPT_X_TLS_PROTOCOL_TLS1_0: int
OPT_X_TLS_PROTOCOL_TLS1_1: int
OPT_X_TLS_PROTOCOL_TLS1_2: int
OPT_X_TLS_PROTOCOL_TLS1_3: int
OPT_X_TLS_RANDOM_FILE: int
OPT_X_TLS_REQUIRE_CERT: int
OPT_X_TLS_REQUIRE_SAN: int
OPT_X_TLS_TRY: int
OPT_X_TLS_VERSION: int
PORT: int
REQ_ABANDON: int
REQ_ADD: int
REQ_BIND: int
REQ_COMPARE: int
REQ_DELETE: int
REQ_EXTENDED: int
REQ_MODIFY: int
REQ_MODRDN: int
REQ_SEARCH: int
REQ_UNBIND: int
RES_ADD: int
RES_ANY: int
RES_BIND: int
RES_COMPARE: int
RES_DELETE: int
RES_EXTENDED: int
RES_INTERMEDIATE: int
RES_MODIFY: int
RES_MODRDN: int
RES_SEARCH_ENTRY: int
RES_SEARCH_REFERENCE: int
RES_SEARCH_RESULT: int
RES_UNSOLICITED: int
SASL_AUTOMATIC: int
SASL_AVAIL: int
SASL_INTERACTIVE: int
SASL_QUIET: int
SCOPE_BASE: int
SCOPE_ONELEVEL: int
SCOPE_SUBORDINATE: int
SCOPE_SUBTREE: int
SYNC_INFO: str
TAG_CONTROLS: int
TAG_EXOP_REQ_OID: int
TAG_EXOP_REQ_VALUE: int
TAG_EXOP_RES_OID: int
TAG_EXOP_RES_VALUE: int
TAG_LDAPCRED: int
TAG_LDAPDN: int
TAG_MESSAGE: int
TAG_MSGID: int
TAG_NEWSUPERIOR: int
TAG_REFERRAL: int
TAG_SASL_RES_CREDS: int
TLS_AVAIL: int
URL_ERR_BADSCOPE: int
URL_ERR_MEM: int
VENDOR_VERSION: int
VERSION: int
VERSION1: int
VERSION2: int
VERSION3: int
VERSION_MAX: int
VERSION_MIN: int

class ADMINLIMIT_EXCEEDED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class AFFECTS_MULTIPLE_DSAS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class ALIAS_DEREF_PROBLEM(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class ALIAS_PROBLEM(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class ALREADY_EXISTS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class ASSERTION_FAILED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class AUTH_METHOD_NOT_SUPPORTED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class AUTH_UNKNOWN(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class BUSY(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CANCELLED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CANNOT_CANCEL(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CLIENT_LOOP(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class COMPARE_FALSE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class COMPARE_TRUE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CONFIDENTIALITY_REQUIRED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CONNECT_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CONSTRAINT_VIOLATION(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class CONTROL_NOT_FOUND(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class DECODING_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class ENCODING_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class FILTER_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INAPPROPRIATE_AUTH(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INAPPROPRIATE_MATCHING(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INSUFFICIENT_ACCESS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INVALID_CREDENTIALS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INVALID_DN_SYNTAX(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class INVALID_SYNTAX(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class IS_LEAF(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class LDAPError(Exception): ...

class LOCAL_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class LOOP_DETECT(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class MORE_RESULTS_TO_RETURN(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NAMING_VIOLATION(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NOT_ALLOWED_ON_NONLEAF(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NOT_ALLOWED_ON_RDN(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NOT_SUPPORTED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_MEMORY(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_OBJECT_CLASS_MODS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_RESULTS_RETURNED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_SUCH_ATTRIBUTE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_SUCH_OBJECT(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class NO_SUCH_OPERATION(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class OBJECT_CLASS_VIOLATION(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class OPERATIONS_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class OTHER(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class PARAM_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class PARTIAL_RESULTS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class PROTOCOL_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class PROXIED_AUTHORIZATION_DENIED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class REFERRAL(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class REFERRAL_LIMIT_EXCEEDED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class RESULTS_TOO_LARGE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class SASL_BIND_IN_PROGRESS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class SERVER_DOWN(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class SIZELIMIT_EXCEEDED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class STRONG_AUTH_NOT_SUPPORTED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class STRONG_AUTH_REQUIRED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class SUCCESS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class TIMELIMIT_EXCEEDED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class TIMEOUT(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class TOO_LATE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class TYPE_OR_VALUE_EXISTS(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class UNAVAILABLE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class UNAVAILABLE_CRITICAL_EXTENSION(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class UNDEFINED_TYPE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class UNWILLING_TO_PERFORM(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class USER_CANCELLED(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class VLV_ERROR(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class X_PROXY_AUTHZ_FAILURE(ldap.LDAPError):
    errnum: ClassVar[int] = ...

class error(Exception): ...

# Everything except the argument type annotations below
# has been autogenerated using stubgen

def decode_page_control(*args: Any, **kwargs: Any) -> Any: ...
def encode_assertion_control(*args: Any, **kwargs: Any) -> Any: ...
def encode_page_control(*args: Any, **kwargs: Any) -> Any: ...
def encode_valuesreturnfilter_control(*args: Any, **kwargs: Any) -> Any: ...
def get_option(*args: Any, **kwargs: Any) -> Any: ...
def initialize(*args: Any, **kwargs: Any) -> Any: ...
def initialize_fd(*args: Any, **kwargs: Any) -> Any: ...
def set_option(*args: Any, **kwargs: Any) -> Any: ...
def str2dn(*args: Any, **kwargs: Any) -> Any: ...
