/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

#define _STR(x)        #x
#define STR(x) _STR(x)

LDAPAPIInfo LDAPMod_version_info = {
    .ldapai_info_version = LDAP_API_INFO_VERSION,
};
int LDAPMod_thread_safe;

static char version_str[] = STR(LDAPMODULE_VERSION);
static char author_str[] = STR(LDAPMODULE_AUTHOR);
static char license_str[] = STR(LDAPMODULE_LICENSE);

static int
init_pkginfo(PyObject *m)
{
    if (PyModule_AddStringConstant(m, "__version__", version_str) != 0)
        return -1;
    if (PyModule_AddStringConstant(m, "__author__", author_str) != 0)
        return -1;
    if (PyModule_AddStringConstant(m, "__license__", license_str) != 0)
        return -1;
    return 0;
}

static PyMethodDef ldap_functions[] = {
    // functions.c
    {"initialize", LDAPMod_initialize, METH_VARARGS},
#ifdef HAVE_LDAP_INIT_FD
    {"initialize_fd", LDAPMod_initialize_fd, METH_VARARGS},
#endif
    {"str2dn", LDAPMod_str2dn, METH_VARARGS},
    {"dn2str", LDAPMod_dn2str, METH_VARARGS},
    {"set_option", LDAPMod_set_option, METH_VARARGS},
    {"get_option", LDAPMod_get_option, METH_VARARGS},
    {"is_filter", LDAPMod_is_filter, METH_VARARGS},
    // ldapcontrol.c
    {"encode_page_control", LDAPMod_encode_rfc2696, METH_VARARGS},
    {"decode_page_control", LDAPMod_decode_rfc2696, METH_VARARGS},
    {"encode_valuesreturnfilter_control", LDAPMod_encode_rfc3876,
     METH_VARARGS},
    {"encode_assertion_control", LDAPMod_encode_assertion_control,
     METH_VARARGS},
    {NULL, NULL}
};

/* module initialisation */
static PyModuleDef_Slot ldap_slots[] = {
#if PY_VERSION_HEX >= 0x030D0000
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
#endif
#if PY_VERSION_HEX >= 0x030C0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {Py_mod_exec, LDAPMod_init_type},
    {Py_mod_exec, LDAPMod_init_constants},
    {Py_mod_exec, init_pkginfo},
    {0, NULL}
};

static struct PyModuleDef ldap_moduledef = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "_ldap",
    .m_size = sizeof(LDAPModState),
    .m_methods = ldap_functions,
    .m_slots = ldap_slots,
};
struct PyModuleDef *LDAPMod_moduledef;

PyMODINIT_FUNC
PyInit__ldap()
{
    /* Prepare global read-only state shared across all copies of this module */
    struct ldap_apifeature_info info = { 1, "X_OPENLDAP_THREAD_SAFE", 0 };

    if (ldap_get_option(NULL, LDAP_OPT_API_INFO, &LDAPMod_version_info) != LDAP_SUCCESS) {
        PyErr_SetString(PyExc_ImportError, "unrecognised libldap version");
        return NULL;
    }

#ifdef LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE
    if (ldap_get_option(NULL, LDAP_OPT_API_FEATURE_INFO, &info) == LDAP_SUCCESS) {
        LDAPMod_thread_safe = (info.ldapaif_version == 1);
    }
#endif

    LDAPMod_moduledef = &ldap_moduledef;
    return PyModuleDef_Init(LDAPMod_moduledef);
}
