/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

#define _STR(x)        #x
#define STR(x) _STR(x)

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
    {"set_option", LDAPMod_set_option, METH_VARARGS},
    {"get_option", LDAPMod_get_option, METH_VARARGS},
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
    {Py_mod_exec, LDAPMod_init_type},
    {Py_mod_exec, LDAPMod_init_constants},
    {Py_mod_exec, init_pkginfo},
    {0, NULL}
};

static struct PyModuleDef ldap_moduledef = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_ldap",
    .m_size = 0,
    .m_methods = ldap_functions,
    .m_slots = ldap_slots,
};

PyMODINIT_FUNC
PyInit__ldap()
{
    return PyModuleDef_Init(&ldap_moduledef);
}
