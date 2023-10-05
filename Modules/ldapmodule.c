/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

#define _STR(x)        #x
#define STR(x) _STR(x)

LDAPAPIInfo ldap_version_info = {
    .ldapai_info_version = LDAP_API_INFO_VERSION,
};

static char version_str[] = STR(LDAPMODULE_VERSION);
static char author_str[] = STR(LDAPMODULE_AUTHOR);
static char license_str[] = STR(LDAPMODULE_LICENSE);

static void
init_pkginfo(PyObject *m)
{
    PyModule_AddStringConstant(m, "__version__", version_str);
    PyModule_AddStringConstant(m, "__author__", author_str);
    PyModule_AddStringConstant(m, "__license__", license_str);
}

/* dummy module methods */
static PyMethodDef methods[] = {
    {NULL, NULL}
};

static struct PyModuleDef ldap_moduledef = {
    PyModuleDef_HEAD_INIT,
    "_ldap",        /* m_name */
    "",             /* m_doc */
    -1,             /* m_size */
    methods,        /* m_methods */
};

/* module initialisation */

PyMODINIT_FUNC
PyInit__ldap()
{
    PyObject *m, *d;

    /* Create the module and add the functions */
    m = PyModule_Create(&ldap_moduledef);

    /* Initialize LDAP class */
    if (PyType_Ready(&LDAP_Type) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    /* Add some symbolic constants to the module */
    d = PyModule_GetDict(m);

    init_pkginfo(m);

    if (LDAPinit_constants(m) == -1) {
        return NULL;
    }

    LDAPinit_functions(d);
    LDAPinit_control(d);

    /* Check for errors */
    if (PyErr_Occurred())
        Py_FatalError("can't initialize module _ldap");

    return m;
}
