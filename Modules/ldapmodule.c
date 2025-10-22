/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

#define _STR(x)        #x
#define STR(x) _STR(x)

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

int
LDAPinit_types( PyObject *d )
{
    /* PyStructSequence types */
    static struct sequence_types {
        PyStructSequence_Desc *desc;
        PyTypeObject *where;
    } sequence_types[] = {
        {
            .desc = &control_tuple_desc,
            .where = &control_tuple_type,
        },
        {
            .desc = &message_tuple_desc,
            .where = &message_tuple_type,
        },
        {
            .desc = NULL,
        }
    }, *type;

    for ( type = sequence_types; type->desc; type++ ) {
        /* We'd like to use PyStructSequence_NewType from Stable ABI but can't
         * until Python 3.8 because of https://bugs.python.org/issue34784 */
        if ( PyStructSequence_InitType2( type->where, type->desc ) ) {
            return -1;
        }
        if ( PyDict_SetItemString( d, type->desc->name, (PyObject *)type->where ) ) {
            return -1;
        }
    }

    return 0;
}

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
    if (LDAPinit_types(d) == -1) {
        return NULL;
    }

    /* Check for errors */
    if (PyErr_Occurred())
        Py_FatalError("can't initialize module _ldap");

    return m;
}
