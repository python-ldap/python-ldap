/* Miscellaneous common routines
 * See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

/* Raise TypeError with custom message and object */
PyObject *
LDAPerror_TypeError(const char *msg, PyObject *obj)
{
    PyObject *args = Py_BuildValue("sO", msg, obj);

    if (args == NULL) {
        return NULL;
    }
    PyErr_SetObject(PyExc_TypeError, args);
    Py_DECREF(args);
    return NULL;
}
