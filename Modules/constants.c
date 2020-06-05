/* constants defined for LDAP
 * See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "constants.h"
#include "ldapcontrol.h"

/* the base exception class */

PyObject *LDAPexception_class;

/* list of exception classes */

#define LDAP_ERROR_MIN          LDAP_REFERRAL_LIMIT_EXCEEDED

#ifdef LDAP_PROXIED_AUTHORIZATION_DENIED
#define LDAP_ERROR_MAX          LDAP_PROXIED_AUTHORIZATION_DENIED
#else
#ifdef LDAP_ASSERTION_FAILED
#define LDAP_ERROR_MAX          LDAP_ASSERTION_FAILED
#else
#define LDAP_ERROR_MAX          LDAP_OTHER
#endif
#endif

#define LDAP_ERROR_OFFSET       -LDAP_ERROR_MIN

static PyObject *errobjects[LDAP_ERROR_MAX - LDAP_ERROR_MIN + 1];

/* Convert a bare LDAP error number into an exception */
PyObject *
LDAPerr(int errnum)
{
    if (errnum >= LDAP_ERROR_MIN && errnum <= LDAP_ERROR_MAX &&
            errobjects[errnum + LDAP_ERROR_OFFSET] != NULL) {
        PyErr_SetNone(errobjects[errnum + LDAP_ERROR_OFFSET]);
    }
    else {
        PyObject *args = Py_BuildValue("{s:i}", "errnum", errnum);

        if (args == NULL)
            return NULL;
        PyErr_SetObject(LDAPexception_class, args);
        Py_DECREF(args);
    }
    return NULL;
}

/* Convert an LDAP error into an informative python exception */
PyObject *
LDAPraise_for_message(LDAP *l, LDAPMessage *m)
{
    int myerrno, errnum, opt_errnum, res, msgid = -1, msgtype = 0;
    PyObject *errobj = NULL;
    PyObject *info = NULL;
    PyObject *str = NULL;
    PyObject *pyerrno = NULL;
    PyObject *pyresult = NULL;
    PyObject *pyctrls = NULL;
    char *matched = NULL;
    char *error = NULL;
    char **refs = NULL;
    LDAPControl **serverctrls = NULL;

    if (l == NULL) {
        PyErr_SetFromErrno(LDAPexception_class);
        ldap_msgfree(m);
        return NULL;
    }

    /* at first save errno for later use before it gets overwritten by another call */
    myerrno = errno;

    if (m != NULL) {
        msgid = ldap_msgid(m);
        msgtype = ldap_msgtype(m);
        ldap_parse_result(l, m, &errnum, &matched, &error, &refs,
                            &serverctrls, 1);
    }

    if (msgtype <= 0) {
        opt_errnum = ldap_get_option(l, LDAP_OPT_ERROR_NUMBER, &errnum);
        if (opt_errnum != LDAP_OPT_SUCCESS) {
            errnum = opt_errnum;
            if (errnum == LDAP_NO_MEMORY) {
                PyErr_NoMemory();
                goto cleanup;
            }
        }

        ldap_get_option(l, LDAP_OPT_MATCHED_DN, &matched);
        ldap_get_option(l, LDAP_OPT_ERROR_STRING, &error);
    }

    if (errnum >= LDAP_ERROR_MIN && errnum <= LDAP_ERROR_MAX) {
        // Borrowed reference
        errobj = errobjects[errnum + LDAP_ERROR_OFFSET];
    }
    if (errobj == NULL) {
        // Borrowed reference
        errobj = LDAPexception_class;
    }

    info = PyDict_New();
    if (info == NULL) {
        goto cleanup;
    }

    if (msgtype > 0) {
        pyresult = PyInt_FromLong(msgtype);
        if (!pyresult) {
            goto cleanup;
        }
        res = PyDict_SetItemString(info, "msgtype", pyresult);
        if (res) {
            goto cleanup;
        }
        Py_CLEAR(pyresult);
    }

    if (msgid >= 0) {
        pyresult = PyInt_FromLong(msgid);
        if (!pyresult) {
            goto cleanup;
        }
        res = PyDict_SetItemString(info, "msgid", pyresult);
        if (res) {
            goto cleanup;
        }
        Py_CLEAR(pyresult);
    }

    pyresult = PyInt_FromLong(errnum);
    if (!pyresult) {
        goto cleanup;
    }
    res = PyDict_SetItemString(info, "result", pyresult);
    if (res) {
        goto cleanup;
    }
    Py_CLEAR(pyresult);

    str = PyUnicode_FromString(ldap_err2string(errnum));
    if (!str) {
        goto cleanup;
    }
    res = PyDict_SetItemString(info, "desc", str);
    if (res) {
        goto cleanup;
    }
    Py_CLEAR(str);

    if (myerrno != 0) {
        pyerrno = PyInt_FromLong(myerrno);
        if (!pyerrno) {
            goto cleanup;
        }
        res = PyDict_SetItemString(info, "errno", pyerrno);
        if (res) {
            goto cleanup;
        }
        Py_CLEAR(pyerrno);
    }

    if (!(pyctrls = LDAPControls_to_List(serverctrls))) {
        int err = LDAP_NO_MEMORY;
        ldap_set_option(l, LDAP_OPT_ERROR_NUMBER, &err);

        PyErr_NoMemory();
        goto cleanup;
    }
    ldap_controls_free(serverctrls);
    serverctrls = NULL;
    res = PyDict_SetItemString(info, "ctrls", pyctrls);
    if (res) {
        goto cleanup;
    }
    Py_CLEAR(pyctrls);

    if (matched != NULL) {
        if (*matched != '\0') {
            str = PyUnicode_FromString(matched);
            if (!str) {
                goto cleanup;
            }
            res = PyDict_SetItemString(info, "matched", str);
            if (res) {
                goto cleanup;
            }
            Py_CLEAR(str);
        }
        ldap_memfree(matched);
        matched = NULL;
    }

    if (errnum == LDAP_REFERRAL && refs != NULL && refs[0] != NULL) {
        /* Keep old behaviour, overshadow error message */
        char err[1024];

        snprintf(err, sizeof(err), "Referral:\n%s", refs[0]);
        str = PyUnicode_FromString(err);
        if (!str) {
            goto cleanup;
        }
        res = PyDict_SetItemString(info, "info", str);
        if (res) {
            goto cleanup;
        }
        Py_CLEAR(str);
    }
    else if (error != NULL && *error != '\0') {
        str = PyUnicode_FromString(error);
        if (!str) {
            goto cleanup;
        }
        res = PyDict_SetItemString(info, "info", str);
        if (res) {
            goto cleanup;
        }
        Py_CLEAR(str);
    }

    PyErr_SetObject(errobj, info);

cleanup:
    if (matched) {
        ldap_memfree(matched);
    }
    if (error) {
        ldap_memfree(error);
    }
    if (refs) {
        ldap_memvfree((void **)refs);
    }
    if (serverctrls) {
        ldap_controls_free(serverctrls);
    }
    Py_XDECREF(pyresult);
    Py_XDECREF(pyerrno);
    Py_XDECREF(str);
    Py_XDECREF(info);
    Py_XDECREF(pyctrls);
    return NULL;
}

PyObject *
LDAPerror(LDAP *l)
{
    return LDAPraise_for_message(l, NULL);
}

/* initialise the module constants */

int
LDAPinit_constants(PyObject *m)
{
    PyObject *exc, *nobj;

    /* simple constants */

    if (PyModule_AddIntConstant(m, "OPT_ON", 1) != 0)
        return -1;
    if (PyModule_AddIntConstant(m, "OPT_OFF", 0) != 0)
        return -1;

    /* exceptions */

    LDAPexception_class = PyErr_NewException("ldap.LDAPError", NULL, NULL);
    if (LDAPexception_class == NULL) {
        return -1;
    }

    if (PyModule_AddObject(m, "LDAPError", LDAPexception_class) != 0)
        return -1;
    Py_INCREF(LDAPexception_class);

    /* XXX - backward compatibility with pre-1.8 */
    if (PyModule_AddObject(m, "error", LDAPexception_class) != 0)
        return -1;
    Py_INCREF(LDAPexception_class);

    /* Generated constants -- see Lib/ldap/constants.py */

#define add_err(n) do {  \
    exc = PyErr_NewException("ldap." #n, LDAPexception_class, NULL);  \
    if (exc == NULL) return -1;  \
    nobj = PyLong_FromLong(LDAP_##n); \
    if (nobj == NULL) return -1; \
    if (PyObject_SetAttrString(exc, "errnum", nobj) != 0) return -1; \
    Py_DECREF(nobj); \
    errobjects[LDAP_##n+LDAP_ERROR_OFFSET] = exc;  \
    if (PyModule_AddObject(m, #n, exc) != 0) return -1;  \
    Py_INCREF(exc);  \
} while (0)

#define add_int(n) do {  \
    if (PyModule_AddIntConstant(m, #n, LDAP_##n) != 0) return -1;  \
} while (0)

#define add_string(n) do {  \
    if (PyModule_AddStringConstant(m, #n, LDAP_##n) != 0) return -1;  \
} while (0)

#include "constants_generated.h"

    return 0;
}
