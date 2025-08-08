/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

/* ldap_initialize */

static PyObject *
l_ldap_initialize(PyObject *unused, PyObject *args)
{
    char *uri;
    LDAP *ld = NULL;
    int ret;
    PyThreadState *save;

    if (!PyArg_ParseTuple(args, "z:initialize", &uri))
        return NULL;

    save = PyEval_SaveThread();
    ret = ldap_initialize(&ld, uri);
    PyEval_RestoreThread(save);

    if (ret != LDAP_SUCCESS)
        return LDAPerror(ld);

    return (PyObject *)newLDAPObject(ld);
}

#ifdef HAVE_LDAP_INIT_FD
/* initialize_fd(fileno, url) */

static PyObject *
l_ldap_initialize_fd(PyObject *unused, PyObject *args)
{
    char *url;
    LDAP *ld = NULL;
    int ret;
    int fd;
    int proto = -1;
    LDAPURLDesc *lud = NULL;

    PyThreadState *save;

    if (!PyArg_ParseTuple(args, "is:initialize_fd", &fd, &url))
        return NULL;

    /* Get LDAP protocol from scheme */
    ret = ldap_url_parse(url, &lud);
    if (ret != LDAP_SUCCESS)
        return LDAPerr(ret);

    if (strcmp(lud->lud_scheme, "ldap") == 0) {
        proto = LDAP_PROTO_TCP;
    }
    else if (strcmp(lud->lud_scheme, "ldaps") == 0) {
        proto = LDAP_PROTO_TCP;
    }
    else if (strcmp(lud->lud_scheme, "ldapi") == 0) {
        proto = LDAP_PROTO_IPC;
    }
#ifdef LDAP_CONNECTIONLESS
    else if (strcmp(lud->lud_scheme, "cldap") == 0) {
        proto = LDAP_PROTO_UDP;
    }
#endif
    else {
        ldap_free_urldesc(lud);
        PyErr_SetString(PyExc_ValueError, "unsupported URL scheme");
        return NULL;
    }
    ldap_free_urldesc(lud);

    save = PyEval_SaveThread();
    ret = ldap_init_fd((ber_socket_t) fd, proto, url, &ld);
    PyEval_RestoreThread(save);

    if (ret != LDAP_SUCCESS)
        return LDAPerror(ld);

    return (PyObject *)newLDAPObject(ld);
}
#endif

/* ldap_str2dn */

static PyObject *
l_ldap_str2dn(PyObject *unused, PyObject *args)
{
    struct berval str;
    LDAPDN dn;
    int flags = 0;
    PyObject *result = NULL, *tmp;
    int res, i, j;
    Py_ssize_t str_len;

    /*
     * From a DN string such as "a=b,c=d;e=f", build
     * a list-equivalent of AVA structures; namely:
     * ((('a','b',1),('c','d',1)),(('e','f',1),))
     * The integers are a bit combination of the AVA_* flags
     */
    if (!PyArg_ParseTuple(args, "z#|i:str2dn", &str.bv_val, &str_len, &flags))
        return NULL;

    if (str_len == 0) {
        // GH-549: ldap_bv2dn() does not support empty string.
        return PyList_New(0);
    }
    str.bv_len = (ber_len_t) str_len;

    res = ldap_bv2dn(&str, &dn, flags);
    if (res != LDAP_SUCCESS)
        return LDAPerr(res);

    tmp = PyList_New(0);
    if (!tmp)
        goto failed;

    for (i = 0; dn[i]; i++) {
        LDAPRDN rdn;
        PyObject *rdnlist;

        rdn = dn[i];
        rdnlist = PyList_New(0);
        if (!rdnlist)
            goto failed;
        if (PyList_Append(tmp, rdnlist) == -1) {
            Py_DECREF(rdnlist);
            goto failed;
        }

        for (j = 0; rdn[j]; j++) {
            LDAPAVA *ava = rdn[j];
            PyObject *tuple;

            tuple = Py_BuildValue("(O&O&i)",
                                  LDAPberval_to_unicode_object, &ava->la_attr,
                                  LDAPberval_to_unicode_object, &ava->la_value,
                                  ava->la_flags & ~(LDAP_AVA_FREE_ATTR |
                                                    LDAP_AVA_FREE_VALUE));
            if (!tuple) {
                Py_DECREF(rdnlist);
                goto failed;
            }

            if (PyList_Append(rdnlist, tuple) == -1) {
                Py_DECREF(tuple);
                goto failed;
            }
            Py_DECREF(tuple);
        }
        Py_DECREF(rdnlist);
    }

    result = tmp;
    tmp = NULL;

  failed:
    Py_XDECREF(tmp);
    ldap_dnfree(dn);
    return result;
}

/* ldap_dn2str */

static void
_free_dn_structure(LDAPDN dn)
{
    if (dn == NULL)
        return;

    for (LDAPRDN *rdn = dn; *rdn != NULL; rdn++) {
        for (LDAPAVA **avap = *rdn; *avap != NULL; avap++) {
            LDAPAVA *ava = *avap;

            if (ava->la_attr.bv_val) {
                free(ava->la_attr.bv_val);
            }
            if (ava->la_value.bv_val) {
                free(ava->la_value.bv_val);
            }
            free(ava);
        }
        free(*rdn);
    }
    free(dn);
}

/*
 * Convert a Python list-of-list-of-(str, str, int) into an LDAPDN and
 * call ldap_dn2bv to build a DN string.
 *
 * Python signature: dn2str(dn: list[list[tuple[str, str, int]]], flags: int) -> str
 * Returns the DN string on success, or raises TypeError or RuntimeError on error.
 */
static PyObject *
l_ldap_dn2str(PyObject *self, PyObject *args)
{
    PyObject *dn_list = NULL;
    int flags = 0;
    LDAPDN dn = NULL;
    LDAPAVA *ava;
    LDAPAVA **rdn;
    BerValue str = { 0, NULL };
    PyObject *py_rdn_seq = NULL, *py_ava_item = NULL;
    PyObject *py_name = NULL, *py_value = NULL, *py_encoding = NULL;
    PyObject *result = NULL;
    Py_ssize_t nrdns = 0, navas = 0, name_len = 0, value_len = 0;
    int i = 0, j = 0;
    int ldap_err;
    const char *name_utf8, *value_utf8;

    const char *type_error_message = "expected list[list[tuple[str, str, int]]]";

    if (!PyArg_ParseTuple(args, "Oi:dn2str", &dn_list, &flags)) {
        return NULL;
    }

    if (!PySequence_Check(dn_list)) {
        PyErr_SetString(PyExc_TypeError, type_error_message);
        return NULL;
    }

    nrdns = PySequence_Size(dn_list);
    if (nrdns < 0) {
        PyErr_SetString(PyExc_TypeError, type_error_message);
        return NULL;
    }

    /* Allocate array of LDAPRDN pointers (+1 for NULL terminator) */
    dn = (LDAPRDN *) calloc((size_t)nrdns + 1, sizeof(LDAPRDN));
    if (dn == NULL) {
        PyErr_NoMemory();
        return NULL;
    }

    for (i = 0; i < nrdns; i++) {
        py_rdn_seq = PySequence_GetItem(dn_list, i);  /* New reference */
        if (py_rdn_seq == NULL) {
            goto error_cleanup;
        }
        if (!PySequence_Check(py_rdn_seq)) {
            PyErr_SetString(PyExc_TypeError, type_error_message);
            goto error_cleanup;
        }

        navas = PySequence_Size(py_rdn_seq);
        if (navas < 0) {
            PyErr_SetString(PyExc_TypeError, type_error_message);
            goto error_cleanup;
        }

        /* Allocate array of LDAPAVA* pointers (+1 for NULL terminator) */
        rdn = (LDAPAVA **)calloc((size_t)navas + 1, sizeof(LDAPAVA *));
        if (rdn == NULL) {
            PyErr_NoMemory();
            goto error_cleanup;
        }

        for (j = 0; j < navas; j++) {
            py_ava_item = PySequence_GetItem(py_rdn_seq, j);  /* New reference */
            if (py_ava_item == NULL) {
                goto error_cleanup;
            }
            /* Expect a 3‐tuple: (name: str, value: str, encoding: int) */
            if (!PyTuple_Check(py_ava_item) || PyTuple_Size(py_ava_item) != 3) {
                PyErr_SetString(PyExc_TypeError, type_error_message);
                goto error_cleanup;
            }

            py_name = PyTuple_GetItem(py_ava_item, 0);  /* Borrowed reference */
            py_value = PyTuple_GetItem(py_ava_item, 1);  /* Borrowed reference */
            py_encoding = PyTuple_GetItem(py_ava_item, 2);  /* Borrowed reference */

            if (!PyUnicode_Check(py_name) || !PyUnicode_Check(py_value) || !PyLong_Check(py_encoding)) {
                PyErr_SetString(PyExc_TypeError, type_error_message);
                goto error_cleanup;
            }

            name_len = 0;
            value_len = 0;
            name_utf8 = PyUnicode_AsUTF8AndSize(py_name, &name_len);
            value_utf8 = PyUnicode_AsUTF8AndSize(py_value, &value_len);
            if (name_utf8 == NULL || value_utf8 == NULL) {
                goto error_cleanup;
            }

            ava = (LDAPAVA *) calloc(1, sizeof(LDAPAVA));

            if (ava == NULL) {
                PyErr_NoMemory();
                goto error_cleanup;
            }

            ava->la_attr.bv_val = (char *)malloc((size_t)name_len + 1);
            if (ava->la_attr.bv_val == NULL) {
                free(ava);
                PyErr_NoMemory();
                goto error_cleanup;
            }
            memcpy(ava->la_attr.bv_val, name_utf8, (size_t)name_len);
            ava->la_attr.bv_val[name_len] = '\0';
            ava->la_attr.bv_len = (ber_len_t) name_len;

            ava->la_value.bv_val = (char *)malloc((size_t)value_len + 1);
            if (ava->la_value.bv_val == NULL) {
                free(ava->la_attr.bv_val);
                free(ava);
                PyErr_NoMemory();
                goto error_cleanup;
            }
            memcpy(ava->la_value.bv_val, value_utf8, (size_t)value_len);
            ava->la_value.bv_val[value_len] = '\0';
            ava->la_value.bv_len = (ber_len_t) value_len;

            ava->la_flags = (int)PyLong_AsLong(py_encoding);
            if (PyErr_Occurred()) {
                /* Encoding conversion failed */
                free(ava->la_attr.bv_val);
                free(ava->la_value.bv_val);
                free(ava);
                goto error_cleanup;
            }

            rdn[j] = ava;
            Py_DECREF(py_ava_item);
            py_ava_item = NULL;
        }

        /* Null‐terminate the RDN */
        rdn[navas] = NULL;

        dn[i] = rdn;
        Py_DECREF(py_rdn_seq);
        py_rdn_seq = NULL;
    }

    /* Null‐terminate the DN */
    dn[nrdns] = NULL;

    /* Call ldap_dn2bv to build a DN string */
    ldap_err = ldap_dn2bv(dn, &str, flags);
    if (ldap_err != LDAP_SUCCESS) {
        PyErr_SetString(PyExc_RuntimeError, ldap_err2string(ldap_err));
        goto error_cleanup;
    }

    result = PyUnicode_FromString(str.bv_val);
    if (result == NULL) {
        goto error_cleanup;
    }

    /* Free the memory allocated by ldap_dn2bv */
    ldap_memfree(str.bv_val);
    str.bv_val = NULL;

    /* Free our local DN structure */
    _free_dn_structure(dn);
    dn = NULL;

    return result;

  error_cleanup:
    /* Free any partially built DN structure */
    _free_dn_structure(dn);
    dn = NULL;

    /* If ldap_dn2bv allocated something, free it */
    if (str.bv_val) {
        ldap_memfree(str.bv_val);
        str.bv_val = NULL;
    }

    /* Cleanup Python temporaries */
    Py_XDECREF(py_ava_item);
    Py_XDECREF(py_rdn_seq);
    return NULL;
}

/* ldap_set_option (global options) */

static PyObject *
l_ldap_set_option(PyObject *self, PyObject *args)
{
    PyObject *value;
    int option;

    if (!PyArg_ParseTuple(args, "iO:set_option", &option, &value))
        return NULL;
    if (!LDAP_set_option(NULL, option, value))
        return NULL;
    Py_INCREF(Py_None);
    return Py_None;
}

/* ldap_get_option (global options) */

static PyObject *
l_ldap_get_option(PyObject *self, PyObject *args)
{
    int option;

    if (!PyArg_ParseTuple(args, "i:get_option", &option))
        return NULL;
    return LDAP_get_option(NULL, option);
}

/* methods */

static PyMethodDef methods[] = {
    {"initialize", (PyCFunction)l_ldap_initialize, METH_VARARGS},
#ifdef HAVE_LDAP_INIT_FD
    {"initialize_fd", (PyCFunction)l_ldap_initialize_fd, METH_VARARGS},
#endif
    {"str2dn", (PyCFunction)l_ldap_str2dn, METH_VARARGS},
    {"dn2str", (PyCFunction)l_ldap_dn2str, METH_VARARGS},
    {"set_option", (PyCFunction)l_ldap_set_option, METH_VARARGS},
    {"get_option", (PyCFunction)l_ldap_get_option, METH_VARARGS},
    {NULL, NULL}
};

/* initialisation */

void
LDAPinit_functions(PyObject *d)
{
    LDAPadd_methods(d, methods);
}
