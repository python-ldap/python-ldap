/* common utility macros
 * See https://www.python-ldap.org/ for details. */

#ifndef pythonldap_h
#define pythonldap_h

/* *** common *** */
#define PY_SSIZE_T_CLEAN

#include "Python.h"

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <lber.h>
#include <ldap.h>
#include <ldap_features.h>

#if LDAP_VENDOR_VERSION < 20400
#error Current python-ldap requires OpenLDAP 2.4.x
#endif

#if LDAP_VENDOR_VERSION >= 20448
  /* openldap.h with ldap_init_fd() was introduced in 2.4.48
   * see https://bugs.openldap.org/show_bug.cgi?id=8671
   */
#define HAVE_LDAP_INIT_FD 1
#include <openldap.h>
#elif (defined(__APPLE__) && (LDAP_VENDOR_VERSION == 20428))
/* macOS system libldap 2.4.28 does not have ldap_init_fd symbol */
#undef HAVE_LDAP_INIT_FD
#else
  /* ldap_init_fd() has been around for a very long time
   * SSSD has been defining the function for a while, so it's probably OK.
   */
#define HAVE_LDAP_INIT_FD 1
#define LDAP_PROTO_TCP 1
#define LDAP_PROTO_UDP 2
#define LDAP_PROTO_IPC 3
LDAP_F(int) ldap_init_fd(ber_socket_t fd, int proto, LDAP_CONST char *url,
                         LDAP **ldp);
#endif

#if defined(MS_WINDOWS)
#include <winsock.h>
#else /* unix */
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#endif

#define PYLDAP_FUNC(rtype) rtype
#define PYLDAP_DATA(rtype) extern rtype

PYLDAP_FUNC(PyObject *) LDAPerror_TypeError(const char *, PyObject *);

PYLDAP_FUNC(void) LDAPadd_methods(PyObject *d, PyMethodDef *methods);

PYLDAP_DATA(PyStructSequence_Desc) control_tuple_desc;
PYLDAP_DATA(PyTypeObject) control_tuple_type;

PYLDAP_DATA(PyStructSequence_Desc) message_tuple_desc;
PYLDAP_DATA(PyTypeObject) message_tuple_type;

#define PyNone_Check(o) ((o) == Py_None)

/* *** berval *** */
PYLDAP_FUNC(PyObject *) LDAPberval_to_object(const struct berval *bv);
PYLDAP_FUNC(PyObject *) LDAPberval_to_unicode_object(const struct berval *bv);

/* *** constants *** */
PYLDAP_FUNC(int) LDAPinit_constants(PyObject *m);

PYLDAP_DATA(PyObject *) LDAPexception_class;
PYLDAP_FUNC(PyObject *) LDAPerror(LDAP *);
PYLDAP_FUNC(PyObject *) LDAPraise_for_message(LDAP *, LDAPMessage *m);
PYLDAP_FUNC(PyObject *) LDAPerr(int errnum);

#ifndef LDAP_CONTROL_PAGE_OID
#define LDAP_CONTROL_PAGE_OID "1.2.840.113556.1.4.319"
#endif /* !LDAP_CONTROL_PAGE_OID */

#ifndef LDAP_CONTROL_VALUESRETURNFILTER
#define LDAP_CONTROL_VALUESRETURNFILTER "1.2.826.0.1.3344810.2.3"       /* RFC 3876 */
#endif /* !LDAP_CONTROL_VALUESRETURNFILTER */

/* *** functions *** */
PYLDAP_FUNC(void) LDAPinit_functions(PyObject *);

/* *** ldapcontrol *** */
PYLDAP_FUNC(void) LDAPinit_control(PyObject *d);
PYLDAP_FUNC(void) LDAPControl_List_DEL(LDAPControl **);
PYLDAP_FUNC(int) LDAPControls_from_object(PyObject *, LDAPControl ***);
PYLDAP_FUNC(PyObject *) LDAPControls_to_List(LDAPControl **ldcs);

/* *** ldapobject *** */
typedef struct {
    PyObject_HEAD LDAP *ldap;
    PyThreadState *_save;  /* for thread saving on referrals */
    int valid;
} LDAPObject;

PYLDAP_DATA(PyTypeObject) LDAP_Type;
PYLDAP_FUNC(LDAPObject *) newLDAPObject(LDAP *);

/* macros to allow thread saving in the context of an LDAP connection */

#define LDAP_BEGIN_ALLOW_THREADS( l )            \
    {                                            \
      LDAPObject *lo = (l);                      \
      if (lo->_save != NULL)                     \
        Py_FatalError( "saving thread twice?" ); \
      lo->_save = PyEval_SaveThread();           \
    }

#define LDAP_END_ALLOW_THREADS( l )              \
    {                                            \
      LDAPObject *lo = (l);                      \
      PyThreadState *_save = lo->_save;          \
      lo->_save = NULL;                          \
      PyEval_RestoreThread( _save );             \
    }

/* *** messages *** */
PYLDAP_FUNC(PyObject *)
LDAPmessage_to_python(LDAP *ld, LDAPMessage *m, int add_ctrls,
                      int add_intermediates);

/* *** options *** */
PYLDAP_FUNC(int) LDAP_optionval_by_name(const char *name);
PYLDAP_FUNC(int) LDAP_set_option(LDAPObject *self, int option,
                                 PyObject *value);
PYLDAP_FUNC(PyObject *) LDAP_get_option(LDAPObject *self, int option);
PYLDAP_FUNC(void) set_timeval_from_double(struct timeval *tv, double d);

#endif /* pythonldap_h */
