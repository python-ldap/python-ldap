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

#if LDAP_VENDOR_VERSION >= 20700
  /* openldap.h made ldap_pvt_put_filter() public in 2.7.x
   * see https://bugs.openldap.org/show_bug.cgi?id=9393
   */
#else
  /* ldap_pvt_put_filter() has existed since OpenLDAP 2.1, but was only
   * declared in the private ldap_pvt.h header before OpenLDAP 2.7.
   */
LDAP_F(int) ldap_pvt_put_filter LDAP_P((BerElement *ber, const char *str));
#endif

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

/* *** berval *** */
PYLDAP_FUNC(PyObject *) LDAPberval_to_object(const struct berval *bv);
PYLDAP_FUNC(PyObject *) LDAPberval_to_unicode_object(const struct berval *bv);

/* *** constants *** */
PYLDAP_FUNC(int) LDAPMod_init_constants(PyObject *m);

struct LDAPModState;

PYLDAP_FUNC(PyObject *) LDAPerror(PyObject *module, LDAP *l);
PYLDAP_FUNC(PyObject *) LDAPraise_for_message(PyObject *module, LDAP *l, LDAPMessage *m);
PYLDAP_FUNC(PyObject *) LDAPerr(PyObject *module, int errnum);

PYLDAP_DATA(struct PyModuleDef *) LDAPMod_moduledef;
PYLDAP_DATA(LDAPAPIInfo) LDAPMod_version_info;
PYLDAP_DATA(int) LDAPMod_thread_safe;

#ifndef LDAP_CONTROL_PAGE_OID
#define LDAP_CONTROL_PAGE_OID "1.2.840.113556.1.4.319"
#endif /* !LDAP_CONTROL_PAGE_OID */

#ifndef LDAP_CONTROL_VALUESRETURNFILTER
#define LDAP_CONTROL_VALUESRETURNFILTER "1.2.826.0.1.3344810.2.3"       /* RFC 3876 */
#endif /* !LDAP_CONTROL_VALUESRETURNFILTER */

/* *** module level state *** */
typedef struct LDAPModState {
    PyTypeObject *ldap_type;
    PyObject *exception_class;
    PyObject *errobjects[LDAP_ERROR_MAX - LDAP_ERROR_MIN + 1];
} LDAPModState;

/* *** ldapcontrol *** */
PYLDAP_FUNC(void) LDAPControl_List_DEL(LDAPControl **);
PYLDAP_FUNC(int) LDAPControls_from_object(PyObject *, LDAPControl ***);
PYLDAP_FUNC(PyObject *) LDAPControls_to_List(LDAPControl **ldcs);
PYLDAP_FUNC(PyObject *) LDAPMod_encode_rfc2696(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_decode_rfc2696(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_encode_rfc3876(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_encode_assertion_control(PyObject *, PyObject *);

/* *** ldapobject *** */
typedef struct {
    PyObject_HEAD LDAP *ldap;
    PyThreadState *_save;  /* for thread saving on referrals */
    int valid;
} LDAPObject;

PYLDAP_FUNC(LDAPObject *) newLDAPObject(PyObject *, LDAP *);
PYLDAP_FUNC(int) LDAPMod_init_type(PyObject *module);

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
LDAPmessage_to_python(PyObject *module, LDAP *ld, LDAPMessage *m,
                      int add_ctrls, int add_intermediates);

/* *** options *** */
PYLDAP_FUNC(int) LDAP_optionval_by_name(const char *name);
PYLDAP_FUNC(int) LDAP_set_option(LDAPObject *self, int option,
                                 PyObject *value);
PYLDAP_FUNC(PyObject *) LDAP_get_option(LDAPObject *self, int option);
PYLDAP_FUNC(void) set_timeval_from_double(struct timeval *tv, double d);

/* *** functions *** */
PYLDAP_FUNC(PyObject *) LDAPMod_initialize(PyObject *, PyObject *);
#ifdef HAVE_LDAP_INIT_FD
PYLDAP_FUNC(PyObject *) LDAPMod_initialize_fd(PyObject *, PyObject *);
#endif
PYLDAP_FUNC(PyObject *) LDAPMod_str2dn(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_dn2str(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_set_option(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_get_option(PyObject *, PyObject *);
PYLDAP_FUNC(PyObject *) LDAPMod_is_filter(PyObject *, PyObject *);

#endif /* pythonldap_h */
