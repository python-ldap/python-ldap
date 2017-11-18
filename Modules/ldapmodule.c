/* See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "constants.h"
#include "errors.h"
#include "functions.h"
#include "ldapcontrol.h"

#include "LDAPObject.h"

#define _STR(x)        #x
#define STR(x) _STR(x)

static char version_str[] = STR(LDAPMODULE_VERSION);
static char author_str[] = STR(LDAPMODULE_AUTHOR);
static char license_str[] = STR(LDAPMODULE_LICENSE);

void
init_pkginfo( PyObject* d )
{
	PyObject *version;
	PyObject *author;
	PyObject *license;

	version = PyString_FromString(version_str);
	PyDict_SetItemString( d, "__version__", version );
	Py_DECREF(version);

  author = PyString_FromString(author_str);
  PyDict_SetItemString(d, "__author__", author);
  Py_DECREF(author);

  license = PyString_FromString(license_str);
  PyDict_SetItemString(d, "__license__", license);
  Py_DECREF(license);

}

DL_EXPORT(void) init_ldap(void);

/* dummy module methods */

static PyMethodDef methods[]  = {
	{ NULL, NULL }
};

/* module initialisation */

DL_EXPORT(void)
init_ldap()
{
	PyObject *m, *d;

#if defined(MS_WINDOWS) || defined(__CYGWIN__)
	LDAP_Type.ob_type = &PyType_Type;
#endif

	/* Create the module and add the functions */
	m = Py_InitModule("_ldap", methods);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);

	init_pkginfo(d);
	LDAPinit_constants(d);
	LDAPinit_errors(d);
	LDAPinit_functions(d);
	LDAPinit_control(d);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module _ldap");
}
