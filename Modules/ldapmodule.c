/* See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "constants.h"
#include "errors.h"
#include "functions.h"
#include "ldapcontrol.h"

#include "LDAPObject.h"

#define _STR(x)	#x
#define STR(x)	_STR(x)

static char version_str[] = STR(LDAPMODULE_VERSION);
static char author_str[] = STR(LDAPMODULE_AUTHOR);
static char license_str[] = STR(LDAPMODULE_LICENSE);

void
LDAPinit_pkginfo( PyObject* d )
{
	PyObject *version;
	PyObject *author;
	PyObject *license;

	version = PyBytes_FromString(version_str);
	author = PyBytes_FromString(author_str);
	license = PyBytes_FromString(license_str);

	PyDict_SetItemString( d, "__version__", version );
	PyDict_SetItemString(d, "__author__", author);
	PyDict_SetItemString(d, "__license__", license);

	Py_DECREF(version);
	Py_DECREF(author);
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

	LDAPinit_pkginfo(d);
	LDAPinit_constants(d);
	LDAPinit_errors(d);
	LDAPinit_functions(d);
	LDAPinit_control(d);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module _ldap");
}
