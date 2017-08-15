/* See https://www.python-ldap.org/ for details.
 * $Id: errors.h,v 1.7 2017/08/15 16:21:59 stroeder Exp $ */

#ifndef __h_errors_
#define __h_errors_

#include "common.h"
#include "lber.h"
#include "ldap.h"

extern PyObject* LDAPexception_class;
extern PyObject* LDAPerror( LDAP*, char*msg );
extern void LDAPinit_errors( PyObject* );
PyObject* LDAPerr(int errnum);

#endif /* __h_errors */
