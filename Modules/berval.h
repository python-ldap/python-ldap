/* See https://www.python-ldap.org/ for details.
 * $Id: berval.h,v 1.2 2017/08/15 16:21:59 stroeder Exp $ */

#ifndef __h_berval 
#define __h_berval 

#include "common.h"
#include "lber.h"

int  LDAPberval_from_object(PyObject *obj, struct berval *bv);
int  LDAPberval_from_object_check(PyObject *obj);
void LDAPberval_release(struct berval *bv);
PyObject *LDAPberval_to_object(const struct berval *bv);

#endif /* __h_berval_ */
