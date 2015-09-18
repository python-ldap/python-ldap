"""
ldap.resiter - processing LDAP results with iterators

See http://www.python-ldap.org/ for details.

\$Id: resiter.py,v 1.7 2015/09/18 20:20:32 stroeder Exp $

Python compability note:
Requires Python 2.3+
"""


class ResultProcessor:
  """
  Mix-in class used with ldap.ldapopbject.LDAPObject or derived classes.
  """

  def allresults(self,msgid,timeout=-1,add_ctrls=0):
    """
    Generator function which returns an iterator for processing all LDAP operation
    results of the given msgid retrieved with LDAPObject.result3() -> 4-tuple
    """
    result_type,result_list,result_msgid,result_serverctrls,_,_ = self.result4(msgid,0,timeout,add_ctrls=add_ctrls)
    while result_type and result_list:
      # Loop over list of search results
      for result_item in result_list:
        yield (result_type,result_list,result_msgid,result_serverctrls)
      result_type,result_list,result_msgid,result_serverctrls,_,_ = self.result4(msgid,0,timeout,add_ctrls=add_ctrls)
    return # allresults()
