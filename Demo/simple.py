#!/usr/bin/env python3
import sys,getpass
import ldap

#l = ldap.open("localhost", 31001)
l = ldap.open("marta.it.uq.edu.au")

login_dn = "cn=root,ou=CSEE,o=UQ,c=AU"
login_pw = getpass.getpass("Password for %s: " % login_dn)
l.simple_bind_s(login_dn, login_pw)

#
# create a new sub organisation
#

try:
    dn = "ou=CSEE,o=UQ,c=AU"
    print("Adding", repr(dn))
    l.add_s(dn,
	 [
	    ("objectclass",[b"organizationalUnit"]),
	    ("ou", [b"CSEE"]),
	    ("description", [
		    b"Department of Computer Science and Electrical Engineering"]),
	 ]
       )

except ldap.LDAPError:
    pass

#
# create an entry for me
#

dn = "cn=David Leonard,ou=CSEE,o=UQ,c=AU"
print("Updating", repr(dn))

try:
	l.delete_s(dn)
except ldap.LDAPError:
	pass

with open("/www/leonard/leonard.jpg", "rb") as jpeg_photo_file:
    jpeg_photo = jpeg_photo_file.read()

l.add_s(dn,
     [
	("objectclass", [b"organizationalPerson"]),
	("sn", [b"Leonard"]),
	("cn", [b"David Leonard"]),
	("description", [b"Ph.D. student"]),
	("display-name", [b"David Leonard"]),
	#("commonname", [b"David Leonard"]),
	("mail", [b"david.leonard@csee.uq.edu.au"]),
	("othermailbox", [b"d@openbsd.org"]),
	("givenname", [b"David"]),
	("surname", [b"Leonard"]),
	("seeAlso", [b"http://www.csee.uq.edu.au/~leonard/"]),
	("url", [b"http://www.csee.uq.edu.au/~leonard/"]),
	#("homephone", []),
	#("fax", []),
	#("otherfacsimiletelephonenumber",[]),
	#("officefax", []),
	#("mobile", []),
	#("otherpager", []),
	#("officepager", []),
	#("pager", []),
	("info", [b"info"]),
	("title", [b"Mr"]),
	#("telephonenumber", []),
	("l", [b"Brisbane"]),
	("st", [b"Queensland"]),
	("c", [b"AU"]),
	("co", [b"co"]),
	("o", [b"UQ"]),
	("ou", [b"CSEE"]),
	#("homepostaladdress", []),
	#("postaladdress", []),
	#("streetaddress", []),
	#("street", []),
	("department", [b"CSEE"]),
	("comment", [b"comment"]),
	#("postalcode", []),
	("physicaldeliveryofficename",  ["Bldg 78, UQ, St Lucia"]),
	("preferredDeliveryMethod", [b"email"]),
	("initials", [b"DRL"]),
	("conferenceinformation", [b"MS-conferenceinformation"]),
	#("usercertificate", []),
	("labeleduri", [b"labeleduri"]),
	("manager", [b"cn=Jaga Indulska"]),
	("reports", [b"reports"]),
	("jpegPhoto", [jpeg_photo]),
	("uid", [b"leonard"]),
	("userPassword", [b""])

    ])

#
# search beneath the CSEE/UQ/AU tree
#

res = l.search_s(
	"ou=CSEE, o=UQ, c=AU",
	ldap.SCOPE_SUBTREE,
	"objectclass=*",
      )
print(res)

l.unbind()
