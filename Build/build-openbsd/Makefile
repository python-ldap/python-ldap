# $Id: Makefile,v 1.5 2014/11/18 08:28:48 stroeder Exp $

WRKDIST=		${.CURDIR}/../..
VERSION!=		sh ${WRKDIST}/Build/version.sh

PKGNAME=		python-ldap-${VERSION}
RUN_DEPENDS=		python:lang/python
CATEGORIES=		misc
MAINTAINER=		leonard@users.sourceforge.net
HOMEPAGE=		http://www.python-ldap.org/

FAKE=			Yes
CONFIGURE_STYLE=	gnu
SEPARATE_BUILD=		Yes
EXTRACT_ONLY=	

CONFIGURE_ARGS+=	--with-ldap=${LOCALBASE}

do-fetch:;

#-- put package on sourceforge ftp server
export-ftp: ${PKGFILE}
	scp ${PKGFILE} python-ldap.sourceforge.net:/home/groups/ftp/pub/python-ldap/${PKGNAME}-${OPSYS}-${ARCH}${PKG_SUFX}

post-build:
	sed -e 's,^${PREFIX}/,,' <${WRKBUILD}/filelist >${WRKBUILD}/filelist2

SED_PLIST+=	|sed -e '/^%%filelist/r${WRKBUILD}/filelist2' -e '//d'
ALL_TARGET=	build filelist

.include <bsd.port.mk>
