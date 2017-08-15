# $Id: Makefile,v 1.6 2017/08/15 16:21:58 stroeder Exp $

WRKDIST=		${.CURDIR}/../..
VERSION!=		sh ${WRKDIST}/Build/version.sh

PKGNAME=		python-ldap-${VERSION}
RUN_DEPENDS=		python:lang/python
CATEGORIES=		misc
MAINTAINER=		leonard@users.sourceforge.net
HOMEPAGE=		https://www.python-ldap.org/

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
