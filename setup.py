"""
setup.py - Setup package with the help Python's DistUtils

See https://www.python-ldap.org/ for details.
"""

import sys
import os
import pprint
from ConfigParser import ConfigParser

# Python 2.3.6+ and setuptools are needed to build eggs, so
# let's handle setuptools' additional  keyword arguments to
# setup() in a fashion that doesn't break compatibility  to
# distutils. This still allows 'normal' builds where either
# Python > 2.3.5 or setuptools (or both ;o) are not available.
try:
    from setuptools import setup, Extension
except ImportError:
    from distutils.core import setup, Extension
    setup_kwargs = dict()
else:
    setup_kwargs = dict(
        include_package_data=True,
        install_requires=['setuptools'],
        zip_safe=False
    )

sys.path.insert(0, os.path.join(os.getcwd(), 'Lib/ldap'))
import pkginfo


class OpenLDAP2BuildConfig:
    """
    class describing the features and requirements of OpenLDAP 2.x
    """

    def __init__(self, meta_defines):
        self.library_dirs = []
        self.include_dirs = []
        self.extra_compile_args = []
        self.extra_link_args = []
        self.extra_objects = []
        self.libs = ['ldap', 'lber']
        self.defines = []
        self.extra_files = []
        #-- Read the [_ldap] section of setup.cfg
        cfg = ConfigParser()
        cfg.read('setup.cfg')
        _ldap_cfg = dict(cfg.items('_ldap'))
        for name, value in _ldap_cfg.items():
            _ldap_cfg[name] = filter(None, value.split(' '))
        # split values of extra_files
        if 'extra_files' in _ldap_cfg:
            for i in range(len(_ldap_cfg['extra_files'])):
                destdir, origfiles = self.extra_files[i].split(':')
                origfileslist = origfiles.split(',')
                _ldap_cfg['extra_files'][i] = (destdir, origfileslist)
        #pprint.pprint(_ldap_cfg)
        for name, val in _ldap_cfg.items():
            setattr(self, name, val)
        if 'ldap_r' in self.libs or 'oldap_r' in self.libs:
            self.defines.append('HAVE_LIBLDAP_R')
        if 'sasl' in self.libs or 'sasl2' in self.libs or 'libsasl' in self.libs:
            self.defines.append('HAVE_SASL')
        if 'ssl' in self.libs and 'crypto' in self.libs:
            self.defines.append('HAVE_TLS')
        self.define_macros = [
            (defm,)
            for defm in set(self.defines)
        ]
        self.define_macros.extend(meta_defines)
        self.include_dirs.insert(0, 'Modules')
        if sys.platform.startswith("win"):
            self.library_dirs = []


LDAP_CLASS = OpenLDAP2BuildConfig(
    [
        ('LDAPMODULE_VERSION', pkginfo.__version__),
        ('LDAPMODULE_AUTHOR', pkginfo.__author__),
        ('LDAPMODULE_LICENSE', pkginfo.__license__),
    ],
)

pprint.pprint(LDAP_CLASS.__dict__)


#-- Let distutils/setuptools do the rest

setup(
    name='python-ldap',
    license=pkginfo.__license__,
    version=pkginfo.__version__,
    description='Python modules for implementing LDAP clients',
    long_description="""python-ldap:
    python-ldap provides an object-oriented API to access LDAP directory servers
    from Python programs. Mainly it wraps the OpenLDAP 2.x libs for that purpose.
    Additionally the package contains modules for other LDAP-related stuff
    (e.g. processing LDIF, LDAPURLs, LDAPv3 schema, LDAPv3 extended operations
    and controls, etc.).
    """,
    author=pkginfo.__author__,
    author_email='python-ldap@python.org',
    url='https://www.python-ldap.org/',
    download_url='https://pypi.python.org/pypi/python-ldap/',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Topic :: Database',
        'Topic :: Internet',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
        'License :: OSI Approved :: Python Software Foundation License',
    ],
    #-- C extension modules
    ext_modules=[
        Extension(
            '_ldap',
            [
                'Modules/LDAPObject.c',
                'Modules/ldapcontrol.c',
                'Modules/common.c',
                'Modules/constants.c',
                'Modules/errors.c',
                'Modules/functions.c',
                'Modules/ldapmodule.c',
                'Modules/message.c',
                'Modules/options.c',
                'Modules/berval.c',
            ],
            libraries=LDAP_CLASS.libs,
            include_dirs=LDAP_CLASS.include_dirs,
            library_dirs=LDAP_CLASS.library_dirs,
            extra_compile_args=LDAP_CLASS.extra_compile_args,
            extra_link_args=LDAP_CLASS.extra_link_args,
            extra_objects=LDAP_CLASS.extra_objects,
            runtime_library_dirs=LDAP_CLASS.library_dirs,
            define_macros=LDAP_CLASS.define_macros,
        ),
    ],
    #-- Python "stand alone" modules
    py_modules=[
        'ldapurl',
        'ldif',
        'ldap',
        'slapdtest',
        'ldap.async',
        'ldap.controls',
        'ldap.controls.deref',
        'ldap.controls.libldap',
        'ldap.controls.openldap',
        'ldap.controls.ppolicy',
        'ldap.controls.psearch',
        'ldap.controls.pwdpolicy',
        'ldap.controls.readentry',
        'ldap.controls.sessiontrack',
        'ldap.controls.simple',
        'ldap.controls.sss',
        'ldap.controls.vlv',
        'ldap.cidict',
        'ldap.dn',
        'ldap.extop',
        'ldap.extop.dds',
        'ldap.filter',
        'ldap.functions',
        'ldap.ldapobject',
        'ldap.ldapobject.simple',
        'ldap.ldapobject.reconnect',
        'ldap.logger',
        'ldap.modlist',
        'ldap.pkginfo',
        'ldap.resiter',
        'ldap.sasl',
        'ldap.schema',
        'ldap.schema.models',
        'ldap.schema.subentry',
        'ldap.schema.tokenizer',
        'ldap.syncrepl',
    ],
    package_dir={'': 'Lib'},
    data_files=LDAP_CLASS.extra_files,
    test_suite='Tests',
    **setup_kwargs
)
