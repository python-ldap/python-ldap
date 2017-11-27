"""
setup.py - Setup package with the help Python's DistUtils

See https://www.python-ldap.org/ for details.
"""

import sys,os

has_setuptools = False
try:
  from setuptools import setup, Extension
  has_setuptools = True
except ImportError:
  from distutils.core import setup, Extension

if sys.version_info[0] == 2 and sys.version_info[1] < 7:
    raise RuntimeError('This software requires Python 2.7 or 3.x.')
if sys.version_info[0] >= 3 and sys.version_info < (3, 3):
    raise RuntimeError('The C API from Python 3.3+ is required.')

if sys.version_info[0] >= 3:
    from configparser import ConfigParser
else:
    from ConfigParser import ConfigParser

sys.path.insert(0, os.path.join(os.getcwd(), 'Lib/ldap'))
import pkginfo

#-- A class describing the features and requirements of OpenLDAP 2.0
class OpenLDAP2:
  library_dirs = []
  include_dirs = []
  extra_compile_args = []
  extra_link_args = []
  extra_objects = []
  libs = ['ldap', 'lber']
  defines = []
  extra_files = []

LDAP_CLASS = OpenLDAP2

#-- Read the [_ldap] section of setup.cfg
cfg = ConfigParser()
cfg.read('setup.cfg')
if cfg.has_section('_ldap'):
  for name in dir(LDAP_CLASS):
    if cfg.has_option('_ldap', name):
      setattr(LDAP_CLASS, name, cfg.get('_ldap', name).split())

for i in range(len(LDAP_CLASS.defines)):
  LDAP_CLASS.defines[i]=((LDAP_CLASS.defines[i],None))

for i in range(len(LDAP_CLASS.extra_files)):
  destdir, origfiles = LDAP_CLASS.extra_files[i].split(':')
  origfileslist = origfiles.split(',')
  LDAP_CLASS.extra_files[i]=(destdir, origfileslist)

if os.environ.get('WITH_GCOV'):
  # Instrumentation for measuring code coverage
  LDAP_CLASS.extra_compile_args.extend(
    ['-O0', '-pg', '-fprofile-arcs', '-ftest-coverage']
  )
  LDAP_CLASS.extra_link_args.append('-pg')
  LDAP_CLASS.libs.append('gcov')

#-- Let distutils/setuptools do the rest
name = 'python-ldap'

# Python 2.3.6+ and setuptools are needed to build eggs, so
# let's handle setuptools' additional  keyword arguments to
# setup() in a fashion that doesn't break compatibility  to
# distutils. This still allows 'normal' builds where either
# Python > 2.3.5 or setuptools (or both ;o) are not available.
kwargs = dict()
if has_setuptools:
  kwargs = dict(
    include_package_data = True,
    install_requires = [
        'setuptools',
        'pyasn1 >= 0.3.7',
        'pyasn1_modules >= 0.1.5',
    ],
    zip_safe = False,
    python_requires = '>=2.7,!=3.0.*,!=3.1.*,!=3.2.*',
  )

setup(
  #-- Package description
  name = name,
  license=pkginfo.__license__,
  version=pkginfo.__version__,
  description = 'Python modules for implementing LDAP clients',
  long_description = """python-ldap:
  python-ldap provides an object-oriented API to access LDAP directory servers
  from Python programs. Mainly it wraps the OpenLDAP 2.x libs for that purpose.
  Additionally the package contains modules for other LDAP-related stuff
  (e.g. processing LDIF, LDAPURLs, LDAPv3 schema, LDAPv3 extended operations
  and controls, etc.). 
  """,
  author = 'python-ldap project',
  author_email = 'python-ldap@python.org',
  url = 'https://www.python-ldap.org/',
  download_url = 'https://pypi.python.org/pypi/python-ldap/',
  classifiers = [
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
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    # Note: when updating Python versions, also change .travis.yml and tox.ini

    'Topic :: Database',
    'Topic :: Internet',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP',
    'License :: OSI Approved :: Python Software Foundation License',
  ],
  #-- C extension modules
  ext_modules = [
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
      libraries = LDAP_CLASS.libs,
      include_dirs = ['Modules'] + LDAP_CLASS.include_dirs,
      library_dirs = LDAP_CLASS.library_dirs,
      extra_compile_args = LDAP_CLASS.extra_compile_args,
      extra_link_args = LDAP_CLASS.extra_link_args,
      extra_objects = LDAP_CLASS.extra_objects,
      runtime_library_dirs = (not sys.platform.startswith("win"))*LDAP_CLASS.library_dirs,
      define_macros = LDAP_CLASS.defines + \
        ('ldap_r' in LDAP_CLASS.libs or 'oldap_r' in LDAP_CLASS.libs)*[('HAVE_LIBLDAP_R',None)] + \
        ('sasl' in LDAP_CLASS.libs or 'sasl2' in LDAP_CLASS.libs or 'libsasl' in LDAP_CLASS.libs)*[('HAVE_SASL',None)] + \
        ('ssl' in LDAP_CLASS.libs and 'crypto' in LDAP_CLASS.libs)*[('HAVE_TLS',None)] + \
        [
          ('LDAPMODULE_VERSION', pkginfo.__version__),
          ('LDAPMODULE_AUTHOR', pkginfo.__author__),
          ('LDAPMODULE_LICENSE', pkginfo.__license__),
        ]
    ),
  ],
  #-- Python "stand alone" modules
  py_modules = [
    'ldapurl',
    'ldif',
    'slapdtest',
  ],
  packages = [
    'ldap',
    'ldap.controls',
    'ldap.extop',
    'ldap.schema',
  ],
  package_dir = {'': 'Lib',},
  data_files = LDAP_CLASS.extra_files,
  test_suite = 'Tests',
  **kwargs
)
