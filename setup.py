"""
setup.py - C extension module configuration for python-ldap

See https://www.python-ldap.org/ for details.
This file handles only the C extension modules (_ldap) configuration,
while pyproject.toml handles all project metadata, dependencies, and other settings.
"""

import sys,os,sysconfig
from setuptools import setup, Extension

if sys.version_info < (3, 6):
  raise RuntimeError(
    'The C API from Python 3.6+ is required, found %s' % sys.version_info
  )

from configparser import ConfigParser

sys.path.insert(0, os.path.join(os.getcwd(), 'Lib/ldap'))
import pkginfo

SETUP_OPTIONS = {}

#-- Limited API configuration:
# Currently some of the symbols we rely on did not appear in the Limited API
# until later. Also free-threading is not in the Limited API in any Pythons
# yet. We have to take all of these into account, allow Stable ABI for 3.13+,
# but do not disallow building on 3.9+.
LIMITED_API_FLOOR = 0x030D0000
LIMITED_API_TAG = 'cp313'

def use_limited_api():
  """
  Decide whether to build against the limited API (Stable ABI)

  Also allow targeting a specific version if PYTHON_LDAP_NO_LIMITED_API is
  nonempty.
  """
  if os.environ.get('PYTHON_LDAP_NO_LIMITED_API'):
    return False
  if sysconfig.get_config_var('Py_GIL_DISABLED'):
    return False
  return sys.hexversion >= LIMITED_API_FLOOR

LIMITED_API = use_limited_api()
if LIMITED_API:
  SETUP_OPTIONS |= {"bdist_wheel": {"py_limited_api": LIMITED_API_TAG}}

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

#-- C extension modules configuration only
setup(
  ext_modules = [
    Extension(
      '_ldap',
      [
        'Modules/LDAPObject.c',
        'Modules/ldapcontrol.c',
        'Modules/common.c',
        'Modules/constants.c',
        'Modules/functions.c',
        'Modules/ldapmodule.c',
        'Modules/message.c',
        'Modules/options.c',
        'Modules/berval.c',
      ],
      depends = [
        'Modules/pythonldap.h',
        'Modules/constants_generated.h',
      ],
      libraries = LDAP_CLASS.libs,
      include_dirs = ['Modules'] + LDAP_CLASS.include_dirs,
      library_dirs = LDAP_CLASS.library_dirs,
      extra_compile_args = LDAP_CLASS.extra_compile_args,
      extra_link_args = LDAP_CLASS.extra_link_args,
      extra_objects = LDAP_CLASS.extra_objects,
      runtime_library_dirs = (not sys.platform.startswith("win"))*LDAP_CLASS.library_dirs,
      py_limited_api = LIMITED_API,
      define_macros = LDAP_CLASS.defines + \
        ('sasl' in LDAP_CLASS.libs or 'sasl2' in LDAP_CLASS.libs or 'libsasl' in LDAP_CLASS.libs)*[('HAVE_SASL',None)] + \
        ('ssl' in LDAP_CLASS.libs and 'crypto' in LDAP_CLASS.libs)*[('HAVE_TLS',None)] + \
        LIMITED_API*[('Py_LIMITED_API', hex(LIMITED_API_FLOOR).upper())] + \
        [
          ('LDAPMODULE_VERSION', pkginfo.__version__),
          ('LDAPMODULE_AUTHOR', pkginfo.__author__),
          ('LDAPMODULE_LICENSE', pkginfo.__license__),
        ]
    ),
  ],
  options = SETUP_OPTIONS,
)
