project('DRAKVUF (C) Tamas K Lengyel 2014-2024', 'c', 'cpp',
        version : '1.1',
        default_options : [
            'cpp_std=c++17',
            'buildtype=release',
            'strip=true',
            'default_library=static',
            'warning_level=2',
            'werror=true',
            'b_pie=true',
            'b_lto=true',
            'b_lto_mode=thin',
            'b_thinlto_cache=true',
            'b_ndebug=if-release'
        ]
)

# Check if C++ compiler is suitable
code='''int main(void) { bool test[2] = { [1] = 1, [0] = 0 }; return 0; }'''
if meson.get_compiler('cpp').compiles(code) == false
    error('Unsupported C++ compiler, please install clang')
endif


cmake = import('cmake')
sub_proj = cmake.subproject('redis-plus-plus')
cm_lib = sub_proj.dependency('redis++')

# Find dependencies
glib = dependency('glib-2.0')
libvmi = dependency('libvmi')
jsonc = dependency('json-c')
hiredis = dependency('hiredis')

deps = [glib, libvmi, jsonc, hiredis, cm_lib]

version = meson.project_version()
if not get_option('release')
    version += '-' + run_command('git', 'describe', '--always', check: true).stdout().strip()
endif

# Setup for generating config.h
add_project_arguments('-DHAVE_CONFIG_H', language : ['c', 'cpp'])
config_h = configuration_data()
config_h.set_quoted('PACKAGE_NAME','DRAKVUF')
config_h.set_quoted('PACKAGE_VERSION', version)

# Ignore these warnings
add_project_arguments('-Wno-c99-designator', language : ['cpp'])
add_project_arguments('-Wno-reorder-init-list', language : ['cpp'])
add_project_arguments('-Wno-unknown-warning-option', language : ['cpp'])
add_project_arguments('-Wno-unused-parameter', language : ['c', 'cpp'])
add_project_arguments('-Wno-missing-field-initializers', language : ['c', 'cpp'])
add_project_arguments('-Wno-packed', language : ['c', 'cpp'])

# Declare additional debug flags
if get_option('buildtype').startswith('debug')
    add_project_arguments('-DDRAKVUF_DEBUG', language : ['c', 'cpp'])
    add_project_arguments('-ggdb3', language : ['c', 'cpp'])
    add_project_arguments('-Wformat', language : ['c', 'cpp'])
    add_project_arguments('-Wformat-security', language : ['c', 'cpp'])
    add_project_arguments('-Wferror-limit=0', language : ['cpp'])
    add_project_arguments('-Wcast-qual', language : ['cpp'])
    add_project_arguments('-Wcast-align', language : ['cpp'])
    add_project_arguments('-Wstrict-aliasing', language : ['cpp'])
    add_project_arguments('-Wpointer-arith', language : ['cpp'])
    add_project_arguments('-Winit-self', language : ['cpp'])
    add_project_arguments('-Wshadow', language : ['cpp'])
    add_project_arguments('-Wredundant-decls', language : ['cpp'])
    add_project_arguments('-Wfloat-equal', language : ['cpp'])
    add_project_arguments('-Wundef', language : ['cpp'])
    add_project_arguments('-Wvla', language : ['cpp'])
endif

# Runtime hardening
hardened_link_args=[]
if get_option('hardening')
    add_project_arguments('-Wno-strict-overflow', language : ['c', 'cpp'])
    add_project_arguments('-D_FORTIFY_SOURCE=2', language : ['c', 'cpp'])
    add_project_arguments('-fstack-protector-all', language : ['c', 'cpp'])
    add_project_arguments('--param', language : ['c', 'cpp'])
    add_project_arguments('ssp-buffer-size=1', language : ['c', 'cpp'])

    hardened_link_args += '-Wl,-z,noexecstack'
    hardened_link_args += '-Wl,-z,relro'
    hardened_link_args += '-Wl,-z,now'
    config_h.set('HARDENING', 1)
endif

if get_option('threadsafety')
    config_h.set('ENABLE_THREADSAFETY', 1)
endif

summary({
    'Build': version,
}, section: 'Version')

# Load meson.build from subdirs
subdir('src/xen_helper')
subdir('src/libdrakvuf')
subdir('src/libinjector')
subdir('src/libusermode')
subdir('src/libhook')
subdir('src/librepl')
subdir('src/plugins')

if get_option('ipt')
    config_h.set('ENABLE_IPT', 1)
endif

# Generate config.h
configure_file(output : 'config.h',
               configuration : config_h)

# Generate executables
incdir = include_directories('.', 'src')

executable('drakvuf',
    'src/main.cpp',
    'src/drakvuf.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : [libdrakvuf, drakvuf_plugins, libinjector],
    link_args : hardened_link_args,
    install : true,
)

executable('injector',
    'src/injector.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : [libdrakvuf, libinjector],
    link_args : hardened_link_args,
    install : true,
)

executable('proc_stat',
    'src/proc_stat.cpp',

    include_directories : incdir,
    dependencies : deps,
    link_language : 'cpp',
    link_with : libdrakvuf,
    link_args : hardened_link_args
)

if get_option('xtf')
    executable('xtf',
               'src/xtf.c',

               include_directories : incdir,
               dependencies : deps,
               link_with : libdrakvuf,
    )
endif

if get_option('repl')
    executable('repl',
               'src/repl.cpp',

               include_directories : incdir,
               dependencies : deps,
               link_with : [libdrakvuf, librepl]
    )
endif

summary({
    'buildtype': get_option('buildtype'),
    'Hardening': get_option('hardening'),
    'XTF': get_option('xtf'),
    'REPL': get_option('repl'),
    'IPT': get_option('ipt'),
}, section: 'Configuration')

summary({
    'prefix/bindir': get_option('prefix') + '/' + get_option('bindir'),
}, section: 'Install path')
