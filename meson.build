project('spank-olm', 'c', 'cpp',
        version : '1.0.0',
        default_options : [
            'c_std=c11',
            'cpp_std=c++23',
            'b_lto=true',
            'b_thinlto_cache=true',
            'warning_level=3',
            # do a release (optimised) build by default
            'buildtype=release',
            # turn off asserts etc. in release mode
            'b_ndebug=if-release'])

# libFuzzer related things
fuzzing_engine = get_option('fuzzing_engine')
if fuzzing_engine == 'libfuzzer'
    if not cc.has_argument('-fsanitize=fuzzer')
        error('fuzzing_engine libfuzzer requires "-fsanitize=fuzzer"')
    endif
    fuzzer_args = ['-fsanitize=fuzzer-no-link', '-fsanitize=fuzzer']
    add_project_arguments(cc.first_supported_argument(fuzzer_args), language : ['cpp', 'c'])
endif

# Check if we are building for WASM
is_wasm = host_machine.system() == 'emscripten'

# Add specific arguments for WASM
if is_wasm
    add_project_arguments('-s', 'WASM=1', '-s', 'MODULARIZE=1', '-s', 'EXPORT_NAME="createModule"', '-flto', language : 'cpp')
    add_project_link_arguments('-s', 'WASM=1', '-s', 'MODULARIZE=1', '-s', 'EXPORT_NAME="createModule"', '-flto', language : 'cpp')
endif

# Cmake doesnt work with meson, so we need to require pkg-config
botan_dep = dependency('botan-3', version : '>=3.6.0', required : true, method : 'pkg-config')

spank_olm_deps = [botan_dep]

incdir = include_directories('include')
# List of source files
src_files = files('src/spank-olm.cpp', 'src/account.cpp')

spank_olm = library('spank_olm', src_files, install : true, dependencies : spank_olm_deps, include_directories : incdir)

spank_olm_dep = declare_dependency(
    include_directories : incdir,
    link_with : spank_olm,
    dependencies : spank_olm_deps,
)

# Generate and install pkg-config file
pkgconfig = {
    'prefix' : get_option('prefix'),
    'libdir' : get_option('libdir'),
    'includedir' : join_paths(get_option('prefix'), get_option('includedir')),
    'name' : 'spank-olm',
    'description' : 'A C++ library based on libolm',
    'version' : meson.project_version(),
    'requires' : 'botan-3',
    'libs' : '-L${libdir} -lspank_olm',
    'cflags' : '-I${includedir}/spank-olm'
}

configure_file(
    input : 'misc/spank-olm.pc.in',
    output : 'spank-olm.pc',
    configuration : pkgconfig,
    install : true,
    install_dir : join_paths(get_option('libdir'), 'pkgconfig')
)

if get_option('build_tests')
    snitch_dep = dependency('snitch')

    test('list_test', executable('list_test', 'tests/list_test.cpp', dependencies : [snitch_dep, spank_olm_dep], include_directories : incdir))
    test('account_test', executable('account_test', 'tests/account_test.cpp', dependencies : [snitch_dep, spank_olm_dep], include_directories : incdir))
endif

subdir('fuzz')