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
    add_project_arguments('-flto', language : 'cpp')
    add_project_link_arguments('-flto', '-lembind', '-sEMBIND_AOT=1', '-sEXPORT_ES6=1', '-sMODULARIZE=1', '-sENVIRONMENT=web,worker', '-sEXPORT_NAME=SpankOlmLibrarys', '-sFILESYSTEM=0', '-sEXPORT_ALL=1', '--emit-tsd=interface.d.ts', language : 'cpp')
endif

# Cmake doesnt work with meson, so we need to require pkg-config
if is_wasm
    # Custom path for libbotan-3.a when targeting WASM
    botan_wasm_path = get_option('botan_wasm_path')
    botan_include_path = get_option('botan_include_path')
    botan_incdir = include_directories(botan_include_path)
    cc = meson.get_compiler('c')
    botan_dep = cc.find_library('botan-3', dirs : meson.global_source_root() / botan_wasm_path, required : true, static : true)
    botan_dep = declare_dependency(dependencies : botan_dep, include_directories : botan_incdir)
else
    botan_dep = dependency('botan-3', version : '>=3.6.0', required : true, method : 'pkg-config')
endif

spank_olm_deps = [botan_dep]

incdir = include_directories('include')
# List of source files
src_files = files(
    'src/spank-olm.cpp',
    'src/account.cpp',
    'src/megolm.cpp',
    'src/pickle.cpp', )

if is_wasm
    spank_olm = executable('spank_olm', src_files, install : true, dependencies : spank_olm_deps, include_directories : incdir, override_options : ['b_lto=false'])
else
    spank_olm = library('spank_olm', src_files, install : true, dependencies : spank_olm_deps, include_directories : incdir)
endif

spank_olm_dep = declare_dependency(
    include_directories : incdir,
    link_with : spank_olm,
    dependencies : spank_olm_deps,
)

if get_option('build_tests') and not is_wasm
    snitch_dep = dependency('snitch')

    test('list_test', executable('list_test', 'tests/list_test.cpp', dependencies : [snitch_dep, spank_olm_dep], include_directories : incdir))
    test('account_test', executable('account_test', 'tests/account_test.cpp', dependencies : [snitch_dep, spank_olm_dep], include_directories : incdir))
endif

# Only build if we are not building wasm
if not is_wasm
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

    subdir('fuzz')
endif