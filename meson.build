project('spank-olm', 'cpp',
        version : '1.0.0',
        default_options : ['warning_level=3',
                           'cpp_std=c++23',
                           'b_lto=true',
                           'b_thinlto_cache=true',
                           'warning_level=3',])

# libFuzzer related things
fuzzing_engine = get_option('fuzzing_engine')
if fuzzing_engine == 'libfuzzer'
    if not cc.has_argument('-fsanitize=fuzzer')
        error('fuzzing_engine libfuzzer requires "-fsanitize=fuzzer"')
    endif
    fuzzer_args = ['-fsanitize=fuzzer-no-link', '-fsanitize=fuzzer']
    add_project_arguments(cc.first_supported_argument(fuzzer_args), language : ['cpp', 'c'])
endif

# Cmake doesnt work with meson, so we need to require pkg-config
botan_dep = dependency('botan-3', version : '>=3.6.0', required : true, method : 'pkg-config')

spank_olm_deps = [botan_dep]

incdir = include_directories('include')
spank_olm = library('spank_olm', 'src/slap-olm.cpp', install : true, dependencies : spank_olm_deps, include_directories : incdir)

spank_olm_dep = declare_dependency(
    link_with: spank_olm,
    dependencies: spank_olm_deps,
)

snitch_dep = dependency('snitch')

test('test', executable('spank-olm-test','tests/test.cpp',dependencies:snitch_dep, link_with : spank_olm))

subdir('fuzz')