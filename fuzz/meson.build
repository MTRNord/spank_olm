fuzz_deps = spank_olm_deps
fuzz_ldflags = []

if get_option('fuzzer_ldflags') != ''
    fuzz_ldflags += [get_option('fuzzer_ldflags')]
endif

if fuzzing_engine == 'none'
    standalone_engine = static_library('standalone_engine',
                                       'StandaloneFuzzTargetMain.c'
    )
    fuzz_deps += declare_dependency(link_with : standalone_engine)
elif fuzzing_engine == 'libfuzzer'
    fuzz_ldflags += ['-fsanitize=fuzzer']
endif

fuzz_progs = [
    'olm_sign_fuzzer'
]

fuzz_execs = []
foreach fuzz_prog : fuzz_progs
    fuzz_execs += executable(fuzz_prog,
                             fuzz_prog + '.cpp',
                             dependencies : [spank_olm_dep, fuzz_deps],
                             link_args : fuzz_ldflags
    )
endforeach

# If the fuzzing engine is not OSS-Fuzz, build the unit tests to be run on CI
if fuzzing_engine != 'oss-fuzz'
    test_fuzz = configure_file(
        input : 'test_fuzz.sh',
        output : 'test_fuzz.sh',
        copy : true,
    )

    test(
        'fuzz',
        test_fuzz,
        workdir : meson.current_build_dir(),
        depends : [
            fuzz_execs,
        ],
        # Increase the timeout as running the tests with sanitizers
        # enabled could be slower than the default 30 seconds.
        timeout : 60,
    )
endif