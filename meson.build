project('spank-olm', 'cpp',
        version : '1.0.0',
        default_options : ['warning_level=3',
                           'cpp_std=c++23',
                           'b_lto=true',
                           'b_thinlto_cache=true'])

spank_olm = executable('spank_olm', 'main.cpp', install : true)

snitch_dep = dependency('snitch')

test('test', executable('spank-olm-test','tests/test.cpp',dependencies:snitch_dep))