/*===- StandaloneFuzzTargetMain.c - standalone main() for fuzz targets. ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// This main() function can be linked to a fuzz target (i.e. a library
// that exports LLVMFuzzerTestOneInput() and possibly LLVMFuzzerInitialize())
// instead of libFuzzer. This main() function will not perform any fuzzing
// but will simply feed all input files one by one to the fuzz target.
//
// Use this file to provide reproducers for bugs when linking against libFuzzer
// or other fuzzing engine is undesirable.
//===----------------------------------------------------------------------===*/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);
extern int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv)
{
    const char *progname;
    if ((progname = strrchr(argv[0], '/')))
        progname++;
    else
        progname = argv[0];
    fprintf(stderr, "%s: running %d inputs\n", progname, argc - 1);
    LLVMFuzzerInitialize(&argc, &argv);
    for (int i = 1; i < argc; i++)
    {
        fprintf(stderr, "Running: %s\n", argv[i]);
        FILE *f = fopen(argv[i], "r+");
        assert(f);
        fseek(f, 0, SEEK_END);
        const long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char *buf = (unsigned char *)malloc(len);
        const size_t n_read = fread(buf, 1, len, f);
        fclose(f);
        assert(n_read == len);
        LLVMFuzzerTestOneInput(buf, len);
        free(buf);
        fprintf(stderr, "Done:    %s: (%zd bytes)\n", argv[i], n_read);
    }
}
