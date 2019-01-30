/*#include <stdio.h>*/
#include <stdlib.h>
#include <string.h>
#include "bs.h"
#include "aes.h"
#include "utils.h"

#include "testbench/app.h"
#ifdef RUN_TESTS
#include "tests/tests.h"
#endif

#ifdef TEST_FOOTPRINT
#define printf(fmt, ...) (0)
#define fprintf(f,fmt, ...) (0)
#else
#include <stdio.h>
#endif

int main(int argc, char * argv[])
{

#ifdef RUN_TESTS
#ifndef TEST_FOOTPRINT
    aes_ecb_test();
#endif
    aes_ctr_test();

#else

    cli_app(argc,argv);

#endif



    return 0;
}


