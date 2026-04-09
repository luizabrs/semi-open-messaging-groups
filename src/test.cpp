#ifdef __cplusplus
extern "C"{
#endif
#include <sodium.h>
#ifdef __cplusplus
}
#endif

#include <cstdio>
#include <iostream>

int main(void)
{
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized; it is not safe to use */
        printf("ERROR: libsodium not found. exiting.\n");
        exit(1);
    }
    printf("All is good with libsodium version %s.\n", sodium_version_string());
    printf("The environment is ready to run benchmarks.\n");
    return 0;
}
