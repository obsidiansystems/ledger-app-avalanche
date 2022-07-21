#include "globals.h"

#include "exception.h"
#include "to_string.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#include "ux.h"
#endif

#include <string.h>

void __attribute__ ((noinline)) dbgout(char *at) {
    volatile uint i;
    PRINTF("%s - sp %p spg %p %d\n", at, &i, &app_stack_canary, app_stack_canary);
    PRINTF("MEMORY: %.*h\n", &i - &app_stack_canary, &app_stack_canary);
    PRINTF("Free space between globals and maximum stack: %d\n", 4 * (&i - &app_stack_canary));
}

// WARNING: ***************************************************
// Non-const globals MUST NOT HAVE AN INITIALIZER.
//
// Providing an initializer will cause the application to crash
// if you write to it.
// ************************************************************


globals_t global;

// These are strange variables that the SDK relies on us to define but uses directly itself.
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

void clear_apdu_globals(void) {
    PRINTF("Clearing APDU globals\n");
    memset(&global.apdu, 0, sizeof(global.apdu));
}

void init_globals(void) {
    memset(&global, 0, sizeof(global));

    memset(&G_ux, 0, sizeof(G_ux));
    memset(&G_ux_params, 0, sizeof(G_ux_params));

    memset(G_io_seproxyhal_spi_buffer, 0, sizeof(G_io_seproxyhal_spi_buffer));
}

// DO NOT TRY TO INIT THIS. This can only be written via an system call.
// The "N_" is *significant*. It tells the linker to put this in NVRAM.
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
nvram_data const N_data_real;
#else
nvram_data N_data_real;
#endif

#if !defined(TARGET_NANOX) && !defined(TARGET_NANOS2)
_Static_assert(sizeof(global) <= 2120, "Size of globals_t exceeds the tested working limit");
#endif
