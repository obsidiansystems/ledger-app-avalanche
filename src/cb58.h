#include <stdbool.h>
#include <stddef.h>

/* Return true IFF successful, false otherwise. */
bool cb58enc(/* out */ char *cb58, /* in/out */ size_t *cb58sz, const void *bin, size_t binsz);
