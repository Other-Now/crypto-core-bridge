#ifndef NANOKEM_TYPES_H
#define NANOKEM_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum nk_status {
    NK_OK = 0,
    NK_ERR_TRUNCATED,   /* buffer shorter than the message/field requires */
    NK_ERR_BAD_LENGTH,  /* declared length overruns the supplied buffer */
    NK_ERR_BAD_ARG,     /* NULL pointer, zero-size output, or out-of-range field */
    NK_ERR_AUTH_FAILED, /* AEAD tag or signature verification failed; output NOT written */
    NK_ERR_UNSUPPORTED, /* well-formed but not something this minimal build handles */
} nk_status;

#ifdef __cplusplus
}
#endif

#endif /* NANOKEM_TYPES_H */
