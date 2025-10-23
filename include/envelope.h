#ifndef ENVELOPE_H
#define ENVELOPE_H

#include <stdint.h>
#include <stddef.h>

#define ENVELOPE_IV_LEN  12
#define ENVELOPE_TAG_LEN 16

/* On-wire layout (canonical):
   [4B key_id (network order)] [12B IV] [ciphertext (ct_len bytes)] [16B tag]
   Total size = 4 + IV_LEN + ct_len + TAG_LEN
*/

/* Lightweight in-memory representation (not on-wire serialization) */
typedef struct {
    uint32_t keyId;            // which key was used (not secret)
    uint8_t iv[ENVELOPE_IV_LEN];             // nonce used (not secret)
    uint8_t tag[ENVELOPE_TAG_LEN];            // authentication tag (MAC)
    uint8_t *ciphertext;        // pointer to ciphertext buffer
    size_t ciphertextLen;      // ciphertext length (same as plaintext)
} CipherEnvelope;

/* Pack an envelope into a caller-provided buffer.
   Returns required length on success (>=0), or -1 on error (buf too small). */
size_t pack_envelope(const CipherEnvelope *env, uint8_t *out_buf, size_t out_buf_len);

/* Parse a serialized envelope buffer without copying ciphertext.
   On success fills env with pointers into buf (non-owning). Returns 0 on success, -1 on error. */
int parse_envelope(const uint8_t *buf, size_t buf_len, CipherEnvelope *env);

#endif // ENVELOPE_H
