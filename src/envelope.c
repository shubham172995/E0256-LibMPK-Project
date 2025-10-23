#include "envelope.h"
#include <string.h>
#include <arpa/inet.h> 
#include <errno.h>

size_t pack_envelope(const CipherEnvelope *env, uint8_t *outBuf, size_t outBufLen) {
    if (!env || !outBuf) return -1;
    size_t needed = 4 + ENVELOPE_IV_LEN + env->ciphertextLen + ENVELOPE_TAG_LEN;    //  keyId + IV + Ciphertext + Tag
    if (outBufLen < needed) { errno = ENOMEM; return -1; }

    uint8_t *p = outBuf;
    uint32_t keyIdBigEndian = htonl(env->keyId);
    memcpy(p, &keyIdBigEndian, 4); p += 4;
    memcpy(p, env->iv, ENVELOPE_IV_LEN); p += ENVELOPE_IV_LEN;
    if (env->ciphertextLen > 0 && env->ciphertext) {
        memcpy(p, env->ciphertext, env->ciphertextLen);
        p += env->ciphertextLen;
    }
    memcpy(p, env->tag, ENVELOPE_TAG_LEN);
    return (ssize_t)needed;
}

int parse_envelope(const uint8_t *buf, size_t bufLen, CipherEnvelope *env) {
    if (!buf || !env) return -1;
    if (bufLen < (size_t)(4 + ENVELOPE_IV_LEN + ENVELOPE_TAG_LEN)) return -1;

    const uint8_t *p = buf;
    uint32_t keyIdBigEndian;
    memcpy(&keyIdBigEndian, p, 4); p += 4;
    env->keyId = ntohl(keyIdBigEndian);
    memcpy(env->iv, p, ENVELOPE_IV_LEN); p += ENVELOPE_IV_LEN;

    /* ciphertext extends from here until last TAG_LEN bytes */
    size_t ciphertextLen = bufLen - (4 + ENVELOPE_IV_LEN + ENVELOPE_TAG_LEN);
    env->ciphertext = (uint8_t *)p; /* non-owning pointer into buf */
    env->ciphertextLen = ciphertextLen;

    /* tag is the final 16 bytes */
    const uint8_t *tagp = buf + (4 + ENVELOPE_IV_LEN + ciphertextLen);
    memcpy(env->tag, tagp, ENVELOPE_TAG_LEN);
    return 0;
}
