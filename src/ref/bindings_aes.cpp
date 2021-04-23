#include <pybind11/pybind11.h>

#include "base58.h"

#define SEEDBYTES 32
#define CRHBYTES 64
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 78
#define GAMMA1 (1 << 17)
#define GAMMA2 ((Q-1)/88)
#define OMEGA 80

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#endif

#if GAMMA2 == (Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q-1)/32
#define POLYW1_PACKEDBYTES  128
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#endif

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (3*SEEDBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (SEEDBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)


typedef struct {
  int32_t coeffs[N];
} poly;


extern "C" int pqcrystals_dilithium2aes_ref_keypair(uint8_t *pk, uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_signature(uint8_t *sig, size_t *siglen,
                                    const uint8_t *m, size_t mlen,
                                    const uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign(uint8_t *sm, size_t *smlen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *pk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign_open(uint8_t *m, size_t *mlen,
                                           const uint8_t *sm, size_t smlen,
                                           const uint8_t *pk);


int pk_ready = 0, sk_ready = 0, skey_ready = 0;


extern "C" int pqcrystals_dilithium2aes_ref_keypair_p(uint8_t *pk, uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_signature_p(uint8_t *sig, size_t *siglen,
                                    const uint8_t *m, size_t mlen,
                                    const uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign_p(uint8_t *sm, size_t *smlen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *sk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign_verify_p(const uint8_t *sig, size_t siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *pk);
extern "C" int pqcrystals_dilithium2aes_ref_crypto_sign_open_p(uint8_t *m, size_t *mlen,
                                           const uint8_t *sm, size_t smlen,
                                           const uint8_t *pk);


PYBIND11_MODULE(pydilithium_aes, m) {
  m.doc() = R"doc(
        Python module
        -----------------------
        .. currentmodule:: pydilithium
        .. autosummary::
           :toctree: _generate

           add
           subtract
    )doc";

  m.def("pqcrystals_dilithium2aes_ref_keypair", &pqcrystals_dilithium2aes_ref_keypair_p, R"doc(
        Generates public and private key.

        Arguments:   - uint8_t *pk: pointer to output public key (allocated
                                    array of CRYPTO_PUBLICKEYBYTES bytes)
                     - uint8_t *sk: pointer to output private key (allocated
                                    array of CRYPTO_SECRETKEYBYTES bytes)
        return int
    )doc");
  m.def("pqcrystals_dilithium2aes_ref_signature", &pqcrystals_dilithium2aes_ref_signature_p, R"doc(
        Computes signature.

        Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
                     - size_t *siglen: pointer to output length of signature
                     - uint8_t *m:     pointer to message to be signed
                     - size_t mlen:    length of message
                     - uint8_t *sk:    pointer to bit-packed secret key
        return int
    )doc");

  m.def("pqcrystals_dilithium2aes_ref_crypto_sign", &pqcrystals_dilithium2aes_ref_crypto_sign_p, R"doc(
        Compute signed message.

        Arguments:   - uint8_t *sm: pointer to output signed message (allocated
                                    array with CRYPTO_BYTES + mlen bytes),
                                    can be equal to m
                     - size_t *smlen: pointer to output length of signed
                                      message
                     - const uint8_t *m: pointer to message to be signed
                     - size_t mlen: length of message
                     - const uint8_t *sk: pointer to bit-packed secret key
        return int
    )doc");

  m.def("pqcrystals_dilithium2aes_ref_crypto_sign_verify", &pqcrystals_dilithium2aes_ref_crypto_sign_verify_p, R"doc(
        Verifies signature.

        Arguments:   - uint8_t *m: pointer to input signature
                     - size_t siglen: length of signature
                     - const uint8_t *m: pointer to message
                     - size_t mlen: length of message
                     - const uint8_t *pk: pointer to bit-packed public key
        return int
    )doc");

  m.def("pqcrystals_dilithium2aes_ref_crypto_sign_open", &pqcrystals_dilithium2aes_ref_crypto_sign_open_p, R"doc(
        Verify signed message.

        Arguments:   - uint8_t *m: pointer to output message (allocated
                                   array with smlen bytes), can be equal to sm
                     - size_t *mlen: pointer to output length of message
                     - const uint8_t *sm: pointer to signed message
                     - size_t smlen: length of signed message
                     - const uint8_t *pk: pointer to bit-packed public key
        return int
    )doc");

}
