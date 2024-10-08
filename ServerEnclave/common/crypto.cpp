// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* Copyright (c) 2021 SUSTech University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto.h"
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>

Crypto::Crypto() {
    m_crypto_initialized = init_openssl();
}

Crypto::~Crypto() {}

/**
 * @brief init crypto object including initialization of ecdsa、aes、rsa、hash
 * @return true
 * @return false
 */
int Crypto::init_openssl(void) {
    // implement openssl
    int ret = 1;
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 17);
    gencb = NULL;
    pkey = EVP_PKEY_new();
    ret = RSA_generate_key_ex(rsa, 2048, e, gencb);
    ret = EVP_PKEY_set1_RSA(pkey, rsa);
    if (ret == 0) {
        TRACE_ENCLAVE("OpenSsl Generate RSA Key failed.");
        return ret;
    }

    out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSA_PUBKEY(out, rsa); // take rsa pubkey, PEM_write_bio_RSA_PUBKEY return 1 means successful
    if (ret == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }

    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr));
    // NID_secp192k1 ecdsa length is 150
    // If the result is 0 or -1, the read fails
    if (swap_pp_size == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_rsa_public_key, swap_pp, sizeof(m_rsa_public_key));
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    if (ret != 1) {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }

    ret = PEM_write_bio_RSAPrivateKey(out, rsa, 0, 0, 0, 0, 0);
    // PEM_write_bio_RSA_PUBKEY return 1 means successful
    if (ret == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }

    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr)); // NID_secp192k1 ecdsa length is 150
    // If the result is 0 or -1, the read fails
    if (swap_pp_size == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }

    memcpy(m_rsa_private_key, swap_pp, sizeof(m_rsa_private_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    if (ret != 1) {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }
    TRACE_ENCLAVE("OpenSsl RSA step init Successful!");

    // AES Openssl implement
    // Generate a aes key
    bn = BN_new();
    BN_rand(bn, AES_BLOCK_SIZE * 8, -1, 1); // genc 128 bit random
    memcpy(m_aes_key, BN_bn2hex(bn), AES_BLOCK_SIZE * 8);
    BN_free(bn); // Free bignum
    TRACE_ENCLAVE("AES Key is %s", m_aes_key);
    if (AES_set_encrypt_key(m_aes_key, AES_BLOCK_SIZE * 8, &AesKey) < 0) {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        ret = 1;
        return ret;
    }
    TRACE_ENCLAVE("OpenSsl AES step init Successful!");

    // INIT Ecdsa
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Choose ecdsa curve
    if (eckey == NULL) {
        TRACE_ENCLAVE("ECDSA Step failed. EC_KEY_new_by_curve_name Failed");
        ret = 1;
        return ret;
    }
    if (!EC_KEY_generate_key(eckey)) {
        // Genc the ec key
        TRACE_ENCLAVE("ECDSA Step failed.EC_KEY_generate_key Failed");
        ret = 1;
        return ret;
    }

    // extract ECDSA public key
    ret = PEM_write_bio_EC_PUBKEY(out, eckey);
    // PEM_write_bio_EC_PUBKEY return 1 representation successful
    if (ret == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }

    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr)); // NID_secp192k1 ecdsa length is 150
    // If the result is 0 or -1, the read fails
    if (swap_pp_size == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_ecdsa_public_key, swap_pp, sizeof(m_ecdsa_public_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));

    ret = BIO_reset(out); // reset out BIO
    if (ret != 1) {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }

    ret = PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL); // ecdsa private key
    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr));   // NID_secp192k1 ecdsa length is 150
    // If the result is 0 or -1, the read fails
    if (swap_pp_size == 0) {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_ecdsa_private_key, swap_pp, sizeof(m_ecdsa_private_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    ret = 0;
    TRACE_ENCLAVE("Openssl initialized.the ret is %d", ret);

    return ret;
}

// Compute the sha256 hash of given data.
int Crypto::Sha256(const uint8_t *data, size_t data_size, uint8_t sha256[32]) {
    int ret = 1;
    if (SHA256((unsigned char *) data, data_size, sha256) == NULL) {
        TRACE_ENCLAVE("Crypto::Sha256 failed\n");
        return ret;
    }

    ret = 0;
    return ret;
}

int Crypto::rsa_decrypt(
        const uint8_t *encrypted_data,
        size_t encrypted_data_size,
        uint8_t *data,
        size_t *data_size) {

    int ret = 1;
    int padding = RSA_PKCS1_PADDING;
    size_t decrypt_size;
    if (m_crypto_initialized != 0) {
        return ret;
    }

    *data_size = RSA_size(rsa);
    decrypt_size = RSA_private_decrypt(encrypted_data_size, encrypted_data, data, rsa, padding);
    if (decrypt_size <= 0) {
        TRACE_ENCLAVE("RSA Step Failed.RSA_public_encrypt failed!.");
        return ret;
    }

    ret = 0;
    return ret;
}

/**
 * @brief Use my RSA private key to sign data
 * @param data the data for signning
 * @param data_size
 * @param rsa_sig_data signed data
 * @param rsa_sig_data_size
 * @return failure 1 success 0
 */
int Crypto::rsa_sign(
        const uint8_t *data,
        size_t data_size,
        uint8_t *rsa_sig_data,
        size_t *rsa_sig_data_size) {

    unsigned char md[32];
    int ret = 1;
    unsigned char rsa_sig[256] = "";
    unsigned int rsa_sig_size = 0;
    if (m_crypto_initialized != 0) // If init failed can not continue
        goto exit;
    if (SHA256((unsigned char *) data, data_size, md) == NULL) {
        TRACE_ENCLAVE("sha256 erro\n");
        return -1;
    }
    ret = RSA_sign(NID_md5, md, 32, rsa_sig, &rsa_sig_size, rsa);
    if (ret != 1) {
        TRACE_ENCLAVE("RSA_sign failed");
        goto exit;
    }
    TRACE_ENCLAVE("Signature Generation Successful!");
    memcpy(rsa_sig_data, rsa_sig, rsa_sig_size); // 256
    *rsa_sig_data_size = rsa_sig_size;
    ret = 0;
    exit:
    // TODO Free something
    return ret;
}

/**
 * @brief verify signature created by rsa
 * @param data
 * @param data_size
 * @param rsa_sig_data
 * @param rsa_sig_data_size
 * @return int
 */
int Crypto::rsa_verify(
        uint8_t *pem_public_key,
        size_t pem_public_key_size,
        const uint8_t *data,
        size_t data_size,
        uint8_t *rsa_sig_data,
        size_t rsa_sig_data_size) {

    unsigned char md[32];
    int ret = 1;
    char swap_buffer[1024] = "";
    unsigned char rsa_sig[256] = "";
    RSA *rsa_recover = RSA_new();;
    BIO *temp = NULL;

    if (m_crypto_initialized != 0) // If init failed can not continue
        goto exit;
    if (SHA256((unsigned char *) data, data_size, md) == NULL) {
        TRACE_ENCLAVE("sha256 erro\n");
        return -1;
    }

    temp = BIO_new(BIO_s_mem());
    memcpy(swap_buffer, pem_public_key, pem_public_key_size);

    BIO_printf(temp, swap_buffer);
    if (temp == NULL) {
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        goto exit;
    }
    rsa_recover = PEM_read_bio_RSA_PUBKEY(temp, NULL, NULL, NULL); // Read public from BIO memory
    if (rsa_recover == NULL) {
        TRACE_ENCLAVE("RSA Read public key failed.");
        goto exit;
    }
    memcpy(rsa_sig, rsa_sig_data, 256);
    ret = RSA_verify(NID_md5, md, 32, rsa_sig, 256, rsa_recover);
    if (ret != 1) {
        TRACE_ENCLAVE("RSA Verify failed");
        goto exit;
    }
    TRACE_ENCLAVE("Signature Verification Successful!");
    ret = 0;
    exit:
    // TODO Free something
    return ret;
}

int Crypto::aes_decrypt(
        const uint8_t *data,
        size_t data_size,
        uint8_t *deencrypted_data,
        size_t *decrypted_data_size,
        const uint8_t *aes_key) {

    int ret = 1;
    AES_KEY AesKeys;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);
    unsigned char *swap_buffer;

    if (m_crypto_initialized != 0) { // If init failed can not continue
        ret = 1;
        return ret;
    }

    swap_buffer = (unsigned char *) malloc(data_size + 128);
    if (swap_buffer == nullptr) {
        TRACE_ENCLAVE("malloc failed");
        ret = 1;
        return ret;
    }
    memset(swap_buffer, 0, data_size + 128);
    if (AES_set_decrypt_key(aes_key, AES_BLOCK_SIZE * 8, &AesKeys) < 0) {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        ret = 1;
        return ret;
    }

    AES_cbc_encrypt(data, swap_buffer, data_size, &AesKeys, iv, AES_DECRYPT);
    if (strlen((const char *) swap_buffer) > data_size + 128) {
        TRACE_ENCLAVE("AES Encrypt failed.Your buffer is more small %zu", strlen((const char *) swap_buffer));
        ret = 1;
        return ret;
    }
    memcpy(deencrypted_data, swap_buffer, data_size + 128);
    *decrypted_data_size = data_size + 128;

    ret = 0;
    oe_free(swap_buffer);
    swap_buffer = NULL;
    return ret;
}