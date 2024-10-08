// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "attestation.h"
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/report.h>
#include <string.h>
#include "log.h"

Attestation::Attestation(Crypto *crypto, uint8_t *enclave_signer_id) {
    m_crypto = crypto;
    m_enclave_signer_id = enclave_signer_id;
}

// Get format settings for the given enclave.
bool Attestation::get_format_settings(
        const oe_uuid_t *format_id,
        uint8_t **format_settings,
        size_t *format_settings_size) {
    bool ret = false;

    // Intialize verifier to get enclave's format settings.
    if (oe_verifier_initialize() != OE_OK) {
        TRACE_ENCLAVE("Errors: oe_verifier_initialize failed");
        ret = 1;
        return ret;
    }

    // Use the plugin.
    if (oe_verifier_get_format_settings(format_id, format_settings, format_settings_size) != OE_OK) {
        TRACE_ENCLAVE("Errors: oe_verifier_get_format_settings failed");
        ret = 1;
        return ret;
    }
    ret = true;

    exit:
    return ret;
}

// Generate evidence for the given data.
bool Attestation::generate_attestation_evidence(
        const oe_uuid_t *format_id,
        uint8_t *format_settings,
        size_t format_settings_size,
        const uint8_t *data,
        const size_t data_size,
        uint8_t **evidence,
        size_t *evidence_size) {

    bool ret = false;
    uint8_t hash[32];
    oe_result_t result = OE_OK;
    uint8_t *custom_claims_buffer = nullptr;
    size_t custom_claims_buffer_size = 0;
    char custom_claim1_name[] = "Event";
    char custom_claim1_value[] = "Attestation sample";
    char custom_claim2_name[] = "Public key hash";

    // The custom_claims[1].value will be filled with hash of public key later
    oe_claim_t custom_claims[2] = {
            {.name = custom_claim1_name,
                    .value = (uint8_t *) custom_claim1_value,
                    .value_size = sizeof(custom_claim1_value)},
            {.name = custom_claim2_name, .value = nullptr, .value_size = 0}};

    if (m_crypto->Sha256(data, data_size, hash) != 0) {
        TRACE_ENCLAVE("Errors: data hashing failed");
        ret = 1;
        return ret;
    }

    // Initialize attester and use the plugin.
    result = oe_attester_initialize();
    if (result != OE_OK) {
        TRACE_ENCLAVE("Errors: oe_attester_initialize failed.");
        ret = 1;
        return ret;
    }

    // serialize the custom claims, store hash of data in custom_claims[1].value
    custom_claims[1].value = hash;
    custom_claims[1].value_size = sizeof(hash);

    if (PRINT_ATTESTATION_MESSAGES) {
        // TRACE_ENCLAVE("Attestation Info: oe_serialize_custom_claims");
    }

    if (oe_serialize_custom_claims(
            custom_claims,
            2,
            &custom_claims_buffer,
            &custom_claims_buffer_size) != OE_OK) {
        TRACE_ENCLAVE("Error: oe_serialize_custom_claims failed.");
        ret = 1;
        return ret;
    }

    if (PRINT_ATTESTATION_MESSAGES) {
        // TRACE_ENCLAVE("Attestation Info: serialized custom claims buffer size: %lu", custom_claims_buffer_size);
    }

    // Generate evidence based on the format selected by the attester.
    result = oe_get_evidence(
            format_id,
            0,
            custom_claims_buffer,
            custom_claims_buffer_size,
            format_settings,
            format_settings_size,
            evidence,
            evidence_size,
            nullptr,
            0);
    if (result != OE_OK) {
        TRACE_ENCLAVE("oe_get_evidence failed.(%s)", oe_result_str(result));
        ret = 1;
        return ret;
    }

    ret = true;
    if (PRINT_ATTESTATION_MESSAGES) {
        TRACE_ENCLAVE("Attestation Info: generate_attestation_evidence succeeded.");
    }

    exit:
    return ret;
}
