/*
 * Barnacle.c
 *
 *  Created on: Oct 18, 2017
 *      Author: stefanth
 */
#include <time.h>
#include "StmUtil.h"
#include "stm32l4xx_hal.h"
#include "usbd_dfu_if.h"
#include <cyrep/RiotTarget.h>
#include <cyrep/RiotStatus.h>
#include <cyrep/RiotSha256.h>
#include <cyrep/RiotEcc.h>
#include <cyrep/RiotCrypt.h>
#include <cyrep/RiotDerEnc.h>
#include <cyrep/RiotX509Bldr.h>
#include <cyrep/RiotBase64.h>
#include <tcps/TcpsId.h>
#include <BarnacleTA.h>
#include <Barnacle.h>

extern RNG_HandleTypeDef hrng;
extern const char DeviceBuildId[32];

__attribute__((section(".AGENTHDR"))) const BARNACLE_AGENT_HDR AgentHdr;
#ifndef NDEBUG
//__attribute__((section(".AGENTCODE"))) const uint8_t AgentCode[0xDD800];
const uint8_t* AgentCode = (uint8_t*)0x08020800;
#else
//__attribute__((section(".AGENTCODE"))) const uint8_t AgentCode[0xF4800];
const uint8_t* AgentCode = (uint8_t*)0x08009800;
#endif

__attribute__((section(".PURW.Private"))) BARNACLE_IDENTITY_PRIVATE CompoundId;
__attribute__((section(".PURW.Public"))) BARNACLE_CERTSTORE CertStore;
__attribute__((section(".PURO"))) const BARNACLE_ISSUED_PUBLIC IssuedCerts;
__attribute__((section(".FWRO"))) const BARNACLE_IDENTITY_PRIVATE FwDeviceId;
__attribute__((section(".FWRW"))) const BARNACLE_CACHED_DATA FwCache;

char dfuString[128] = {0};
char* BarnacleGetDfuStr(void)
{
    uint32_t cursor = 0;
    int32_t agentArea = ((uint32_t)&FwDeviceId - (uint32_t)&AgentHdr) / 4096;
    cursor += sprintf(&dfuString[cursor], "@Barnacle /0x%08x/", (unsigned int)&AgentHdr);
    while(agentArea > 0)
    {
        uint32_t iteration = MIN(agentArea, 99);
        cursor += sprintf(&dfuString[cursor], "%02u*004Kf", (unsigned int)iteration);
        agentArea -= iteration;
        if(agentArea > 0)
        {
            cursor += sprintf(&dfuString[cursor], ",");
        }
    }
    cursor += sprintf(&dfuString[cursor], "/0x%08x/01*04K%c", (unsigned int)&IssuedCerts, ((IssuedCerts.info.magic != BARNACLEMAGIC) || !(IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_WRITELOCK)) ? 'g' : 'a' );
    return dfuString;
}

bool BarnacleErasePages(void* dest, uint32_t size)
{
    bool result = true;
    uint32_t pageError = 0;
    uint32_t flashOffset = ((uint32_t)dest) - 0x08000000;
    uint32_t bankSel = (flashOffset < (256 * 2048)) ? FLASH_BANK_1 : FLASH_BANK_2;
    uint32_t pageSel = ((bankSel == FLASH_BANK_1) ? flashOffset : (flashOffset - (256 * 2048))) / 0x800;
    FLASH_EraseInitTypeDef eraseInfo = {FLASH_TYPEERASE_PAGES,
                                        bankSel,
                                        pageSel,
                                        (size + 0x7ff) / 0x800};

    // Parameter check
    if(!(result = (((uint32_t)dest >= 0x08000000) &&
                   ((uint32_t)dest < 0x08100000) &&
                   ((uint32_t)dest % 0x800) == 0)))
    {
        logError("BarnacleErasePages() bad parameter.\r\n");
        goto Cleanup;
    }

    // Open the memory protection
    for(uint32_t m = 0; m < 10; m++)
    {
        if((result = (HAL_FLASH_Unlock() == HAL_OK)) != false)
        {
            break;
        }
        logWarning("HAL_FLASH_Unlock() retry %u.\r\n", (unsigned int)m);
        // Bring the flash subsystem into a defined state.
        HAL_FLASH_Lock();
        HAL_Delay(1);
    }
    if(!result)
    {
        logError("HAL_FLASH_Unlock() failed.\r\n");
        goto Cleanup;
    }

    // Erase the necessary pages
    for(uint32_t m = 0; m < 10; m++)
    {
        if((result = ((HAL_FLASHEx_Erase(&eraseInfo, &pageError) == HAL_OK) && (pageError == 0xffffffff))))
        {
            break;
        }
        logWarning("HAL_FLASHEx_Erase() retry %u.\r\n", (unsigned int)m);
    }
    if(!result)
    {
        logError("HAL_FLASHEx_Erase() failed.\r\n");
        goto Cleanup;
    }

Cleanup:
    HAL_FLASH_Lock();
    return result;
}

bool BarnacleFlashPages(void* dest, void* src, uint32_t size)
{
    bool result = true;

    // Parameter check
    if(!(result = ((((uint32_t)src % sizeof(uint32_t)) == 0))))
    {
        goto Cleanup;
    }

    // Erase the required area
    if(!(result = BarnacleErasePages(dest, size)))
    {
        goto Cleanup;
    }

    // Open the memory protection
    if(!(result = (HAL_FLASH_Unlock() == HAL_OK)))
    {
        goto Cleanup;
    }

    // Flash the src buffer 8 byte at a time and verify
    for(uint32_t n = 0; n < ((size + sizeof(uint64_t) - 1) / sizeof(uint64_t)); n++)
    {
        result = false;
        for(uint32_t m = 0; m < 10; m++)
        {
            uint32_t progPtr = (uint32_t)&(((uint64_t*)dest)[n]);
            uint64_t progData = ((uint64_t*)src)[n];
            if((progData == *((uint64_t*)progPtr)) ||
               ((result = (HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, progPtr, progData) == HAL_OK)) &&
                (progData == *((uint64_t*)progPtr))))
            {
                result = true;
                break;
            }
            logWarning("HAL_FLASH_Program() retry %u.\r\n", (unsigned int)m);
        }
        if(result == false)
        {
            goto Cleanup;
        }
    }

Cleanup:
    HAL_FLASH_Lock();
    return result;
}

void BarnacleDumpCertStore(void)
{
    dbgPrint("CertStore:\r\n");
    for(uint32_t n = 0; n < NUMELEM(CertStore.info.certTable); n++)
    {
        if(CertStore.info.certTable[n].size > 0)
        {
            dbgPrintAppend("%s", (char*)&CertStore.certBag[CertStore.info.certTable[n].start]);
        }
    }
}

void BarnacleGetRandom(void* dest, uint32_t size)
{
    for(uint32_t n = 0; n < size; n += sizeof(uint32_t))
    {
        uint32_t entropy = HAL_RNG_GetRandomNumber(&hrng);
        memcpy(&(((uint8_t*)dest)[n]), (uint8_t*)&entropy, MIN(sizeof(entropy), size - n));
    }
}

bool BarnacleNullCheck(void* dataPtr, uint32_t dataSize)
{
    for(uint32_t n = 0; n < dataSize; n++)
    {
        if(((uint8_t*)dataPtr)[n] != 0x00) return false;
    }
    return true;
}

bool BarnacleWriteLockLoader()
{
    bool result = true;
    FLASH_OBProgramInitTypeDef ob = {0};

    HAL_FLASHEx_OBGetConfig(&ob);

    if(ob.RDPLevel == OB_RDP_LEVEL_0)
    {
        logInfo("Device not yet locked down.\r\n");
        memset(&ob, 0x00, sizeof(ob));
        ob.OptionType = OPTIONBYTE_WRP | OPTIONBYTE_RDP;
        ob.WRPArea = OB_WRPAREA_BANK1_AREAA;
        ob.WRPStartOffset = 0x00000000;
#ifndef NDEBUG
        ob.WRPEndOffset = 0x0000003f;
#else
        ob.WRPEndOffset = 0x0000001f;
#endif
#ifdef IRREVERSIBLELOCKDOWN
        ob.RDPLevel = OB_RDP_LEVEL_2;
#else
        ob.RDPLevel = OB_RDP_LEVEL_1;
        ob.PCROPConfig = OB_PCROP_RDP_ERASE;
#endif
        HAL_FLASH_Lock();
        if(HAL_FLASH_Unlock() != HAL_OK)
        {
            result = false;
            dbgPrint("PANIC: HAL_FLASH_Unlock() failed.\r\n");
            goto Cleanup;
        }

        __HAL_FLASH_CLEAR_FLAG(FLASH_FLAG_OPTVERR);

        if(HAL_FLASH_OB_Unlock() != HAL_OK)
        {
            result = false;
            dbgPrint("PANIC: HAL_FLASH_OB_Unlock() failed.\r\n");
            goto Cleanup;
        }
#ifdef TOUCHOPTIONBYTES
        if(HAL_FLASHEx_OBProgram(&ob) != HAL_OK)
        {
            result = false;
            dbgPrint("PANIC: HAL_FLASHEx_OBProgram() failed.\r\n");
            goto Cleanup;
        }
        logInfo("Option bytes written. Generating System Reset to load the new option byte values.\r\n");
        HAL_FLASH_OB_Launch();
#else
        logWarning("Writing option bytes is disabled.\r\n");
#endif
    }
    else if(ob.RDPLevel == OB_RDP_LEVEL_1)
    {
        logWarning("Non-permanent device lock down detected.\r\n");
    }
    else if(ob.RDPLevel == OB_RDP_LEVEL_2)
    {
        logInfo("Device permanently locked down.\r\n");
    }
    else
    {
        result = false;
        dbgPrint("PANIC: Undefined OB_RDP_LEVEL\r\n");
    }

Cleanup:
    HAL_FLASH_OB_Lock();
    HAL_FLASH_Lock();
    return result;
}

bool BarnacleInitialProvision()
{
    bool result = true;
    bool generateCerts = false;

    // Check if the platform identity is already provisioned
    if(generateCerts ||
       (FwDeviceId.info.magic != BARNACLEMAGIC))
    {
        logInfo("Generating and persisting new device identity.\r\n");
        uint8_t cdi[SHA256_DIGEST_LENGTH] = {0};
        BARNACLE_IDENTITY_PRIVATE newId = {0};

        // Generate a random device Identity from the hardware RNG
        newId.info.magic = BARNACLEMAGIC;
        BarnacleGetRandom(cdi, sizeof(cdi));
        if(!(result = (RiotCrypt_DeriveEccKey(&newId.info.pubKey,
                                             &newId.info.privKey,
                                             cdi, sizeof(cdi),
                                             (const uint8_t *)RIOT_LABEL_IDENTITY,
                                             lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_DeriveEccKey failed.\r\n");
            goto Cleanup;
        }

        // Persist the identity
        if(!(result = (BarnacleFlashPages((void*)&FwDeviceId, (void*)&newId, sizeof(newId)))))
        {
            logError("BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }

        generateCerts = true;
    }

    // Check if the platform cert are provisioned
    if(generateCerts ||
       (IssuedCerts.info.magic != BARNACLEMAGIC))
    {
        BARNACLE_ISSUED_PUBLIC newCertBag = {0};
        RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                           "CyReP Device", "Microsoft", "US",
                                           "170101000000Z", "370101000000Z",
                                           "CyReP Device", "Microsoft", "US" };
        DERBuilderContext derCtx = { 0 };
        uint8_t derBuffer[DER_MAX_TBS] = { 0 };
        uint8_t digest[SHA256_DIGEST_LENGTH] = { 0 };
        uint32_t length = 0;
        RIOT_ECC_SIGNATURE  tbsSig = { 0 };
        uint8_t tcps[BARNACLE_TCPS_ID_BUF_LENGTH];
        uint32_t tcpsLen = 0;

        logInfo("Generating and persisting new device certificate.\r\n");
        // Make sure we don't flash unwritten space in the cert bag
        newCertBag.info.magic = BARNACLEMAGIC;
        memset(newCertBag.certBag, 0xff, sizeof(newCertBag.certBag) - 1);

        // Generating self-signed DeviceID certificate
        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        if(!(result = (RiotCrypt_Kdf(digest,
                                     sizeof(digest),
                                     (uint8_t*)&FwDeviceId.info.pubKey, sizeof(FwDeviceId.info.pubKey),
                                     NULL, 0,
                                     (const uint8_t *)RIOT_LABEL_SERIAL,
                                     lblSize(RIOT_LABEL_SERIAL),
                                     sizeof(digest)) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_Kdf failed.\r\n");
            goto Cleanup;
        }
        digest[0] &= 0x7F; // Ensure that the serial number is positive
        digest[0] |= 0x01; // Ensure that the serial is not null
        memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));

        if(!(result = (BuildTCPSDeviceIdentity((RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                               (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                               (uint8_t*)DeviceBuildId,
                                               sizeof(DeviceBuildId),
                                               tcps,
                                               sizeof(tcps),
                                               &tcpsLen) == RIOT_SUCCESS)))
        {
            logError("BuildTCPSDeviceIdentity failed.\r\n");
            goto Cleanup;
        }

        result = (X509GetDeviceCertTBS(&derCtx,
                                       &x509TBSData,
                                       (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                       (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                       tcps,
                                       tcpsLen,
                                       2) == 0);
        if(!result)
        {
            logError("X509GetDeviceCertTBS failed.\r\n");
            goto Cleanup;
        }

        // Self-sign the certificate and finalize it
        if(!(result = (RiotCrypt_Sign(&tbsSig,
                                      derCtx.Buffer,
                                      derCtx.Position,
                                      (RIOT_ECC_PRIVATE*)&FwDeviceId.info.privKey) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_Sign failed.\r\n");
            goto Cleanup;
        }
        if(!(result = (X509MakeDeviceCert(&derCtx, &tbsSig) == 0)))
        {
            logError("X509MakeDeviceCert failed.\r\n");
            goto Cleanup;
        }

        // Produce a PEM formatted output from the DER encoded cert
        length = sizeof(newCertBag.certBag) - newCertBag.info.cursor;
        if(!(result = (DERtoPEM(&derCtx, R_CERT_TYPE, (char*)&newCertBag.certBag[newCertBag.info.cursor], &length) == 0)))
        {
            logError("DERtoPEM failed.\r\n");
            goto Cleanup;
        }
        newCertBag.info.certTable[BARNACLE_ISSUED_DEVICE].start = newCertBag.info.cursor;
        newCertBag.info.certTable[BARNACLE_ISSUED_DEVICE].size = (uint16_t)length;
        newCertBag.info.cursor += length;
        newCertBag.certBag[newCertBag.info.cursor++] = '\0';

        // Persist the new certBag in flash
        if(!(result = (BarnacleFlashPages((void*)&IssuedCerts, (void*)&newCertBag, sizeof(newCertBag)))))
        {
            logError("BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }
        generateCerts = true;
    }

    if(!generateCerts)
    {
        logInfo("Device already provisioned.\r\n");
    }

    {
        uint8_t devicePub[65] = {0};
        uint8_t deviceID[8] = {0};
        char deviceIDStr[27] = {0};
        RiotCrypt_ExportEccPub((RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey, devicePub, NULL);
        for(uint32_t n = 0; n < 16; n++)
        {
            deviceID[n] = devicePub[n + 1] ^ devicePub[16 + n + 1] ^ devicePub[32 + n + 1] ^ devicePub[48 + n + 1];
        }
        Base64Encode(deviceID, 16, deviceIDStr, NULL);
        deviceIDStr[24] = '\0';
        logInfo("DevPub (%s) :\r\n0x", deviceIDStr);
        for(uint32_t n = 0; n < sizeof(devicePub); n++)
        {
            if (!((n + 1) % 22) && (n > 0)) dbgPrintAppend("\r\n");
            dbgPrintAppend("%02x", devicePub[n]);
        }

        dbgPrintAppend("\r\n");
        printf("DevID: %s\r\n", deviceIDStr);
    }

    logInfo("DeviceCert %s and %s\r\n", ((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_PROVISIONIED) ? "ISSUED" : "SELFSIGNED"),
                                               ((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_WRITELOCK) ? "WRITELOCKED" : "WRITEABLE"));
//    dbgPrint("%s", (char*)&IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].start]);
//    if(IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size != 0)
//    {
//        dbgPrint("%s", (char*)&IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].start]);
//    }
    logInfo("CodeAuthorityPub %s", ((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT) ? "LOCKED to\r\n0x" : "UNLOCKED\r\n"));
    if(IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT)
    {
        uint8_t codeAuthPub[65] = {0};
        RiotCrypt_ExportEccPub((RIOT_ECC_PUBLIC*)&IssuedCerts.info.codeAuthPubKey, codeAuthPub, NULL);
        for(uint32_t n = 0; n < sizeof(codeAuthPub); n++)
        {
            if (!((n + 1) % 22) && (n > 0)) dbgPrintAppend("\r\n");
            dbgPrintAppend("%02x", codeAuthPub[n]);
        }
        dbgPrintAppend("\r\n");
    }

Cleanup:
    return result;
}

bool BarnacleVerifyAgent()
{
    bool result = true;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    RIOT_ECC_SIGNATURE sig = {0};

    // Sniff the header
    if(!(result = ((AgentHdr.s.sign.hdr.magic == BARNACLEMAGIC) &&
                   (AgentHdr.s.sign.hdr.version <= BARNACLEVERSION))))
    {
        logError("Invalid agent present.\r\n");
        goto Cleanup;
    }

    // Make sure the agent code starts where we expect it to start
    if(!(result = (AgentCode == &((uint8_t*)&AgentHdr)[AgentHdr.s.sign.hdr.size])))
    {
        logError("Unexpected agent start address.\r\n");
        goto Cleanup;
    }

    // Verify the agent code digest against the header
    if(!(result = (RiotCrypt_Hash(digest,
                                  sizeof(digest),
                                  AgentCode,
                                  AgentHdr.s.sign.agent.size) == RIOT_SUCCESS)))
    {
        logError("RiotCrypt_Hash failed.\r\n");
        goto Cleanup;
    }
    if(!(result = (memcmp(digest, AgentHdr.s.sign.agent.digest, sizeof(digest)) == 0)))
    {
        logError("Agent digest mismatch.\r\n");
        goto Cleanup;
    }

    // Calculate the header signature
    if(!(result = (RiotCrypt_Hash(digest,
                                  sizeof(digest),
                                  (const void*)&AgentHdr.s.sign,
                                  sizeof(AgentHdr.s.sign)) == RIOT_SUCCESS)))
    {
        logError("RiotCrypt_Hash failed.\r\n");
        goto Cleanup;
    }

    // If authenticated boot is provisioned and enabled
    if((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_PROVISIONIED) &&
       (IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_AUTHENTICATED_BOOT) &&
       (!BarnacleNullCheck((void*)&IssuedCerts.info.codeAuthPubKey, sizeof(IssuedCerts.info.codeAuthPubKey))))
    {
        //Re-hydrate the signature
        BigIntToBigVal(&sig.r, AgentHdr.s.signature.r, sizeof(AgentHdr.s.signature.r));
        BigIntToBigVal(&sig.s, AgentHdr.s.signature.s, sizeof(AgentHdr.s.signature.s));
        if(!(result = (RiotCrypt_VerifyDigest(digest,
                                               sizeof(digest),
                                               &sig,
                                               &IssuedCerts.info.codeAuthPubKey) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_Verify failed.\r\n");
            goto Cleanup;
        }
        logInfo("Agent signature valid.\r\n");
    }

    // Is this the first launch or the first launch after an update?
    if((FwCache.info.magic != BARNACLEMAGIC) ||
       (memcmp(digest, FwCache.info.agentHdrDigest, sizeof(digest))))
    {
        logInfo("Generating and caching agent identity.\r\n");
        RIOT_X509_TBS_DATA x509TBSData = { { 0 },
                                           "CyReP Device", "Microsoft", "US",
                                           "170101000000Z", "370101000000Z",
                                           AgentHdr.s.sign.agent.name, NULL, NULL };
        DERBuilderContext derCtx = { 0 };
        uint8_t derBuffer[DER_MAX_TBS] = { 0 };
        uint32_t length = 0;
        RIOT_ECC_SIGNATURE  tbsSig = { 0 };
        BARNACLE_CACHED_DATA cache = {0};
        uint8_t tcps[BARNACLE_TCPS_ID_BUF_LENGTH];
        uint32_t tcpsLen = 0;

        // Detect rollback attack if this is not the first launch
        if(FwCache.info.magic == BARNACLEMAGIC)
        {
            if(!(result = (FwCache.info.lastVersion < AgentHdr.s.sign.agent.version)))
            {
                logError("Version Roll-back detected to %d.%d.\r\n",
                         (short unsigned int)AgentHdr.s.sign.agent.version >> 16,
                         (short unsigned int)AgentHdr.s.sign.agent.version % 0x0000ffff);
                goto Cleanup;
            }
            if(!(result = (FwCache.info.lastIssued < AgentHdr.s.sign.agent.issued)))
            {
                char* dateStr = asctime(localtime((time_t*)&AgentHdr.s.sign.agent.issued));
                dateStr[24] = '\0';
                logError("Issuance Roll-back detected to %s.\r\n", dateStr);
                goto Cleanup;
            }
        }

        {
            char* dateStr = asctime(localtime((time_t*)&AgentHdr.s.sign.agent.issued));
            dateStr[24] = '\0';
            logInfo("Agent upgrade to Version %d.%d, issued %s.\r\n",
                     (short unsigned int)AgentHdr.s.sign.agent.version >> 16,
                     (short unsigned int)AgentHdr.s.sign.agent.version % 0x0000ffff,
                     dateStr);
        }

        // Set the new cache policy
        memset(cache.cert, 0xff, sizeof(cache.cert));
        cache.info.magic = BARNACLEMAGIC;
        cache.info.lastIssued = AgentHdr.s.sign.agent.issued;
        cache.info.lastVersion = AgentHdr.s.sign.agent.version;
        memcpy(cache.info.agentHdrDigest, digest, sizeof(digest));

        if(!(result = (RiotCrypt_Hash2(digest,
                                       sizeof(digest),
                                       cache.info.agentHdrDigest,
                                       sizeof(cache.info.agentHdrDigest),
                                       &FwDeviceId.info.privKey,
                                       sizeof(FwDeviceId.info.privKey)))) == RIOT_SUCCESS)
        {
            logError("RiotCrypt2_Hash failed.\r\n");
            goto Cleanup;
        }

        // Derive the agent compound key
        if(!(result = (RiotCrypt_DeriveEccKey(&cache.info.compoundPubKey,
                                              &cache.info.compoundPrivKey,
                                              digest, sizeof(digest),
                                              (const uint8_t *)RIOT_LABEL_IDENTITY,
                                              lblSize(RIOT_LABEL_IDENTITY)) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_DeriveEccKey failed.\r\n");
            goto Cleanup;
        }

        DERInitContext(&derCtx, derBuffer, DER_MAX_TBS);
        if(!(result = (RiotCrypt_Kdf(digest,
                                     sizeof(digest),
                                     (uint8_t*)&cache.info.compoundPubKey, sizeof(cache.info.compoundPubKey),
                                     NULL, 0,
                                     (const uint8_t *)RIOT_LABEL_SERIAL,
                                     lblSize(RIOT_LABEL_SERIAL),
                                     sizeof(digest)) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_Kdf failed.\r\n");
            goto Cleanup;
        }
        digest[0] &= 0x7F; // Ensure that the serial number is positive
        digest[0] |= 0x01; // Ensure that the serial is not null
        memcpy(x509TBSData.SerialNum, digest, sizeof(x509TBSData.SerialNum));

        if(!(result = (BuildTCPSAliasIdentity((RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                              (uint8_t*)AgentHdr.s.sign.agent.digest,
                                              sizeof(AgentHdr.s.sign.agent.digest),
                                              tcps,
                                              sizeof(tcps),
                                              &tcpsLen) == RIOT_SUCCESS)))
        {
            logError("BuildTCPSAliasIdentity failed.\r\n");
            goto Cleanup;
        }

        result = (X509GetAliasCertTBS(&derCtx,
                                      &x509TBSData,
                                      (RIOT_ECC_PUBLIC*)&cache.info.compoundPubKey,
                                      (RIOT_ECC_PUBLIC*)&FwDeviceId.info.pubKey,
                                      (uint8_t*)AgentHdr.s.sign.agent.digest,
                                      sizeof(AgentHdr.s.sign.agent.digest),
                                      tcps,
                                      tcpsLen,
                                      1) == 0);
        if(!result)
        {
            logError("X509GetAliasCertTBS failed.\r\n");
            goto Cleanup;
        }

        // Sign the agent compound key Certificate's TBS region
        if(!(result = (RiotCrypt_Sign(&tbsSig,
                                      derCtx.Buffer,
                                      derCtx.Position,
                                      &FwDeviceId.info.privKey) == RIOT_SUCCESS)))
        {
            logError("RiotCrypt_Sign failed.\r\n");
            goto Cleanup;
        }

        // Generate compound key Certificate
        if(!(result = (X509MakeAliasCert(&derCtx, &tbsSig) == 0)))
        {
            logError("X509MakeAliasCert failed.\r\n");
            goto Cleanup;
        }

        // Copy compound key Certificate
        length = sizeof(cache.cert);
        if(!(result = (DERtoPEM(&derCtx, R_CERT_TYPE, (char*)cache.cert, &length) == 0)))
        {
            logError("DERtoPEM failed.\r\n");
            goto Cleanup;
        }
        cache.info.compoundCertSize = length;
        cache.cert[cache.info.compoundCertSize] = '\0';

        // Persist the new certBag in flash
        if(!(result = (BarnacleFlashPages((void*)&FwCache, (void*)&cache, sizeof(cache)))))
        {
            logError("BarnacleFlashPages failed.\r\n");
            goto Cleanup;
        }
    }
    else
    {
        char* dateStr = asctime(localtime((time_t*)&AgentHdr.s.sign.agent.issued));
        dateStr[24] = '\0';
        logInfo("Using cached agent identity Version %d.%d, issued %s.\r\n",
                 (short unsigned int)AgentHdr.s.sign.agent.version >> 16,
                 (short unsigned int)AgentHdr.s.sign.agent.version % 0x0000ffff,
                 dateStr);
    }

    // Copy the cached identity and cert to the cert store
    CompoundId.info.magic = BARNACLEMAGIC;
    memcpy(&CompoundId.info.pubKey, &FwCache.info.compoundPubKey, sizeof(CompoundId.info.pubKey));
    memcpy(&CompoundId.info.privKey, &FwCache.info.compoundPrivKey, sizeof(CompoundId.info.privKey));
    memset(&CertStore, 0x00, sizeof(CertStore));
    CertStore.info.magic = BARNACLEMAGIC;
    memcpy(&CertStore.info.devicePubKey, &FwDeviceId.info.pubKey, sizeof(CertStore.info.devicePubKey));

    // Issued Root
    if((CertStore.info.cursor + IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size) >  sizeof(CertStore.certBag))
    {
        logError("Certstore overflow BARNACLE_ISSUED_ROOT.\r\n");
        goto Cleanup;
    }
    if((IssuedCerts.info.flags & BARNACLE_ISSUEDFLAG_PROVISIONIED) &&
       (IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size != 0))
    {
    	memcpy(&CertStore.certBag[CertStore.info.cursor],
    		   &IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].start],
			   IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size);
    	CertStore.info.certTable[BARNACLE_CERTSTORE_ROOT].start = CertStore.info.cursor;
    	CertStore.info.certTable[BARNACLE_CERTSTORE_ROOT].size = IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size;
    	CertStore.info.cursor += IssuedCerts.info.certTable[BARNACLE_ISSUED_ROOT].size;
    	CertStore.certBag[CertStore.info.cursor++] = '\0';
    }

    // Issued or generated device
    if((CertStore.info.cursor + IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size) >  sizeof(CertStore.certBag))
    {
        logError("Certstore overflow BARNACLE_ISSUED_DEVICE.\r\n");
        goto Cleanup;
    }
	memcpy(&CertStore.certBag[CertStore.info.cursor],
		   &IssuedCerts.certBag[IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].start],
		   IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size);
	CertStore.info.certTable[BARNACLE_CERTSTORE_DEVICE].start = CertStore.info.cursor;
	CertStore.info.certTable[BARNACLE_CERTSTORE_DEVICE].size = IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size;
	CertStore.info.cursor += IssuedCerts.info.certTable[BARNACLE_ISSUED_DEVICE].size;
	CertStore.certBag[CertStore.info.cursor++] = '\0';

	// Cached agent
    if((CertStore.info.cursor + FwCache.info.compoundCertSize) >  sizeof(CertStore.certBag))
    {
        logError("Certstore overflow BARNACLE_CERTSTORE_AGENT.\r\n");
        goto Cleanup;
    }
	memcpy(&CertStore.certBag[CertStore.info.cursor],
		   FwCache.cert,
		   FwCache.info.compoundCertSize);
	CertStore.info.certTable[BARNACLE_CERTSTORE_AGENT].start = CertStore.info.cursor;
	CertStore.info.certTable[BARNACLE_CERTSTORE_AGENT].size = FwCache.info.compoundCertSize;
	CertStore.info.cursor += FwCache.info.compoundCertSize;
	CertStore.certBag[CertStore.info.cursor++] = '\0';

Cleanup:
    return result;
}

bool BarnacleFWViolation()
{
    bool result = (__HAL_RCC_GET_FLAG(RCC_FLAG_FWRST) != RESET);

    if (result)
    {
        __HAL_RCC_CLEAR_RESET_FLAGS();
    }
    return result;
}

FIREWALL_InitTypeDef fw_init =
{
    0, 0,
    (uint32_t)&FwDeviceId, sizeof(FwDeviceId) + sizeof(FwCache),
    0, 0,
    FIREWALL_VOLATILEDATA_NOT_EXECUTABLE,
    FIREWALL_VOLATILEDATA_NOT_SHARED
};
bool BarnacleSecureFWData()
{
    bool result = true;

    __HAL_RCC_SYSCFG_CLK_ENABLE();
    if(HAL_FIREWALL_Config(&fw_init) != HAL_OK)
    {
        logError("HAL_FIREWALL_Config() failed.\r\n");
        result = false;
        goto Cleanup;
    }
    HAL_FIREWALL_EnableFirewall();
    if(!__HAL_FIREWALL_IS_ENABLED())
    {
        logError("HAL_FIREWALL_EnableFirewall() had no effect.\r\n");
        result = false;
        goto Cleanup;
    }
    logInfo("Firewall is UP!\r\n");

Cleanup:
    return result;
}
