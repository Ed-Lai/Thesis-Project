
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <cstdlib>
#include "ippcp.h"
#include "ipp.h"
#include "ipp\ipps.h"
#include "ipp\ippcore.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "string.h"
#include <immintrin.h>
#include "sgx_tcrypto.h"
#include <stdlib.h>
#include <malloc.h>
#include "sgx_tseal.h"



#define CHECK(x)                                                                      \
{                                                                                     \
    IppStatus z = x;                                                                  \
    if (z) printf("Line #%d: error in "#x": %s\n", __LINE__, ippcpGetStatusString(z)); \
}
#define LAMBDA 128
#define HMAC_KEY_SIZE 64  // Key size (64 bytes for HMAC-SHA512)
#define HMAC_DIGEST_SIZE 64 // Output size for HMAC-SHA512 (512 bits = 64 bytes)




/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);

}


// Custom aligned malloc and free for SGX
void* aligned_malloc(size_t size, size_t alignment) {
    void* ptr = NULL;
    uintptr_t aligned_ptr = 0;

    // Allocate enough memory to adjust for alignment and store the original pointer
    ptr = malloc(size + alignment - 1 + sizeof(void*));
    if (ptr == NULL) {
        return NULL;  // Allocation failed
    }

    // Align the pointer by rounding it up to the next multiple of alignment
    aligned_ptr = (uintptr_t)ptr + sizeof(void*);
    aligned_ptr = (aligned_ptr + alignment - 1) & ~(alignment - 1);

    // Store the original pointer just before the aligned pointer for later deallocation
    ((void**)aligned_ptr)[-1] = ptr;

    return (void*)aligned_ptr;
}

void aligned_free(void* aligned_ptr) {
    if (aligned_ptr) {
        free(((void**)aligned_ptr)[-1]);  // Retrieve and free the original pointer
    }
}



sgx_status_t seal(uint8_t* data, uint32_t data_size, uint8_t* sealed_data, uint32_t sealed_size) {
    // Seal the data inside the enclave
    sgx_status_t ret = sgx_seal_data(0, nullptr, data_size, data, sealed_size, (sgx_sealed_data_t*)sealed_data);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}

sgx_status_t unseal(uint8_t* sealed_data, uint32_t sealed_size, uint8_t* unsealed_data, uint32_t unsealed_size) {
    // Unseal the data inside the enclave
    sgx_status_t ret = sgx_unseal_data(
        (sgx_sealed_data_t*)sealed_data,  // Cast sealed_data to sgx_sealed_data_t*
        nullptr,                           // MAC text (optional, can be null)
        nullptr,                           // Additional MAC text size (optional, can be null)
        unsealed_data,                     // Pointer to output buffer for unsealed data
        &unsealed_size                     // Pass the address of unsealed_size
    );

    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}

uint32_t ecall_calc_sealed_size(uint32_t data_size) {
    // Calculate the size of the sealed data
    uint32_t sealed_size = sgx_calc_sealed_data_size(0, data_size);

    // Check if the calculation failed (returns UINT32_MAX on failure)
    if (sealed_size == UINT32_MAX) {
        return 0;  // Return 0 to indicate failure (or any error code you prefer)
    }

    return sealed_size;  // Return the calculated sealed size
}


int AES(void) {
    
    // secret key
    Ipp8u key[] = "\x00\x01\x02\x03\x04\x05\x06\x07"
        "\x08\x09\x10\x11\x12\x13\x14\x15";
    // define and setup AES cipher
    int ctxSize;
    ippsAESGetSize(&ctxSize);
    IppsAESSpec* pAES = (IppsAESSpec*)(new Ipp8u[ctxSize]);

    ippsAESInit(key, sizeof(key) - 1, pAES, ctxSize);
    // message to be encrypted
    Ipp8u msg[] = "the quick brown fox jumps over the lazy dog";
    // and initial counter
    Ipp8u ctr0[] = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88"
        "\x77\x66\x55\x44\x33\x22\x11\x00";
    // counter
    Ipp8u ctr[16];
    // init counter before encryption
    memcpy(ctr, ctr0, sizeof(ctr));
    // encrypted message
    Ipp8u ctext[sizeof(msg)];
    // encryption

    ippsAESEncryptCTR(msg, ctext, sizeof(msg), pAES, ctr, 64);
    // init counter before decryption
    memcpy(ctr, ctr0, sizeof(ctr));
    // decrypted message
    Ipp8u rtext[sizeof(ctext)];
    // decryption
    ippsAESDecryptCTR(ctext, rtext, sizeof(ctext), pAES, ctr, 64);
    printf("Decrypted\n");
    printf("%s\n", rtext);
    // remove secret and release resource
    ippsAESInit(0, sizeof(key) - 1, pAES, ctxSize);
    delete[](Ipp8u*)pAES;
    int error = memcmp(rtext, msg, sizeof(msg));
    return 0 == error;
}
static IppsBigNumState* newStrBN(int bitsize, const Ipp8u* pStr, int strLen)
{
    int ctxSize;
    int len32 = (bitsize + 31) / 32; // The length of the integer big number in Ipp32u
    IppsBigNumState* pBN;
    ippsBigNumGetSize(len32, &ctxSize);
    pBN = (IppsBigNumState*)malloc(ctxSize);
    ippsBigNumInit(len32, pBN);
    if (pStr && strLen > 0) {
        ippsSetOctString_BN(pStr, strLen, pBN);
    }
    return pBN;
}
static void deleteBN(IppsBigNumState* pBN) {
    free(pBN);
}
static IppsGFpState* newGFp(int bitsize, const Ipp8u* pPrimeStr, int strLen)
{
    IppsBigNumState* pPrime = newStrBN(bitsize, pPrimeStr, strLen);
    IppsGFpState* pGF = 0;
    if (pPrimeStr && strLen > 0) {
        int ctxSize;
        ippsGFpGetSize(bitsize, &ctxSize);
        pGF = (IppsGFpState*)malloc(ctxSize);
        ippsGFpInitArbitrary(pPrime, bitsize, pGF);
    }
    deleteBN(pPrime);
    return pGF;
}
static void deleteGFp(IppsGFpState* pGF)
{
    free(pGF);
}
static IppsGFpElement* newStrElement(const Ipp8u* pStr, int strLen, IppsGFpState* pGF)
{
    int ctxSize = 0;
    IppsGFpElement* pE = 0;
    ippsGFpElementGetSize(pGF, &ctxSize);
    pE = (IppsGFpElement*)malloc(ctxSize);
    ippsGFpElementInit(0, 0, pE, pGF);
    if (pStr && strLen > 0)
        ippsGFpSetElementOctString(pStr, strLen, pE, pGF);
    return pE;
}
static void deleteElement(IppsGFpElement* pE)
{
    free(pE);
}
static IppsGFpECState* newEC(const IppsGFpElement* pA, const IppsGFpElement* pB,
    const IppsGFpElement* pX, const IppsGFpElement* pY, const IppsBigNumState* pN,
    const IppsGFpState* pGF)
{
    Ipp8u cofactor_str[] = "\x00\x00\x00\x01";
    IppsBigNumState* pCofactor = newStrBN(32, cofactor_str, sizeof(cofactor_str) - 1);

    int ctxSize = 0;
    IppsGFpECState* pEC = 0;

    // EC over GF
    ippsGFpECGetSize(pGF, &ctxSize);
    pEC = (IppsGFpECState*)malloc(ctxSize);
    ippsGFpECInit(pGF, pA, pB, pEC);
    ippsGFpECSetSubgroup(pX, pY, pN, pCofactor, pEC);

    deleteBN(pCofactor);
    return pEC;
}
static void deleteEC(IppsGFpECState* pEC)
{
    free(pEC);
}
static IppsGFpECPoint* newECPoint(IppsGFpECState* pEC)
{
    int ctxSize = 0;
    IppsGFpECPoint* pPoint = 0;
    ippsGFpECPointGetSize(pEC, &ctxSize);
    pPoint = (IppsGFpECPoint*)malloc(ctxSize);
    ippsGFpECPointInit(0, 0, pPoint, pEC);
    return pPoint;
}
static void deleteECPoint(IppsGFpECPoint* pPoint)
{
    free(pPoint);
}

int PKE_Sample() {
    const Ipp8u pMsg[] = "\x65\x6E\x63\x72\x79\x70\x74\x69\x6F\x6E\x20\x73\x74\x61\x6E\x64\x61\x72\x64";
    const Ipp8u pKAT[] = "\x04\x24\x5C\x26\xFB\x68\xB1\xDD\xDD\xB1\x2C\x4B\x6B\xF9\xF2\xB6\xD5\xFE\x60\xA3\x83\xB0\xD1\x8D\x1C\x41\x44\xAB\xF1\x7F\x62\x52\xE7\x76\xCB\x92\x64\xC2\xA7\xE8\x8E\x52\xB1\x99\x03\xFD\xC4\x73\x78\xF6\x05\xE3\x68\x11\xF5\xC0\x74\x23\xA2\x4B\x84\x40\x0F\x01\xB8\x65\x00\x53\xA8\x9B\x41\xC4\x18\xB0\xC3\xAA\xD0\x0D\x88\x6C\x00\x28\x64\x67\x9C\x3D\x73\x60\xC3\x01\x56\xFA\xB7\xC8\x0A\x02\x76\x71\x2D\xA9\xD8\x09\x4A\x63\x4B\x76\x6D\x3A\x28\x5E\x07\x48\x06\x53\x42\x6D";

    int msgLen = sizeof(pMsg) - 1;
    int katLen = sizeof(pKAT) - 1;
    
    int failed = 0;

    const int GFp256 = 256;

    // underlying GF over prime
    int gfbitsize = GFp256;
    Ipp8u P_str[] = "\x85\x42\xD6\x9E\x4C\x04\x4F\x18\xE8\xB9\x24\x35\xBF\x6F\xF7\xDE\x45\x72\x83\x91\x5C\x45\x51\x7D\x72\x2E\xDB\x8B\x08\xF1\xDF\xC3";
    IppsGFpState* gf256 = newGFp(gfbitsize, P_str, sizeof(P_str) - 1);

    // EC parameters
    Ipp8u A_str[] = "\x78\x79\x68\xB4\xFA\x32\xC3\xFD\x24\x17\x84\x2E\x73\xBB\xFE\xFF\x2F\x3C\x84\x8B\x68\x31\xD7\xE0\xEC\x65\x22\x8B\x39\x37\xE4\x98";
    Ipp8u B_str[] = "\x63\xE4\xC6\xD3\xB2\x3B\x0C\x84\x9C\xF8\x42\x41\x48\x4B\xFE\x48\xF6\x1D\x59\xA5\xB1\x6B\xA0\x6E\x6E\x12\xD1\xDA\x27\xC5\x24\x9A";
    Ipp8u X_str[] = "\x42\x1D\xEB\xD6\x1B\x62\xEA\xB6\x74\x64\x34\xEB\xC3\xCC\x31\x5E\x32\x22\x0B\x3B\xAD\xD5\x0B\xDC\x4C\x4E\x6C\x14\x7F\xED\xD4\x3D";
    Ipp8u Y_str[] = "\x06\x80\x51\x2B\xCB\xB4\x2C\x07\xD4\x73\x49\xD2\x15\x3B\x70\xC4\xE5\xD7\xFD\xFC\xBF\xA3\x6E\xA1\xA8\x58\x41\xB9\xE4\x6E\x09\xA2";
    Ipp8u N_str[] = "\x85\x42\xD6\x9E\x4C\x04\x4F\x18\xE8\xB9\x24\x35\xBF\x6F\xF7\xDD\x29\x77\x20\x63\x04\x85\x62\x8D\x5A\xE7\x4E\xE7\xC3\x2E\x79\xB7";

    IppsGFpElement* eA = newStrElement(A_str, sizeof(A_str) - 1, gf256);
    IppsGFpElement* eB = newStrElement(B_str, sizeof(B_str) - 1, gf256);
    IppsGFpElement* eX = newStrElement(X_str, sizeof(X_str) - 1, gf256);
    IppsGFpElement* eY = newStrElement(Y_str, sizeof(Y_str) - 1, gf256);
    IppsBigNumState* pN = newStrBN(gfbitsize, N_str, sizeof(N_str) - 1);

    // EC
    IppsGFpECState* pEC = newEC(eA, eB, eX, eY, pN, gf256);

    // sender's key pairs
    Ipp8u privA_str[33] = "\x4C\x62\xEE\xFD\x6E\xCF\xC2\xB9\x5B\x92\xFD\x6C\x3D\x95\x75\x14\x8A\xFA\x17\x42\x55\x46\xD4\x90\x18\xE5\x38\x8D\x49\xDD\x7B\x4F";
    IppsBigNumState* pPrivateA = newStrBN(gfbitsize, privA_str, sizeof(privA_str) - 1);
    IppsGFpECPoint* pPublicA = newECPoint(pEC);

    // recipient's key pairs
    Ipp8u privB_str[] = "\x16\x49\xAB\x77\xA0\x06\x37\xBD\x5E\x2E\xFE\x28\x3F\xBF\x35\x35\x34\xAA\x7F\x7C\xB8\x94\x63\xF2\x08\xDD\xBC\x29\x20\xBB\x0D\xA0";
    IppsBigNumState* pPrivateB = newStrBN(gfbitsize, privB_str, sizeof(privB_str) - 1);
    IppsGFpECPoint* pPublicB = newECPoint(pEC);

    // EC work buffer
    int ecBufferSize = 0;
    CHECK(ippsGFpECScratchBufferSize(1, pEC, &ecBufferSize));
    Ipp8u* pECScratchBuffer = (Ipp8u*)malloc(ecBufferSize);

    CHECK(ippsGFpECPublicKey(pPrivateA, pPublicA, pEC, pECScratchBuffer));
    CHECK(ippsGFpECPublicKey(pPrivateB, pPublicB, pEC, pECScratchBuffer));

    // encryption
    {
        int ctxSize = 0;
        IppsECESState_SM2* esSm2State = 0;

        // ES SM2 context
        CHECK(ippsGFpECESGetSize_SM2(pEC, &ctxSize));
        esSm2State = (IppsECESState_SM2*)malloc(ctxSize);
        CHECK(ippsGFpECESInit_SM2(pEC, esSm2State, ctxSize));

        int edBuffer_HeadSize;
        int edBuffer_TailSize;
        CHECK(ippsGFpECESGetBuffersSize_SM2(&edBuffer_HeadSize, &edBuffer_TailSize, esSm2State));
        ++edBuffer_HeadSize; // 0x04
        int edBufferSize = edBuffer_HeadSize + msgLen + edBuffer_TailSize;
        Ipp8u* edBuffer = (Ipp8u*)malloc(edBufferSize);

        // set enc keys
        CHECK(ippsGFpECESSetKey_SM2(pPrivateA, pPublicB, esSm2State, pEC, pECScratchBuffer));

        // get head of bufferED
        edBuffer[0] = 0x04;
        CHECK(ippsGFpECGetPointOctString(pPublicA, edBuffer + 1, edBuffer_HeadSize - 1, pEC));

        // encryption
        CHECK(ippsGFpECESStart_SM2(esSm2State));
        CHECK(ippsGFpECESEncrypt_SM2(pMsg, edBuffer + edBuffer_HeadSize, msgLen, esSm2State));
        CHECK(ippsGFpECESFinal_SM2(edBuffer + edBuffer_HeadSize + msgLen, edBuffer_TailSize, esSm2State));

        /* test encryption result */
        if (katLen != edBufferSize) {
            printf("Encryption length failed: %d instead of %d\n", edBufferSize, katLen);
            failed = 1;
        }

        if (0 == failed && memcmp(pKAT, edBuffer, katLen)) {
            printf("Encryption failed: output mismatch\n");
            failed = 1;
        }

        // Decryption
        IppsECESState_SM2* dsSm2State = 0;

        // DS SM2 context
        CHECK(ippsGFpECESGetSize_SM2(pEC, &ctxSize));
        dsSm2State = (IppsECESState_SM2*)malloc(ctxSize);
        CHECK(ippsGFpECESInit_SM2(pEC, dsSm2State, ctxSize));

        Ipp8u* decryptedMsg = (Ipp8u*)malloc(msgLen);

        // set dec keys
        CHECK(ippsGFpECESSetKey_SM2(pPrivateB, pPublicA, dsSm2State, pEC, pECScratchBuffer));

        // decryption
        CHECK(ippsGFpECESStart_SM2(dsSm2State));
        CHECK(ippsGFpECESDecrypt_SM2(edBuffer + edBuffer_HeadSize, decryptedMsg, msgLen, dsSm2State));
        CHECK(ippsGFpECESFinal_SM2(edBuffer + edBuffer_HeadSize + msgLen, edBuffer_TailSize, dsSm2State));

        // Validate decryption
        if (memcmp(pMsg, decryptedMsg, msgLen)) {
            printf("Decryption failed: output mismatch\n");
            failed = 1;
        }
        else {
            printf("Decryption test passed!\n");
        }

        free(esSm2State);
        free(dsSm2State);
        free(edBuffer);
        free(decryptedMsg);
    }

    if (failed == 0)
        printf("Encryption test passed!\n");



    free(pECScratchBuffer);
    deleteECPoint(pPublicB);
    deleteBN(pPrivateB);
    deleteECPoint(pPublicA);
    deleteBN(pPrivateA);
    deleteEC(pEC);
    deleteBN(pN);
    deleteElement(eY);
    deleteElement(eX);
    deleteElement(eB);
    deleteElement(eA);
    deleteGFp(gf256);

    return 0;
}

void computeHMAC_SHA512(const Ipp8u* pKey, int keyLen, const Ipp8u* pData, int dataLen, Ipp8u* pDigest) {
    IppStatus status;
    int ctxSize = 0;

    // Get the size of the HMAC SHA-512 context
    status = ippsHMACGetSize_rmf(&ctxSize);
    if (status != ippStsNoErr) {
        printf("Error getting HMAC context size: %d\n", status);
        return;
    }
    
    // Allocate the HMAC context
     IppsHMACState_rmf* pHMAC = (IppsHMACState_rmf*)malloc(ctxSize);

    // Initialize the HMAC context for SHA-512
    const IppsHashMethod* pMethod = ippsHashMethod_SHA512();
    status = ippsHMACInit_rmf(pKey, keyLen, pHMAC, pMethod);
    if (status != ippStsNoErr) {
        printf("Error initializing HMAC: %d\n", status);
        free(pHMAC);
        return;
    }
    
    // Update the HMAC context with the input data
    status = ippsHMACUpdate_rmf(pData, dataLen, pHMAC);
    if (status != ippStsNoErr) {
        printf("Error updating HMAC: %d\n", status);
        free(pHMAC);
        return;
    }
  
    // Finalize the HMAC computation and get the result
    status = ippsHMACFinal_rmf(pDigest, HMAC_DIGEST_SIZE, pHMAC);
    if (status != ippStsNoErr) {
        printf("Error finalizing HMAC: %d\n", status);
    }

    // Clean up
    free(pHMAC);
}

Ipp32u get_random_seed() {
    unsigned int random_seed;
    if (_rdrand32_step(&random_seed)) {
        return random_seed;  // Successfully generated random number
    }
    else {
        return 42;  // Fallback if RDRAND is not available
    }
}

Ipp32u get_deterministic_seed() {
    return 12345;  
}

void Setup(IppsECCPState** ecState, Ipp8u** msk) {
    int ecStateSize;
    ippsECCPGetSize(256, &ecStateSize);
    *ecState = (IppsECCPState*)aligned_malloc(ecStateSize, 64);  // Use aligned_malloc with 64-byte alignment
    ippsECCPInit(256, *ecState);

    // Set the elliptic curve parameters
    ippsECCPSetStd(IppECCPStd256r1, *ecState);

    // Generate a hard-coded master secret key (msk)
    IppsBigNumState* pRandBN;
    IppsBigNumState* pSeedBN;
    Ipp32u seed = get_deterministic_seed();
    IppsPRNGState* pPRNG;
    int prngSize, bnSize;

    ippsPRNGGetSize(&prngSize);
    pPRNG = (IppsPRNGState*)aligned_malloc(prngSize, 64);  // Aligned memory for PRNG
    ippsPRNGInit(160, pPRNG);

    ippsBigNumGetSize(32, &bnSize);  // 32-bit number for seed
    pSeedBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum seed
    ippsBigNumInit(32, pSeedBN);
    ippsSet_BN(IppsBigNumPOS, 1, &seed, pSeedBN);
    ippsPRNGSetSeed(pSeedBN, pPRNG);

    ippsBigNumGetSize(256, &bnSize);  // 256-bit number
    pRandBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum random number
    ippsBigNumInit(256, pRandBN);

    ippsPRNGen_BN(pRandBN, 256, pPRNG);  // 256-bit random number for msk
    *msk = (Ipp8u*)aligned_malloc(256 / 8, 64);  // Allocate aligned 256-bit (32 bytes) for msk
    ippsGetOctString_BN(*msk, 256 / 8, pRandBN);

    aligned_free(pRandBN);
    aligned_free(pSeedBN);
    aligned_free(pPRNG);
}

void CEval1(IppsECCPState* ecState, const Ipp8u* x, IppsECCPPointState** ch, IppsBigNumState** k) {
    int pointSize;
    ippsECCPPointGetSize(256, &pointSize);
    *ch = (IppsECCPPointState*)aligned_malloc(pointSize, 64);  // Aligned memory for ECCPPoint
    ippsECCPPointInit(256, *ch);

    int bnSize;
    ippsBigNumGetSize(256, &bnSize);  // 256-bit number
    *k = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum scalar
    ippsBigNumInit(256, *k);

    // Generate a random scalar k
    Ipp32u seed = get_random_seed();
    IppsPRNGState* prng;
    int prngSize;
    ippsPRNGGetSize(&prngSize);
    prng = (IppsPRNGState*)aligned_malloc(prngSize, 64);  // Aligned memory for PRNG
    ippsPRNGInit(160, prng);
    IppsBigNumState* seedBN;
    ippsBigNumGetSize(32, &bnSize);  // 32-bit number for seed
    seedBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum seed
    ippsBigNumInit(32, seedBN);
    ippsSet_BN(IppsBigNumPOS, 1, &seed, seedBN);
    ippsPRNGSetSeed(seedBN, prng);
    ippsPRNGen_BN(*k, 256, prng);  // 256-bit random number

    // Hash the passphrase to an ECC point
    ippsGFpECSetPointHash(0, x, strlen((const char*)x), *ch, ecState, ippHashAlg_SHA256, NULL);

    // Multiply the hashed point by the random scalar k to produce ch
    ippsECCPMulPointScalar(*ch, *k, *ch, ecState);

    aligned_free(seedBN);
    aligned_free(prng);
}

void SEval(IppsECCPState* ecState, IppsECCPPointState* ch, const Ipp8u* msk, IppsECCPPointState** rp) {
    int pointSize;
    ippsECCPPointGetSize(256, &pointSize);
    *rp = (IppsECCPPointState*)aligned_malloc(pointSize, 64);  // Aligned memory for ECCPPoint
    ippsECCPPointInit(256, *rp);

    // Convert msk to big number
    IppsBigNumState* mskBN;
    int bnSize;
    ippsBigNumGetSize(LAMBDA / 8, &bnSize);
    mskBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum msk
    ippsBigNumInit(LAMBDA / 8, mskBN);
    ippsSetOctString_BN(msk, LAMBDA / 8, mskBN);
    // Compute rp = ch * msk
    ippsECCPMulPointScalar(ch, mskBN, *rp, ecState);

    aligned_free(mskBN);
}


void CEval2(IppsECCPState* ecState, IppsECCPPointState* rp, IppsBigNumState* k, Ipp8u** y, const Ipp8u* x) {
    *y = (Ipp8u*)aligned_malloc(LAMBDA / 8, 64);  // Allocate aligned memory for y

    // Convert rp to octet string
    int rpSize;
    ippsECCPPointGetSize(256, &rpSize);
    Ipp8u* rpOct = (Ipp8u*)aligned_malloc(rpSize, 64);  // Allocate aligned memory for rpOct

    IppsBigNumState* rpX, * rpY;
    int bnSize;
    ippsBigNumGetSize(256 / 8, &bnSize);
    rpX = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum rpX
    rpY = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum rpY
    ippsBigNumInit(256 / 8, rpX);
    ippsBigNumInit(256 / 8, rpY);

    ippsECCPGetPoint(rpX, rpY, rp, ecState);
    ippsGetOctString_BN(rpOct, LAMBDA / 8, rpX);

    // Inverse the random scalar k
    IppsBigNumState* kInv;
    ippsBigNumGetSize(LAMBDA / 8, &bnSize);
    kInv = (IppsBigNumState*)aligned_malloc(bnSize, 64);  // Aligned memory for BigNum kInv
    ippsBigNumInit(LAMBDA / 8, kInv);
    ippsModInv_BN(k, NULL, kInv);  // NULL is used for the modulus

    // Unblind the rp point
    ippsECCPMulPointScalar(rp, kInv, rp, ecState);

    // Convert the unblinded rp point to octet string
    ippsECCPGetPoint(rpX, rpY, rp, ecState);
    ippsGetOctString_BN(rpOct, LAMBDA / 8, rpX);

    // Hash the result with the passphrase
    Ipp8u temp[LAMBDA / 8];
    for (int i = 0; i < LAMBDA / 8; i++) {
        temp[i] = rpOct[i] ^ x[i % strlen((const char*)x)];
    }
    ippsHashMessage(temp, LAMBDA / 8, *y, ippHashAlg_SHA256);

    aligned_free(rpOct);
    aligned_free(rpX);
    aligned_free(rpY);
    aligned_free(kInv);
}

int IBOPRF(uint8_t* ecPBytes, uint32_t ecPBytesLen, uint8_t* userIDBytes, uint32_t userIDLength) {
    /*
    IppsECCPState* ecState = NULL;
    Ipp8u* msk = NULL;
    Ipp8u* id = (Ipp8u*)"client_identity";
    Ipp8u* x = (Ipp8u*)"user_passphrase";
    IppsECCPPointState* ch = NULL, * rp = NULL;
    Ipp8u* y = NULL;
    IppsBigNumState* k = NULL;
    */

    IppsECCPState* ecState = NULL;
    Ipp8u* msk = NULL;
    IppsECCPPointState* ch = NULL;
    IppsECCPPointState* rp = NULL;


    Setup(&ecState, &msk);

    Ipp8u hmacResult[HMAC_DIGEST_SIZE];  // Output for HMAC-SHA512

    printf("Computing HMAC-SHA512 with userID...\n");
    
    computeHMAC_SHA512(msk, 32, userIDBytes, userIDLength, hmacResult);

    // Convert the HMAC result to a BigNum for scalar multiplication
    IppsBigNumState* hmacBN;
    int bnSizeB;
    ippsBigNumGetSize(256 / 8, &bnSizeB);  // 256-bit number
    hmacBN = (IppsBigNumState*)aligned_malloc(bnSizeB, 64);  // Aligned memory for BigNum HMAC
    ippsBigNumInit(256 / 8, hmacBN);

    // Use the first 256 bits (32 bytes) of the HMAC result as the scalar
    ippsSetOctString_BN(hmacResult, 32, hmacBN);

    int pointSize;
    ippsECCPPointGetSize(256, &pointSize);
    ch = (IppsECCPPointState*)aligned_malloc(pointSize, 64);
    ippsECCPPointInit(256, ch);

    IppsBigNumState* xBN;
    IppsBigNumState* yBN;
    int bnSize;
    ippsBigNumGetSize(256 / 8, &bnSize);

    xBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);
    yBN = (IppsBigNumState*)aligned_malloc(bnSize, 64);

    ippsBigNumInit(256 / 8, xBN);
    ippsBigNumInit(256 / 8, yBN);

    // Extract X and Y coordinates from `ecBytes`
    ippsSetOctString_BN(ecPBytes + 1, 32, xBN);  // X coordinate is the first 32 bytes after the prefix
    ippsSetOctString_BN(ecPBytes + 33, 32, yBN); // Y coordinate is the next 32 bytes

    // Step 4: Set the elliptic curve point `ch` using X and Y coordinates
    IppStatus status = ippsECCPSetPoint(xBN, yBN, ch, ecState);

    if (status != ippStsNoErr) {
        printf("Error parsing EC point from ecBytes: %d\n", status);
        aligned_free(ecState);
        aligned_free(msk);
        aligned_free(ch);
        return -1;
    }

    // Step 4: Initialize the output point `rp` for the result of SEval
    rp = (IppsECCPPointState*)aligned_malloc(pointSize, 64);
    ippsECCPPointInit(256, rp);

    // Step 5: Perform server-side evaluation (SEval)
    //SEval(ecState, ch, msk, &rp);
    ippsECCPMulPointScalar(ch, hmacBN, rp, ecState);

    IppECResult isValid;

    IppStatus statusA = ippsECCPCheckPoint(rp, &isValid, ecState);
    if (statusA != ippStsNoErr) {
        printf("Error during ECCPCheckPoint: %d\n", status);
    }

    if (isValid == ippECValid) {
        printf("The elliptic curve point is valid.\n");
    }
    else {
        printf("The elliptic curve point is INVALID.\n");
    }

    Ipp8u rpBytes[65];
    rpBytes[0] = 0x04;

    IppsBigNumState* rpX;
    IppsBigNumState* rpY;
    int bnSizeA;
    ippsBigNumGetSize(256, &bnSizeA);  // For 256-bit numbers (32 bytes)
    rpX = (IppsBigNumState*)aligned_malloc(bnSizeA, 64);
    rpY = (IppsBigNumState*)aligned_malloc(bnSizeA, 64);
    ippsBigNumInit(256, rpX);
    ippsBigNumInit(256, rpY);

    // Get X and Y coordinates from the point `rp`
    status = ippsECCPGetPoint(rpX, rpY, rp, ecState);
    if (status != ippStsNoErr) {
        printf("Error extracting X and Y coordinates from EC point: %d\n", status);
        aligned_free(ecState);
        aligned_free(msk);
        aligned_free(ch);
        aligned_free(rp);
        aligned_free(rpX);
        aligned_free(rpY);
        return SGX_ERROR_UNEXPECTED;
    }

    // Step 7: Convert X and Y coordinates to byte arrays
    //Ipp8u rpXBytes[32], rpYBytes[32];  // 256-bit numbers are 32 bytes
    ippsGetOctString_BN(rpBytes + 1, 32, rpX);
    ippsGetOctString_BN(rpBytes + 33, 32, rpY);

    // Print the X and Y coordinates as hex
    printf("rp coordinates: ");
    for (int i = 0; i < 65; i++) {
        printf("%02X", rpBytes[i]);
    }
    printf("\n");

    //printf("rp Y coordinate: ");
    //for (int i = 0; i < 32; i++) {
      //  printf("%02X", rpYBytes[i]);
    //}
    //printf("\n");
    
    //CEval1(ecState, x, &ch, &k);

    //SEval(ecState, ch, msk, &rp);

    //CEval2(ecState, rp, k, &y, x);

    /*
    printf("Generated password: ");
    for (int i = 0; i < LAMBDA / 8; i++) {
        printf("%02X", y[i]);
    }
    printf("\n");
    */

    aligned_free(ecState);
    aligned_free(msk);
    aligned_free(ch);
    aligned_free(rp);
    aligned_free(rpX);
    aligned_free(rpY);
    aligned_free(hmacBN);

    /*
    aligned_free(ecState);
    aligned_free(msk);
    aligned_free(y);
    aligned_free(k);
    aligned_free(ch);
    aligned_free(rp);
    */
    return 0;
}



static IppsECCPState* newStd_256_ECP(void) {
    int ctxSize;
    ippsECCPGetSize(256, &ctxSize);
    IppsECCPState* pCtx = (IppsECCPState*)(new Ipp8u[ctxSize]);
    ippsECCPInit(256, pCtx);
    ippsECCPSetStd(IppECCPStd256r1, pCtx);
    return pCtx;
}
static IppsECCPPointState* newECP_256_Point(void) {
    int ctxSize;
    ippsECCPPointGetSize(256, &ctxSize);
    IppsECCPPointState* pPoint = (IppsECCPPointState*)(new Ipp8u[ctxSize]);
    ippsECCPPointInit(256, pPoint);
    return pPoint;
}
static IppsBigNumState* newBN(int len, const Ipp32u* pData) {
    int ctxSize;
    ippsBigNumGetSize(len, &ctxSize);
    IppsBigNumState* pBN = (IppsBigNumState*)(new Ipp8u[ctxSize]);
    ippsBigNumInit(len, pBN);
    if (pData)
        ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
    return pBN;
}
IppsPRNGState* newPRNG(void) {
    int ctxSize;
    ippsPRNGGetSize(&ctxSize);
    IppsPRNGState* pCtx = (IppsPRNGState*)(new Ipp8u[ctxSize]);
    ippsPRNGInit(160, pCtx);
    return pCtx;
}
int ECDSA() {
    // define standard 256-bit EC
    IppsECCPState* pECP = newStd_256_ECP();

    // extract or use any other way to get order(ECP)
    const Ipp32u secp256r1_r[] = { 0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
    const int ordSize = sizeof(secp256r1_r) / sizeof(Ipp32u);
    IppsBigNumState* pECPorder = newBN(ordSize, secp256r1_r);

    // define a message to be signed; let it be random, for example
    IppsPRNGState* pRandGen = newPRNG(); // 'external' PRNG

    Ipp32u tmpData[ordSize];
    ippsPRNGen(tmpData, 256, pRandGen);
    IppsBigNumState* pRandMsg = newBN(ordSize, tmpData); // random 256-bit message
    IppsBigNumState* pMsg = newBN(ordSize, 0); // msg to be signed
    ippsMod_BN(pRandMsg, pECPorder, pMsg);

    // declare Signer's regular and ephemeral key pair
    IppsBigNumState* regPrivate = newBN(ordSize, 0);
    IppsBigNumState* ephPrivate = newBN(ordSize, 0);

    // define Signer's ephemeral key pair
    IppsECCPPointState* regPublic = newECP_256_Point();
    IppsECCPPointState* ephPublic = newECP_256_Point();
    // generate regular & ephemeral key pairs, should be different each other
    ippsECCPGenKeyPair(regPrivate, regPublic, pECP, ippsPRNGen, pRandGen);
    ippsECCPGenKeyPair(ephPrivate, ephPublic, pECP, ippsPRNGen, pRandGen);

    // signature
    // set ephemeral key pair
    ippsECCPSetKeyPair(ephPrivate, ephPublic, ippFalse, pECP);
    // compute signature
    IppsBigNumState* signX = newBN(ordSize, 0);
    IppsBigNumState* signY = newBN(ordSize, 0);
    ippsECCPSignDSA(pMsg, regPrivate, signX, signY, pECP);

    // verification
    ippsECCPSetKeyPair(NULL, regPublic, ippTrue, pECP);
    IppECResult eccResult;
    ippsECCPVerifyDSA(pMsg, signX, signY, &eccResult, pECP);
    if (ippECValid == eccResult)
        printf("signature verification passed\n");
    else
        printf("signature verification failed\n");

    delete[](Ipp8u*)signX;
    delete[](Ipp8u*)signY;
    delete[](Ipp8u*)ephPublic;
    delete[](Ipp8u*)regPublic;
    delete[](Ipp8u*)ephPrivate;
    delete[](Ipp8u*)regPrivate;
    delete[](Ipp8u*)pRandMsg;
    delete[](Ipp8u*)pMsg;
    delete[](Ipp8u*)pRandGen;
    delete[](Ipp8u*)pECPorder;
    delete[](Ipp8u*)pECP;
    return 0;
}

sgx_status_t ecall_call_aes(uint8_t* ecBytes, uint32_t ecBytesLen, uint8_t* userIDBytes, uint32_t userIDLength) {



    // Ensure that the incoming buffer is valid
    if (ecBytes == NULL || ecBytesLen == 0) {
        printf("Invalid ecBytes or ecBytesLen.");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    char buffer[256];
    //snprintf(buffer, sizeof(buffer), "Received ecBytes of length %u in enclave: ", ecBytesLen);
    //printf(buffer);

    printf("Received ecBytes of length 65 in enclaveE: ");
    for (int i = 0; i < 65; ++i) {
        printf("%02X", (unsigned char)ecBytes[i]);
    }
    printf("\n");

    for (uint32_t i = 0; i < ecBytesLen; i++) {
        snprintf(buffer, sizeof(buffer), "%02X", ecBytes[i]);
        printf(buffer);
    }
    printf("\n");

    //int result = AES();
    //int resultB = PKE_Sample();
    //int resultC = ECDSA();
    int resultD = IBOPRF(ecBytes, ecBytesLen, userIDBytes, userIDLength);


    
    if (resultD == 0) {
        printf("IBOPRF ECALL executed successfully.\n");
        return SGX_SUCCESS;
    }
    else {
        printf("IBOPRF ECALL failed or returned an error.\n");
        return SGX_ERROR_UNEXPECTED;
    }
    
  
}


