#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <immintrin.h>
#include "sgx_tseal.h"  // Include for sealing functions
#include <fstream>
#include <vector>
#include "sgx_utils.h"
#include "sgx_tcrypto.h"

#define LAMBDA 128
#define K 128


#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
#endif



#include "sgx_urts.h"
#include "ippcp.h"
#include "ipp.h"
#include "App.h"
#include "Enclave_u.h"


#define CHECK(x)                                                                      \
{                                                                                     \
    IppStatus z = x;                                                                  \
    if (z) printf("Line #%d: error in "#x": %s\n", __LINE__, ippcpGetStatusString(z)); \
}


const char* sealed_data_file = "sealed_userids.bin";

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
#ifdef _MSC_VER
    /* try to get the token saved in CSIDL_LOCAL_APPDATA */
    if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, token_path)) {
        strncpy_s(token_path, _countof(token_path), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    } else {
        strncat_s(token_path, _countof(token_path), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
    }

    /* open the token file */
    HANDLE token_handler = CreateFileA(token_path, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
    if (token_handler == INVALID_HANDLE_VALUE) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    } else {
        /* read the token from saved file */
        DWORD read_num = 0;
        ReadFile(token_handler, token, sizeof(sgx_launch_token_t), &read_num, NULL);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#else /* __GNUC__ */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
#endif
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
#ifdef _MSC_VER
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
#else
        if (fp != NULL) fclose(fp);
#endif
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
#ifdef _MSC_VER
    if (updated == FALSE || token_handler == INVALID_HANDLE_VALUE) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (token_handler != INVALID_HANDLE_VALUE)
            CloseHandle(token_handler);
        return 0;
    }
    
    /* flush the file cache */
    FlushFileBuffers(token_handler);
    /* set access offset to the begin of the file */
    SetFilePointer(token_handler, 0, NULL, FILE_BEGIN);

    /* write back the token */
    DWORD write_num = 0;
    WriteFile(token_handler, token, sizeof(sgx_launch_token_t), &write_num, NULL);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    CloseHandle(token_handler);
#else /* __GNUC__ */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
#endif
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}
// Function to check if a user ID already exists in allUserIDs
// Function to check if a user ID already exists in allUserIDs
bool userIDExists(const std::vector<uint8_t>& allUserIDs, const std::vector<uint8_t>& userID) {
    size_t userIDCount = allUserIDs.size() / 28;  // Calculate how many user IDs are stored

    if (userID.size() != 28) {
        printf("Error: userID size is not 28 bytes!\n");
        return false;
    }

    // Iterate over all stored user IDs
    for (size_t i = 0; i < userIDCount; ++i) {
        bool isDuplicate = true;

        // Skip zero-padded entries
        if (allUserIDs[i * 28] == 0) {
            continue;  // Skip this entry if it's zero-padded
        }

        // Compare each 28-byte segment with the new user ID
        for (size_t j = 0; j < 28; ++j) {
            if (allUserIDs[i * 28 + j] != userID[j]) {
                isDuplicate = false;
                break;  // If any byte differs, it's not a duplicate
            }
        }

        if (isDuplicate) {
            printf("Duplicate found at position: %zu\n", i);
            return true;  // If all bytes match, it's a duplicate
        }
    }

    printf("No duplicate found.\n");
    return false;  // No duplicate found
}




/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
       // printf("Enter a character before exit ...\n");
       // getchar();
        return -1; 
    }
    printf("Enclave Initiated.\n");

    // Buffer to receive ecBytes from stdin
    char ecBytes[256];  // Example size, change as per your needs
    uint8_t userIDBytes[256];
    size_t userIDLength = 0;

    size_t totalBytesRead = 0;
    size_t bytesRead = 0;
    int retryCount = 0;
    const int expectedLengthEC = 65;
    const int maxRetries = 3;

    // Loop until we have read the full expected size or exceed the retry count
    while (totalBytesRead < 65) {
        std::cin.read(reinterpret_cast<char*>(ecBytes + totalBytesRead), 65 - totalBytesRead);
        bytesRead = std::cin.gcount();

        totalBytesRead += bytesRead;
    }

    printf("%lld :", bytesRead);
    uint8_t ecBytes_uint8[65];
    for (int i = 0; i < bytesRead; ++i) {
        ecBytes_uint8[i] = static_cast<uint8_t>(ecBytes[i]);  // Cast each byte to uint8_t
    }

    std::cin.read(reinterpret_cast<char*>(&userIDLength), 1);  // Assuming userID length is sent as first byte
    if (userIDLength > 0 && userIDLength < sizeof(userIDBytes)) {
        std::cin.read(reinterpret_cast<char*>(userIDBytes), userIDLength);

        // Print the received userIDBytes
        printf("Received userIDBytes of length %zu: ", userIDLength);
        for (size_t i = 0; i < userIDLength; i++) {
            printf("%02X", userIDBytes[i]);
        }
        printf("\n");
    }
    else {
        printf("Invalid userID length received.\n");
        return -1;
    }

    std::cin.clear();  // Clear the input buffer
    std::cin.sync();

    std::vector<uint8_t> allUserIDs;

    // Attempt to read existing sealed data from file
    std::ifstream sealedFile(sealed_data_file, std::ios::binary);
    sgx_status_t retA;

    if (sealedFile.is_open()) {
        // Get size of the sealed data
        sealedFile.seekg(0, sealedFile.end);
        size_t sealed_size = sealedFile.tellg();
        sealedFile.seekg(0, sealedFile.beg);

        // Read the sealed data into a buffer
        std::vector<uint8_t> sealedData(sealed_size);
        sealedFile.read(reinterpret_cast<char*>(sealedData.data()), sealed_size);
        sealedFile.close();

        

        uint32_t unsealed_data_size;

        ecall_calc_sealed_size(global_eid, &unsealed_data_size, allUserIDs.size());
      
        std::vector<uint8_t> unsealed_data(unsealed_data_size);
        
        // Unseal data
        unseal(global_eid, &retA, sealedData.data(), (uint32_t)sealed_size, unsealed_data.data(), (uint32_t)unsealed_data_size);

        if (retA != SGX_SUCCESS) {
            printf("Unsealing failed with error code: 0x%x\n", retA);
            return -1;
        }

        std::vector<uint8_t> newUserID(userIDBytes, userIDBytes + 28);  // Assuming userIDBytes is 28 bytes
        if (!userIDExists(unsealed_data, newUserID)) {
            // Step 3: Only insert if it's not a duplicate
            allUserIDs.insert(allUserIDs.end(), newUserID.begin(), newUserID.end());
            printf("Inserted new userID.\n");
        }
        else {
            printf("Duplicate User ID detected, skipping insertion.\n");
        }


    }

    // Append the new userIDBytes to the allUserIDs vector
    allUserIDs.insert(allUserIDs.end(), userIDBytes, userIDBytes + userIDLength);

    // Seal the combined user IDs back to a file


  

    // Call the ECALL to calculate the sealed data size
   
    uint32_t sealed_size;
    ecall_calc_sealed_size(global_eid, &sealed_size, allUserIDs.size());

    if (sealed_size == UINT32_MAX) {
        printf("Error calculating sealed data size\n");
        return -1;
    }

    // Allocate buffer for sealing
    std::vector<uint8_t> sealedData(sealed_size);

    // Call ECALL seal, passing the necessary parameters
    seal(global_eid, &retA, allUserIDs.data(), (uint32_t)allUserIDs.size(), sealedData.data(), sealed_size);

    if (retA != SGX_SUCCESS) {
        printf("Sealing failed with error code: 0x%x\n", retA);
        return -1;
    }

    // Write sealed data to file
    std::ofstream outFile(sealed_data_file, std::ios::binary);
    outFile.write(reinterpret_cast<const char*>(sealedData.data()), sealed_size);
    outFile.close();

    // Print the contents of the stored userIDs
    printf("Stored UserIDs:\n");
    for (size_t i = 0; i < allUserIDs.size(); i++) {
        printf("%02X", allUserIDs[i]);
        if ((i + 1) % userIDLength == 0) {
            printf("\n");
        }
    }

  

    // Prepare the return value variable for the ECALL
    sgx_status_t retval;
    
    sgx_status_t ret;

    ecall_call_aes(global_eid, &ret, ecBytes_uint8, (uint32_t) bytesRead, userIDBytes, (uint32_t) userIDLength);
    
    // Check for errors
    if (ret != SGX_SUCCESS) {
        printf("ECALL failed with status: 0x%x\n", ret);
        return -1;
    }
    // Optionally, check the return value from the enclave
    if (ret != SGX_SUCCESS) {
        printf("IBOPRF operation failed inside the enclave with status: 0x%x\n", ret);
    }
    else {
        printf("IBOPRF operation succeeded\n");
    }
    
    
    /* Utilize edger8r attributes */
    edger8r_array_attributes();
    edger8r_pointer_attributes();
    edger8r_type_attributes();
    edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    ecall_libc_functions();
    ecall_libcxx_functions();
    ecall_thread_functions();

    /* Destroy the enclave */
    printf("Info: Sample Enclave successfully returned.\n");

  //  printf("Enter a character before exit ...\n");
   // getchar();

    sgx_destroy_enclave(global_eid);
    
    
    return 0;
}

