/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_crypto.h"

#ifdef POST_BOOT
#include <stdint.h>
#include <stdio.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

// #include <wolfssl/openssl/options.h>
#include <wolfssl/openssl/aes.h>
#include <wolfssl/openssl/random.h>
#include <wolfssl/openssl/sha256.h>


/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/
#define AES_KEY_SIZE 32 // For AES-256
#define MAX_BUFFER_SIZE 1024 // Might need adjustment


// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
byte aes_key[AES_KEY_SIZE] = { /* Initialize with AES key bytes */ };
byte iv[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE is typically 16 bytes for AES
static const byte hardcoded_secret[] = { /* ... secret bytes ... */ };

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, byte* buffer, int len, Aes* aes) {
    byte encryptedBuffer[MAX_BUFFER_SIZE]; // Ensure this buffer is large enough for the encrypted data

    // Assuming the AES key has already been securely exchanged and initialized in `aes`
    wc_AesSetKey(aes, aes_key, AES_KEY_SIZE, iv, AES_ENCRYPTION);
    wc_AesCbcEncrypt(aes, encryptedBuffer, buffer, len);

    // Now `encryptedBuffer` contains the encrypted data, which can be sent using `send_packet`
    send_packet(address, encryptedBuffer, len); // Adjust len as needed based on encryption

    return 0; // Simplified return for example purposes
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, byte* buffer, Aes* aes) {
    byte encryptedBuffer[MAX_BUFFER_SIZE]; // Buffer to receive encrypted data

    // Receive the encrypted data
    int receivedLen = poll_and_receive_packet(address, encryptedBuffer);

    // Assuming the AES key has already been securely exchanged and initialized in `aes`
    wc_AesSetKey(aes, aes_key, AES_KEY_SIZE, iv, AES_DECRYPTION);
    wc_AesCbcDecrypt(aes, buffer, encryptedBuffer, receivedLen); // Adjust `receivedLen` as needed

    return receivedLen; // Simplified return for example purposes
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

int derive_key_from_secret() {
    // If the hardcoded secret is not the correct length, hash it to get the key
    int ret = wc_Sha256Hash(hardcoded_secret, sizeof(hardcoded_secret), aes_key);
    return ret == 0 ? SUCCESS_RETURN : ERROR_RETURN;
}

int generate_random_message(byte* message, int message_len) {
    RNG rng;
    int ret = wc_InitRng(&rng);
    if (ret != 0) return ERROR_RETURN;

    ret = wc_RNG_GenerateBlock(&rng, message, message_len);
    wc_FreeRng(&rng);
    return ret == 0 ? SUCCESS_RETURN : ERROR_RETURN;
}

int encrypt_message(const byte* plaintext, int plaintext_len, byte* ciphertext, byte* iv) {
    // Generate a random IV
    RNG rng;
    int ret = wc_InitRng(&rng);
    if (ret != 0) return ERROR_RETURN;

    ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    wc_FreeRng(&rng);
    if (ret != 0) return ERROR_RETURN;

    // Encrypt the plaintext
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    ret = wc_AesSetKey(&aes, aes_key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ERROR_RETURN;
    }

    ret = wc_AesCbcEncrypt(&aes, ciphertext, plaintext, plaintext_len);
    wc_AesFree(&aes);

    return ret == 0 ? SUCCESS_RETURN : ERROR_RETURN;
}

int decrypt_message(const byte* ciphertext, int ciphertext_len, byte* plaintext, const byte* iv) {
    // Initialize AES context for decryption
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ERROR_RETURN;

    // Set the AES key and IV for decryption
    ret = wc_AesSetKey(&aes, aes_key, AES_256_KEY_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) {
        wc_AesFree(&aes);
        return ERROR_RETURN;
    }

    // Decrypt the ciphertext
    ret = wc_AesCbcDecrypt(&aes, plaintext, ciphertext, ciphertext_len);
    wc_AesFree(&aes);

    return ret == 0 ? SUCCESS_RETURN : ERROR_RETURN;
}

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    int result = send_packet(addr, sizeof(uint8_t), transmit);
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Derive the key from the hardcoded secret
    if (derive_key_from_secret() != SUCCESS_RETURN) {
        print_error("Key derivation failed\n");
        return ERROR_RETURN;
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Iterate over each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Generate a random starting sequence number
        uint32_t random_seq_num;
        RNG rng;
        wc_InitRng(&rng);
        wc_RNG_GenerateBlock(&rng, (byte*)&random_seq_num, sizeof(random_seq_num));
        wc_FreeRng(&rng);

        // Generate a random message
        byte random_message[16];
        if (generate_random_message(random_message, sizeof(random_message)) != SUCCESS_RETURN) {
            print_error("Random message generation failed\n");
            return ERROR_RETURN;
        }

        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Prepare the data to send (random_seq_num + random_message)
        byte data_to_send[20]; // 4 bytes of seq_num + 16 bytes of message
        memcpy(data_to_send, &random_seq_num, sizeof(random_seq_num));
        memcpy(data_to_send + sizeof(random_seq_num), random_message, sizeof(random_message));

        // Encrypt the data
        byte iv[AES_BLOCK_SIZE];
        byte encrypted_data[sizeof(data_to_send) + AES_BLOCK_SIZE]; // Account for padding
        if (encrypt_message(data_to_send, sizeof(data_to_send), encrypted_data, iv) != SUCCESS_RETURN) {
            print_error("Data encryption failed\n");
            return ERROR_RETURN;
        }

        // Send the encrypted data and IV to the component
        memcpy(transmit_buffer, encrypted_data, sizeof(encrypted_data));
        memcpy(transmit_buffer + sizeof(encrypted_data), iv, AES_BLOCK_SIZE);
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        // Decrypt the response
        byte decrypted_response[sizeof(data_to_send)];
        if (decrypt_message(receive_buffer, len - AES_BLOCK_SIZE, decrypted_response, iv) != SUCCESS_RETURN) {
            print_error("Response decryption failed\n");
            return ERROR_RETURN;
        }

        // Extract the sequence number and message from the decrypted response
        uint32_t received_seq_num;
        byte received_message[16];
        memcpy(&received_seq_num, decrypted_response, sizeof(received_seq_num));
        memcpy(received_message, decrypted_response + sizeof(received_seq_num), sizeof(received_message));

        // Check that the sequence number is incremented by 1 and the message is the same
        if (received_seq_num != random_seq_num + 1 || 
            memcmp(received_message, random_message, sizeof(received_message)) != 0) {
            print_error("Component validation failed\n");
            return ERROR_RETURN;
        }
        //Logic for sequence number reuse goes here.
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }

    // Print out attestation data 
    print_info("C>0x%08x\n", component_id);
    print_info("%s", receive_buffer);
    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // Example of how to utilize included simple_crypto.h
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    
    // Zero out the key
    bzero(key, BLOCK_SIZE); // Sets key to all 0s... this is bad... obviously - Michael

    
    /***************************** EXAMPLE CRYPTO *******************************/
    //
    //
    // This shows how to use the WolfSSL library, do not use in secure_receive
    // or secure_send.
    //
    /****************************** EXAMPLE CRYPTO *******************************/
    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext); 
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results 
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);
    
    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[50];
    recv_input("Enter pin: ", buf);
    if (!strcmp(buf, AP_PIN)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf);
    if (!strcmp(buf, AP_TOKEN)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
