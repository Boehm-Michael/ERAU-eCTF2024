/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
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
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
// #include "ectf_params.h"
#include "global_secrets.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*

*/
#define AES_KEY_SIZE 32 // For AES-256
#define MAX_BUFFER_SIZE 1024 // Might need adjustment
#define COMPONENT_BOOT_MSG "Component boot"
#define COMPONENT_ID 0x11111124
#define ATTESTATION_LOC "McLean"
#define ATTESTATION_DATE "08/08/08"
#define ATTESTATION_CUSTOMER "Fritz"

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for receiving messages from the AP
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

typedef struct {
    uint32_t component_id;
} validate_message;

typedef struct {
    uint32_t component_id;
} scan_message;

/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_boot(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global varaibles
uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];
static const byte hardcoded_secret[] = {SECRET};
byte aes_key[SHA256_DIGEST_SIZE]; // Use SHA256 hash size for the key
byte iv[AES_BLOCK_SIZE]; // AES_BLOCK_SIZE is typically 16 bytes for AES
/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Securely send data over I2C using AES encryption.
 * 
 * @param buffer Pointer to the plaintext data to be sent.
 * @param len Length of the plaintext data.
 */
void secure_send(uint8_t* buffer, uint8_t len) {
    Aes aes;
    byte encryptedBuffer[MAX_BUFFER_SIZE]; // Ensure this buffer is large enough for the encrypted data

    // Initialize AES for encryption with the pre-shared key and IV
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_ENCRYPTION); // Pass the address of `aes`
    wc_AesCbcEncrypt(&aes, encryptedBuffer, buffer, len);

    // Send the encrypted data over I2C
    send_packet_and_ack(len + AES_BLOCK_SIZE, encryptedBuffer); // Include padding in the length

    wc_AesFree(&aes); // Free AES structure
}

/**
 * @brief Securely receive data over I2C using AES decryption.
 * 
 * @param buffer Pointer to the buffer where decrypted data will be stored.
 * @return int Number of bytes received and decrypted, negative on error.
 */
int secure_receive(uint8_t* buffer) {
    Aes aes;
    byte encryptedBuffer[MAX_BUFFER_SIZE]; // Buffer to receive encrypted data

    // Receive the encrypted data over I2C
    int receivedLen = wait_and_receive_packet(encryptedBuffer);

    if (receivedLen <= 0) {
        return -1; // Error or no data received
    }

    // Initialize AES for decryption with the pre-shared key and IV
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_DECRYPTION); // Pass the address of `aes`
    wc_AesCbcDecrypt(&aes, buffer, encryptedBuffer, receivedLen);

    wc_AesFree(&aes); // Free AES structure

    // Assuming the plaintext is the same length as the ciphertext minus padding
    return receivedLen - AES_BLOCK_SIZE; // Adjust based on your padding scheme
}

/******************************* FUNCTION DEFINITIONS *********************************/

int encrypt_message(const byte* plaintext, int plaintext_len, byte* ciphertext, byte* iv) {
    // Generate a random IV
    // RNG rng;
    // int ret = wc_InitRng(&rng);
    // if (ret != 0) return ERROR_RETURN;

    // int ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    // wc_FreeRng(&rng);
    // if (ret != 0) return ERROR_RETURN;

    // Encrypt the plaintext
    Aes aes;
    wc_AesInit(&aes, NULL, INVALID_DEVID);
    int ret = wc_AesSetKey(&aes, aes_key, AES_256_KEY_SIZE, iv, AES_ENCRYPTION);
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

// Example boot sequence
// Your design does not need to change this
void boot() {

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
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

// Handle a transaction from the AP
void component_process_cmd() {
    command_message* command = (command_message*) receive_buffer;

    // Output to application processor dependent on command received
    switch (command->opcode) {
    case COMPONENT_CMD_BOOT:
        process_boot();
        break;
    case COMPONENT_CMD_SCAN:
        process_scan();
        break;
    case COMPONENT_CMD_VALIDATE:
        process_validate();
        break;
    case COMPONENT_CMD_ATTEST:
        process_attest();
        break;
    default:
        printf("Error: Unrecognized command received %d\n", command->opcode);
        break;
    }
}

void process_boot() {
    // The AP requested a boot. Set `component_boot` for the main loop and
    // respond with the boot message
    uint8_t len = strlen(COMPONENT_BOOT_MSG) + 1;
    memcpy((void*)transmit_buffer, COMPONENT_BOOT_MSG, len);
    send_packet_and_ack(len, transmit_buffer);
    // Call the boot function
    boot();
}

void process_scan() {
    // The AP requested a scan. Respond with the Component ID
    scan_message* packet = (scan_message*) transmit_buffer;
    packet->component_id = COMPONENT_ID;
    send_packet_and_ack(sizeof(scan_message), transmit_buffer);
}

int derive_key_from_secret() {
    // If the hardcoded secret is not the correct length, hash it to get the key
    int ret = wc_Sha256Hash(hardcoded_secret, sizeof(hardcoded_secret), aes_key);
    return ret == 0 ? SUCCESS_RETURN : ERROR_RETURN;
}

void process_validate() {
    // The AP has requested validation.
    uint8_t decrypted_data[20]; // Adjust size as needed for your message + sequence number
    uint8_t iv[AES_BLOCK_SIZE]; // The IV should be received alongside the message

    // Derive the key from the hardcoded secret
    if (derive_key_from_secret() != SUCCESS_RETURN) {
        printf("Key derivation failed\n");
        return;
    }

    // Assuming the first part of the received data is the IV
    memcpy(iv, receive_buffer, AES_BLOCK_SIZE);

    int total_length = sizeof(receive_buffer);
    int ciphertext_len = total_length - AES_BLOCK_SIZE; // Calculate the length of the ciphertext

    // Decrypt the message after the IV
    if (decrypt_message(receive_buffer + AES_BLOCK_SIZE, ciphertext_len, decrypted_data, iv) != SUCCESS_RETURN) {
        printf("Error: Decryption failed\n");
        return;
    }

    // Increment the sequence number by 1
    uint32_t seq_num;
    memcpy(&seq_num, decrypted_data, sizeof(seq_num)); // Extract sequence number
    seq_num += 1; // Increment sequence number

    // Prepare the response data: copy the incremented sequence number back into the buffer
    memcpy(decrypted_data, &seq_num, sizeof(seq_num));

    // Encrypt the response data
    uint8_t encrypted_response[sizeof(decrypted_data) + AES_BLOCK_SIZE]; // Adjust for potential padding due to encryption
    if (encrypt_message(decrypted_data, sizeof(decrypted_data), encrypted_response, iv) != SUCCESS_RETURN) {
        printf("Error: Encryption failed\n");
        return;
    }

    // Send the encrypted response back
    send_packet_and_ack(sizeof(encrypted_response), encrypted_response);
}

void process_attest() {
    // The AP requested attestation. Respond with the attestation data
    uint8_t len = sprintf((char*)transmit_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n",
                ATTESTATION_LOC, ATTESTATION_DATE, ATTESTATION_CUSTOMER) + 1;
    send_packet_and_ack(len, transmit_buffer);
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    
    LED_On(LED2);

    while (1) {
        wait_and_receive_packet(receive_buffer);

        component_process_cmd();
    }
}
