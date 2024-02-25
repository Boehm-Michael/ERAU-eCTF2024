// Global Variables for Purposes 

//struct for header
// include orgin address (global variable in AP)
// include purpose (int) 

//struct for tail 
// include MD5 - call from woldssl - this is to verify the checksum 
// include struct for sequence (int) 
// include comp1, comp2 (make int sequence == struct.comp1) to verify and stop Man in the middle attacks 


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/openssl/md5.h>

//Purpose variables 
#define ATTESTATION 0 
#define PING 1
#define CHALLENGE 2

//CCSDS Packet 
CCSDS_Packet ccsdsPacket_new(){
    res.primary_header = malloc(HEADER_LENGTH);
    res.dataField = malloc(2*sizeof(void *)); 
    return res;
}

// Struct for Header
typedef struct {
    int orginAddress;
    int purpose;
} Header;

// data field 
CCSDS_data_field ccsdsDataField(CC)

// Struct for Tail
typedef struct {
    // call MD5
    WOLFSSL_MD5_CTX md5;
    unsigned char hash[16]; // i think this is where the 128 bits hash goes ?

    int sequence; 
    typedef struct {
        int comp1_seq;
        int comp2_seq;
    } Component;
} Tail;

// // add the header to the encrypted data 
// void addHeader(){
//     Header header;
//     header.orginAddress = //the global address;
//     header.purpose = //purpose number;

//     // This is how to copy the header to the packet 
//     // memcpy(data, &header, sizeof(SDLS_Header));
// }
