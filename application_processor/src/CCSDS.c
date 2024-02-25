
// This goes in the src folder 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "CCSDS.h"

//Purpose variables 
#define ATTESTATION 0 
#define PING 1
#define CHALLENGE 2

// Get endian
const int i = 1;
#define is_bigendian() ( (*(char*)&i) == 0 )

// Define functions
void exampleGenPacketWithoutScdHeader();

// Put in AP
// int main() {
//     exampleGenPacketWithoutScdHeader();
//     return 0;
// }

void exampleGenPacketWithoutScdHeader(){
    // Create packet
    char data[10] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'a'};     // Some test userData

    unsigned short dataLength = sizeof(data);      // Length of the userData field

    CCSDS_data_field dataField = ccsdsDataField(data);        // Create userData field without header

    CCSDS_primary_header primaryHeader = ccsdsPrimaryHeader(0b001, PACKET_TYPE_ATTESTATION,
                                                            0b011, SEQUENCE_FLAG_UNSEGMENTED,
                                                            0b0, dataLength - 1);


    CCSDS_packet packet = ccsdsPacketBuild(&primaryHeader, &dataField);

    // Get packet length
    unsigned short packet_length = PRIMARY_HEADER_LENGTH + dataLength;

    // Write packet into buffer using binary structure of CCSDS
    void* buff = writeInBuffer(&packet);

    FILE *fp;

    fp = fopen("first.bin", "w");
    int bytesWritten = fwrite(buff, packet_length, 1, fp);
    printf("Written successfully %d elements \n", bytesWritten * packet_length);
    fclose(fp);
}

/**
 * Create the skeleton of a CCSDS_packet. Malloc primary_header and dataField and return the pointer
 * @return CCSDS_packet
 */
CCSDS_packet ccsdsPacket_new(){
    CCSDS_packet res;
    res.primary_header = malloc(PRIMARY_HEADER_LENGTH);
    res.dataField = malloc(2*sizeof(void *));
    return res;
}

/**
 * Create a CCSDS_primary_header
 * @param version - 4.1.2.2 Packet Version Number (3 bits) Max value 7
 * @param type - 4.1.2.3.2 Packet Type (1 bit) 0 -> PACKET_TYPE_TELEMETRY, 1 -> PACKET_TYPE_TELECOMMAND
 * @param sec_header_flag - 4.1.2.3.3 Secondary Header Flag (1 bit) 0 -> SECONDAY_HEADER_FLAG_NOTEXIST,
 *                                                                  1 -> SECONDAY_HEADER_FLAG_EXIST
 * @param proc_id - 4.1.2.3.4 Application Process Identifier (11 bits) Max value 2047
 * @param seq_flags - 4.1.2.4.2 Sequence Flags (2 bits) 00 -> SEQUENCE_FLAG_CONT
 *                                                      01 -> SEQUENCE_FLAG_FIRST
 *                                                      10 -> SEQUENCE_FLAG_LAST
 *                                                      11 -> SEQUENCE_FLAG_LAST
 * @param seq_cnt - 4.1.2.4.3 Packet Sequence Count or Packet Name (14 bits) Max value 16383
 * @param length - 4.1.2.5 Packet Data Length (2 bytes)
 * @return CCSDS_primary_header
 */
CCSDS_primary_header ccsdsPrimaryHeader(unsigned short version, unsigned short type,
                                        unsigned short proc_id, unsigned short seq_flags, unsigned short seq_cnt,
                                        unsigned short length) {      //Build a CCSDS_primary_header packet
    CCSDS_primary_header res = {version, type, proc_id, seq_flags, seq_cnt, length};
    return res;
}

/**
 * Build CCSDS_data_field given CCSDS_secondary_header and a pointer to userData
 * @param secondaryHeader - Pointer to CCSDS_secondary_header, if there is no secondary_header put it to NULL
 * @param data - Pointer to userData, length is defined in CCSDS_primary_header
 * @return CCSDS_data_field
 */
CCSDS_data_field ccsdsDataField(void* data) {    // Build userData field 
    CCSDS_data_field res = {data};
    return res;
}

/**
 * Build CCSDS_packet
 * @param primaryHeader - pointer to CCSDS_primary_header
 * @param dataField - pointer to CCSDS_data_field
 * @return CCSDS_packet
 */
CCSDS_packet ccsdsPacketBuild(CCSDS_primary_header* primaryHeader, CCSDS_data_field* dataField) {   // Build CCSDS packet
    CCSDS_packet res = {primaryHeader, dataField};
    return res;
}

// Given an I/O stream read primary header and put it into packet->primaryHeader
void ccsdsReadPrimaryHeader(FILE *fp, CCSDS_packet *packet){
    unsigned char* buffer = malloc(PRIMARY_HEADER_LENGTH);

    // Read 6 bytes from the file into the buffer
    if (fread(buffer, 1, PRIMARY_HEADER_LENGTH, fp) != PRIMARY_HEADER_LENGTH) {
        fprintf(stderr, "Error reading file\n");
        return 1;
    }
    
    packet->primary_header->version = (buffer[0] >> 5) & 0b111;
    packet->primary_header->type = (buffer[0] >> 4) & 0b1;
    packet->primary_header->proc_id = ((buffer[0] & 0b111) << 8) | buffer[1];
    packet->primary_header->seq_flags = (buffer[2] >> 6) & 0b11;
    packet->primary_header->seq_cnt = (buffer[2] & 0b111111) | buffer[3];
    packet->primary_header->length = (unsigned short) buffer[4] << 8 | 
                                     (unsigned short) buffer[5];
    
}

// Given an I/O stream malloc length and print userData. Not recommended, only for testing. Big userData length can collapse system.
void ccsdsReadFullUserData(FILE *fp, CCSDS_packet *packet){
    packet->dataField->userData = (unsigned char *) malloc(packet->primary_header->length + 1);
    fread(packet->dataField->userData, packet->primary_header->length + 1, 1, fp);
}

// Given an I/O stream print packet
size_t write_packet(FILE *fp, CCSDS_packet *packet){
    size_t bytesWritten = 0;
    bytesWritten += fwrite(packet->primary_header, PRIMARY_HEADER_LENGTH, 1, fp);   //Write primary header
    bytesWritten += fwrite(packet->dataField->userData, packet->primary_header->length + 1, 1, fp);      // Write userData
    return bytesWritten;
}

// Given a CCSDS_packet print the DataField Content. 
void printDataField(CCSDS_packet *packet){
    long i = packet->primary_header->length + 1;

    for(;i > 0; i--){
        printf("GET: %c\n", *(unsigned char*)(packet->dataField->userData++));
    }
}

// Given a CCSDS_primary_header print the primary header content
void printPrimaryHeader(CCSDS_primary_header* primaryHeader){
    printf("Version: %d\n", primaryHeader->version);
    if(primaryHeader->type == PACKET_TYPE_ATTESTATION) printf("TYPE: ATTESTATION\n");
    else printf("TYPE: TELECOMMAND\n"); // enter different types later
    printf("Application proccess identifier: %d\n", primaryHeader->proc_id);
    printf("Sequence Flags: %d\n", primaryHeader->seq_flags);
    printf("Packet Sequence count: %d\n", primaryHeader->seq_cnt);
    printf("Packet Data length: %d\n", primaryHeader->length);
}

// Write ccsds packet into a pointer using the correct binary structure
// Also convert little endian to big endian of the header due to cc3200 architecture.
// Data field of the packet is only copied, not modified.
void* writeInBuffer(CCSDS_packet *packet){

    // Get packet length based on his header
    unsigned short packet_length = PRIMARY_HEADER_LENGTH + packet->primary_header->length + 1;

    // Allocate memory
    void* res = malloc(packet_length);

    // Clean buffer
    memset(res, 0, sizeof(packet_length));

    // Write PRIMARY HEADER DATA
    void* mod = res;     // Copy pointer for moving when copying
    *(unsigned short*) mod = packet->primary_header->version << 13 |     // Assign first 2 bytes
                             packet->primary_header->type << 12 |
                             packet->primary_header->proc_id;
    mod += sizeof(unsigned short);           // Move pointer for next 2 bytes

    *(unsigned short*) mod = packet->primary_header->seq_flags << 14 |
                             packet->primary_header->seq_cnt;
    mod += sizeof(unsigned short);           // Move pointer for next 2 bytes

    *(unsigned short*) mod = packet->primary_header->length;
    mod += sizeof(unsigned short);   // Move pointer

    // Copy datafield to packet (not modified)
    memcpy(mod, packet->dataField->userData, packet->primary_header->length + 1);

    //Swap primary and secondary header bytes
    mod = res + 1;
    unsigned char headers_size = packet_length - packet->primary_header->length - 1;
    for(; mod < res + headers_size; mod+=2){  // Swap pair of bytes
        unsigned char aux = *(unsigned char*)mod;
        *(unsigned char*) mod = *(unsigned char*)(mod-1);
        *(unsigned char*) (mod-1) = aux;
    }

    return res;
}