// This goes in the inc folder 

#ifndef CCSDS_h
#define CCSDS_h

enum PACKET_TYPE{
    ATTESTATION = 0 , 
    PING = 1 ,
    CHALLENGE = 2
};


#define PACKET_TYPE_ATTESTATION 0b0               // 4.1.2.3.2.3
#define PACKET_TYPE_PING 0b1
#define PACKET_TYPE_CHALLENGE 0b2
#define SEQUENCE_FLAG_CONT 0b00                 // 4.1.2.4.2.2 a)
#define SEQUENCE_FLAG_FIRST 0b01                // 4.1.2.4.2.2 b)
#define SEQUENCE_FLAG_LAST 0b10                 // 4.1.2.4.2.2 c)
#define SEQUENCE_FLAG_UNSEGMENTED 0b11          // 4.1.2.4.2.2 d)
#define PRIMARY_HEADER_LENGTH 6                 // Number of bytes of primary header

typedef struct {
    unsigned short version : 3;
    unsigned short type : 1;
    unsigned short proc_id : 11;
    unsigned short seq_flags : 2;
    unsigned short seq_cnt : 14;    //Seq count or packet name
    unsigned short length;
} CCSDS_primary_header;

typedef struct {
    void* userData;
} CCSDS_data_field;

typedef struct{
    CCSDS_primary_header* primary_header;
    CCSDS_data_field* dataField;
} CCSDS_packet;

/**
 * Create the skeleton of a CCSDS_packet. Malloc primary_header and dataField and return the pointer
 * @return CCSDS_packet
 */
CCSDS_packet ccsdsPacket_new(void);

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
                                        unsigned short length);

/**
 * Build CCSDS_data_field given CCSDS_secondary_header and a pointer to userData
 * @param data - Pointer to userData, length is defined in CCSDS_primary_header
 * @return CCSDS_data_field
 */
CCSDS_data_field ccsdsDataField(void* data);

/**
 * Build CCSDS_packet
 * @param primaryHeader - pointer to CCSDS_primary_header
 * @param dataField - pointer to CCSDS_data_field
 * @return CCSDS_packet
 */
CCSDS_packet ccsdsPacketBuild(CCSDS_primary_header* primaryHeader, CCSDS_data_field* dataField);    //TODO: if no userData put at least one byte

// Given an I/O stream read primary header and put it into packet->primaryHeader
void ccsdsReadPrimaryHeader(FILE *fp, CCSDS_packet *packet);

// Given an I/O stream read secondary header and put it into packet->dataField->secondaryHeader
// void ccsdsReadSecondaryHeader(FILE *fp, CCSDS_packet *packet);

// Given an I/O stream malloc length and print userData. Not recommended, only for testing. Big userData length can collapse system.
void ccsdsReadFullUserData(FILE *fp, CCSDS_packet *packet);

// Given an I/O stream print packet
size_t write_packet(FILE *fp, CCSDS_packet *packet);

// Given a CCSDS_secondary_header print its content
// void printSecondaryHeader(CCSDS_secondary_header* secondaryHeader);

// Given a CCSDS_packet print the DataField Content. If the packet have secondary header
// it prints too.
void printDataField(CCSDS_packet* packet);

// Given a CCSDS_primary_header print the primary header content
void printPrimaryHeader(CCSDS_primary_header* packet);

/**
 * Write ccsds packet into a pointer using the correct binary structure. Data field of the packet is not modified, only copied.
 * @param pointer to CCSDS_packet
 * @return pointer to address where binary packet is written. Length is set on ccsds packet header
 */
void* writeInBuffer(CCSDS_packet *packet);


#endif