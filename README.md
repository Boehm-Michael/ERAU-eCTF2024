# ERAU eCTF 2024 Documentation

Document functions and components here.

Initial Documentation will be created here and compiled into a .pdf later.

This document is live, please update it as we go. Not documenting will make me sad :(



# Make me secure TODO:

1. Implement secure_send() function post-boot scenario
- #ifdef POSTBOOT #define send_packet() secure_send() #endif
- Change in PostBoot in boot() function of application_processor.c
- Add in WolfSSL to secure_send()
- Add in memory location of keys
2. Implement key exchange during boot process
- Diffie Helman and/or use shared secret, attestation pin/shared secret is not secure
3. Implement memory management for I2C buffers
- prevent buf[50] from being overflown
- Gracefully handle buffers
4. Implement Component reciprocity to secure_send()/secure_receive()
- Self explanatory, should be copy + paste
5. Implement TRNG source and Key Generation
- calvin
6. Implement better attestation verification (not just response)
- Share hash of key with other data? Idk
7. Implement 
- Implement

