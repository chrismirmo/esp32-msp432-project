#include <ti/devices/msp432p4xx/driverlib/driverlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "secrets.h"


#define IV_LEN  12
#define MAC_LEN 16
#define TAG_LEN 16


#pragma pack(push, 1)
typedef struct {
    uint32_t magic;         // 0xAA55AA55
    uint32_t frame_seq;     // Rolling sequence index
    uint8_t  cam_status;    // 0x01 = Active
    uint32_t payload_len;   // Byte count of encrypted frame
    uint8_t  pad[3];        // 16-byte alignment pad
    uint8_t  iv[IV_LEN];    // 12-byte GCM Nonce
    uint32_t timestamp;     // Millis timestamp
} PacketHeader;

typedef struct {
    PacketHeader header;               // 32 bytes (2 AES blocks)
    uint8_t      header_mac[MAC_LEN];  // 16 bytes: CBC-MAC
    uint8_t      payload_tag[TAG_LEN]; // 16 bytes: GCM Tag
} WirePacketMeta;
#pragma pack(pop)

// Maximum buffer size for payload routing
#define MAX_PAYLOAD_SIZE (12 * 1024)
static WirePacketMeta rx_meta;
static volatile uint8_t rx_payload[MAX_PAYLOAD_SIZE];

// Hardware SPI Slave Configuration (EUSCI_B0 - Mode 0)
const eUSCI_SPI_SlaveConfig spiSlaveConfig = {
    EUSCI_B_SPI_MSB_FIRST,
    EUSCI_SPI_PHASE_DATA_CAPTURED_ONFIRST_CHANGED_ON_NEXT,
    EUSCI_B_SPI_CLOCKPOLARITY_INACTIVITY_LOW,
    EUSCI_B_SPI_3PIN
};

// eUSCI_B2 Master Configuration (Mode 0, 12 MHz from 24 Mhz SMCLK)
const eUSCI_SPI_MasterConfig spiMasterConfig = {
    EUSCI_B_SPI_CLOCKSOURCE_SMCLK,
    24000000,                       // SMCLK = 24 MHz
    12000000,                       // Target SPI Clock = 12 MHz
    EUSCI_B_SPI_MSB_FIRST,
    EUSCI_SPI_PHASE_DATA_CAPTURED_ONFIRST_CHANGED_ON_NEXT,
    EUSCI_B_SPI_CLOCKPOLARITY_INACTIVITY_LOW,
    EUSCI_B_SPI_3PIN
};

void init_forwarding_spi_master(void){
    // configure p3.5 (clk), p3.6 (mosi), p3.7 (miso) as primary peripheral
    GPIO_setAsPeripheralModuleFunctionInputPin(
    GPIO_PORT_P3, 
    GPIO_PIN5|GPIO_PIN6|GPIO_PIN7, 
    GPIO_PRIMARY_MODULE_FUNCTION
    );

    // Configure p4.6 as manual CS output (idle HIGH)
    GPIO_setAsOutputPin(GPIO_PORT_P4, GPIO_PIN6);
    GPIO_setOutputHighOnPin(GPIO_PORT_P4, GPIO_PIN6);

    // Initialize and enable eUSCI_B2 as SPI Master
    SPI_initMaster(EUSCI_B2_BASE, &spiMasterConfig);
    SPI_enableModule(EUSCI_B2_BASE);
}

void spi_master_send_buffer(const uint8_t *data, uint32_t length) {
    uint32_t k;
    for (k=0; k<length; k++) {
        while (!(SPI_getInterruptStatus(EUSCI_B2_BASE, EUSCI_B_SPI_TRANSMIT_INTERRUPT)));
        SPI_transmitData(EUSCI_B2_BASE, data[k]);
    }
}

// Compute AES-CBC-MAC using MSP432 hardware accelerator
void verify_header_mac(const PacketHeader *hdr, const uint8_t *expected_mac) {
    uint8_t block0[16];
    uint8_t block1[16];
    uint8_t cipher_out[16];
    uint8_t computed_mac[16];
    uint8_t diff = 0;
    uint32_t i;

    // Split 32-byte header into two 16-byte blocks
    memcpy(block0, (const uint8_t *)hdr, 16);
    memcpy(block1, ((const uint8_t *)hdr) + 16, 16);

    // 1. Load 128-bit key into hardware engine
    AES256_setCipherKey(AES256_BASE, (uint8_t *)KEY_AUTH, AES256_KEYLENGTH_128BIT);

    // 2. Encrypt Block 0 (zero IV)
    AES256_encryptData(AES256_BASE, block0, cipher_out);

    // 3. CBC XOR: Chaining block 1 with ciphertext of block 0
    for (i = 0; i < 16; i++) {
        block1[i] ^= cipher_out[i];
    }

    // 4. Encrypt Block 1: The resulting ciphertext is the 16-byte CBC-MAC
    AES256_encryptData(AES256_BASE, block1, computed_mac);

    // 5. Constant-time verification
    for (i = 0; i < 16; i++) {
        diff |= (computed_mac[i] ^ expected_mac[i]);
    }

    if (diff == 0 && hdr->magic == 0xAA55AA55) {
        if (hdr->cam_status == 0x01) {
            GPIO_setOutputHighOnPin(GPIO_PORT_P1, GPIO_PIN0); // Turn ON Red LED1
        } else {
            GPIO_setOutputLowOnPin(GPIO_PORT_P1, GPIO_PIN0);
        }
    } else {
        GPIO_setOutputLowOnPin(GPIO_PORT_P1, GPIO_PIN0); // Kill LED on mismatch
    }
}

int main(void) {
    uint8_t *meta_ptr;
    uint32_t i;
    uint32_t len;

    // Stop Watchdog Timer
    WDT_A_holdTimer();

    // Configure core clock to 48 MHz for MSP432P4111 (FlashCtl_A enhanced controller)
    PCM_setCoreVoltageLevel(PCM_VCORE1);
    FlashCtl_A_setWaitState(FLASH_A_BANK0, 2);
    FlashCtl_A_setWaitState(FLASH_A_BANK1, 2);
    CS_setDCOCenteredFrequency(CS_DCO_FREQUENCY_48);
    CS_initClockSignal(CS_MCLK, CS_DCOCLK_SELECT, CS_CLOCK_DIVIDER_1);
    CS_initClockSignal(CS_SMCLK, CS_DCOCLK_SELECT, CS_CLOCK_DIVIDER_2);

    // Configure P1.0 (Onboard Red LED1) as output
    GPIO_setAsOutputPin(GPIO_PORT_P1, GPIO_PIN0);
    GPIO_setOutputLowOnPin(GPIO_PORT_P1, GPIO_PIN0);

    // Configure SPI Pins: P1.5 (CLK), P1.6 (SIMO), P1.7 (SOMI)
    GPIO_setAsPeripheralModuleFunctionInputPin(
        GPIO_PORT_P1,
        GPIO_PIN5 | GPIO_PIN6 | GPIO_PIN7,
        GPIO_PRIMARY_MODULE_FUNCTION
    );

    // Configure CS Pin: P5.4 as GPIO Input with Pull-Up (BoosterPack pin J3.25)
    GPIO_setAsInputPinWithPullUpResistor(GPIO_PORT_P5, GPIO_PIN4);

    // Initialize eUSCI_B0 as SPI Slave
    SPI_initSlave(EUSCI_B0_BASE, &spiSlaveConfig);
    SPI_enableModule(EUSCI_B0_BASE);

    while (1) {
        // 1. Wait for CS (P5.4) to pull LOW (ESP32 begins transmission)
        while (GPIO_getInputPinValue(GPIO_PORT_P5, GPIO_PIN4) == GPIO_INPUT_PIN_HIGH);

        // 2. Ingest 64-byte WirePacketMeta
        meta_ptr = (uint8_t *)&rx_meta;
        for (i = 0; i < sizeof(WirePacketMeta); i++) {
            while (!(SPI_getInterruptStatus(EUSCI_B0_BASE, EUSCI_B_SPI_RECEIVE_INTERRUPT))) {
                // Break out if CS goes HIGH prematurely
                if (GPIO_getInputPinValue(GPIO_PORT_P5, GPIO_PIN4) == GPIO_INPUT_PIN_HIGH) {
                    goto frame_end;
                }
            }
            meta_ptr[i] = SPI_receiveData(EUSCI_B0_BASE);
        }

        // 3. Only proceed if Delimiter is valid
        if (rx_meta.header.magic == 0xAA55AA55) {
            // Hardware CBC-MAC verification (~7 us execution)
            verify_header_mac(&rx_meta.header, rx_meta.header_mac);

            // 4. Ingest encrypted JPEG payload
            len = rx_meta.header.payload_len;
            if (len > MAX_PAYLOAD_SIZE) {
                len = MAX_PAYLOAD_SIZE;
            }

            for (i = 0; i < len; i++) {
                while (!(SPI_getInterruptStatus(EUSCI_B0_BASE, EUSCI_B_SPI_RECEIVE_INTERRUPT))) {
                    if (GPIO_getInputPinValue(GPIO_PORT_P5, GPIO_PIN4) == GPIO_INPUT_PIN_HIGH) {
                        goto frame_end;
                    }
                }
                rx_payload[i] = SPI_receiveData(EUSCI_B0_BASE);
            }
        } else {
            // Corrupt header: turn off LED and do not get trapped in payload loop
            GPIO_setOutputLowOnPin(GPIO_PORT_P1, GPIO_PIN0);
        }

        // 5. Forward authenticated packet to esp32-wroom
        if (GPIO_getInputPinValue(GPIO_PORT_P1, GPIO_PIN0) == GPIO_INPUT_PIN_HIGH){
            // Assert CS to ESP32-Wroom
            GPIO_setOutputLowOnPin(GPIO_PORT_P4, GPIO_PIN6);

            // transmit 64-byte header
            spi_master_send_buffer((const uint8_t *)&rx_meta, sizeof(WirePacketMeta));

            // transmit encrypted JPEG
            spi_master_send_buffer((const uint8_t *)rx_payload, len);

            // deassert CS
            GPIO_setOutputHighOnPin(GPIO_PORT_P4, GPIO_PIN6);
        }
frame_end:
        // 5. Wait for CS (P5.4) to return HIGH
        while (GPIO_getInputPinValue(GPIO_PORT_P5, GPIO_PIN4) == GPIO_INPUT_PIN_LOW);

        // 6. Reset eUSCI while CS is IDLE (HIGH) so it is primed for the next packet
        SPI_disableModule(EUSCI_B0_BASE);
        SPI_enableModule(EUSCI_B0_BASE);

        // Drain any residual byte
        while (SPI_getInterruptStatus(EUSCI_B0_BASE, EUSCI_B_SPI_RECEIVE_INTERRUPT)) {
            SPI_receiveData(EUSCI_B0_BASE);
        }
    }
}
