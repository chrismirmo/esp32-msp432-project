#include "esp_camera.h"
#include <Arduino.h>
#include <SPI.h>
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "esp_random.h"
#include "secrets.h"

// AI-Thinker Camera Pinout
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27
#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22

#define STATUS_LED_PIN    33

// SPI Hardware Pins (HSPI)
#define SPI_SCK_PIN       14
#define SPI_MISO_PIN      12 // ESP32 in <- MSP432 out (Do NOT pull high at boot!)
#define SPI_MOSI_PIN      13 // ESP32 out -> MSP432 in
#define SPI_CS_PIN        15 // Active LOW Chip Select

// Dedicated Hardware SPI instance
SPIClass SPI_BUS(HSPI);
static const uint32_t SPI_CLOCK_HZ = 1000000; // 1 MHz

#define IV_LEN 12
#define MAC_LEN 16
#define TAG_LEN 16

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;         // 0xAA55AA55
    uint32_t frame_seq;     // Sequence index
    uint8_t  cam_status;    // 0x01 = Active
    uint32_t payload_len;   // Bytes in frame
    uint8_t  pad[3];        // 16-byte alignment pad
    uint8_t  iv[IV_LEN];    // Nonce
    uint32_t timestamp;     // Timestamp
} PacketHeader;

typedef struct {
    PacketHeader header;              // 32 bytes
    uint8_t      header_mac[MAC_LEN]; // 16 bytes (CBC-MAC for MSP432)
    uint8_t      payload_tag[TAG_LEN];// 16 bytes (GCM Tag for Gateway)
} WirePacketMeta;
#pragma pack(pop)

static QueueHandle_t xFrameQueue = NULL;
static uint32_t frame_counter = 0;

#define MAX_CIPHERTEXT_SIZE (35 * 1024)
static uint8_t s_ciphertext_buffer[MAX_CIPHERTEXT_SIZE];

void setupCamera() {
    camera_config_t config;
    config.ledc_channel = LEDC_CHANNEL_0;
    config.ledc_timer   = LEDC_TIMER_0;
    config.pin_d0       = Y2_GPIO_NUM;
    config.pin_d1       = Y3_GPIO_NUM;
    config.pin_d2       = Y4_GPIO_NUM;
    config.pin_d3       = Y5_GPIO_NUM;
    config.pin_d4       = Y6_GPIO_NUM;
    config.pin_d5       = Y7_GPIO_NUM;
    config.pin_d6       = Y8_GPIO_NUM;
    config.pin_d7       = Y9_GPIO_NUM;
    config.pin_xclk     = XCLK_GPIO_NUM;
    config.pin_pclk     = PCLK_GPIO_NUM;
    config.pin_vsync    = VSYNC_GPIO_NUM;
    config.pin_href     = HREF_GPIO_NUM;
    config.pin_sccb_sda = SIOD_GPIO_NUM;
    config.pin_sccb_scl = SIOC_GPIO_NUM;
    config.pin_pwdn     = PWDN_GPIO_NUM;
    config.pin_reset    = RESET_GPIO_NUM;
    config.xclk_freq_hz = 20000000;
    config.pixel_format = PIXFORMAT_JPEG;

    if (psramFound()) {
        config.frame_size = FRAMESIZE_QVGA;
        config.jpeg_quality = 12;
        config.fb_count = 2;
        config.fb_location = CAMERA_FB_IN_PSRAM;
    } else {
        config.frame_size = FRAMESIZE_QVGA;
        config.jpeg_quality = 14;
        config.fb_count = 1;
        config.fb_location = CAMERA_FB_IN_DRAM;
    }

    esp_err_t err = esp_camera_init(&config);
    if (err != ESP_OK) {
        Serial.printf("Camera initialization failed: 0x%x\n", err);
        while (true) { vTaskDelay(pdMS_TO_TICKS(1000)); }
    }
    Serial.println("Camera ready.");
}

void compute_header_cbc_mac(const PacketHeader *hdr, uint8_t *out_mac) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, KEY_AUTH, 128);

    uint8_t iv[16] = {0};
    uint8_t cbc_output[32];

    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, sizeof(PacketHeader), iv, (const unsigned char *)hdr, cbc_output);
    mbedtls_aes_free(&aes);

    memcpy(out_mac, &cbc_output[16], 16);
}

void CameraTask(void *pvParameters) {
    while (true) {
        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) {
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        if (xQueueSend(xFrameQueue, &fb, 0) != pdPASS) {
            esp_camera_fb_return(fb);
        }

        vTaskDelay(pdMS_TO_TICKS(40)); // ~25 FPS capture rate
    }
}

void CryptoAndSpiTask(void *pvParameters) {
    camera_fb_t *fb = NULL;
    mbedtls_gcm_context gcm;
    WirePacketMeta pkt;

    while (true) {
        if (xQueueReceive(xFrameQueue, &fb, portMAX_DELAY) == pdPASS) {
            if (!fb) continue;

            digitalWrite(STATUS_LED_PIN, LOW);

            if (fb->len <= MAX_CIPHERTEXT_SIZE) {
                // 1. Fill Header
                pkt.header.magic = 0xAA55AA55;
                pkt.header.frame_seq = frame_counter++;
                pkt.header.cam_status = 0x01;
                pkt.header.payload_len = fb->len;
                pkt.header.pad[0] = 0; pkt.header.pad[1] = 0; pkt.header.pad[2] = 0;
                esp_fill_random(pkt.header.iv, IV_LEN);
                pkt.header.timestamp = millis();

                // 2. Compute Header CBC-MAC for MSP432
                compute_header_cbc_mac(&pkt.header, pkt.header_mac);

                // 3. Encrypt payload with AES-GCM for Gateway
                mbedtls_gcm_init(&gcm);
                mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, KEY_DATA, 128);
                mbedtls_gcm_crypt_and_tag(
                    &gcm,
                    MBEDTLS_GCM_ENCRYPT,
                    fb->len,
                    pkt.header.iv,
                    IV_LEN,
                    NULL, 0,
                    fb->buf,
                    s_ciphertext_buffer,
                    TAG_LEN,
                    pkt.payload_tag
                );
                mbedtls_gcm_free(&gcm);

                // 4. SPI Transmission to MSP432 (Mode 0, MSB First, 10 MHz)
                SPI_BUS.beginTransaction(SPISettings(SPI_CLOCK_HZ, MSBFIRST, SPI_MODE0));
                digitalWrite(SPI_CS_PIN, LOW); // Assert CS: triggers MSP432 DMA start

                delayMicroseconds(10); // Give MSP432 slave time to enter receive loop

                // Send 64-byte Header + MACs
                SPI_BUS.transferBytes((uint8_t *)&pkt, NULL, sizeof(WirePacketMeta));
                delayMicroseconds(10);

                // Send Encrypted JPEG Payload
                SPI_BUS.transferBytes(s_ciphertext_buffer, NULL, pkt.header.payload_len);
                delayMicroseconds(10);

                digitalWrite(SPI_CS_PIN, HIGH); // Deassert CS: triggers MSP432 packet completion
                SPI_BUS.endTransaction();

                Serial.printf("[SPI TX #%u] %u B | Frame Sent | MAC: %02X%02X..\n",
                              pkt.header.frame_seq, pkt.header.payload_len,
                              pkt.header_mac[0], pkt.header_mac[1]);
            }

            esp_camera_fb_return(fb);
            digitalWrite(STATUS_LED_PIN, HIGH);
        }
    }
}

void setup() {
    Serial.begin(115200);

    // Initialize SPI Chip Select
    pinMode(SPI_CS_PIN, OUTPUT);
    digitalWrite(SPI_CS_PIN, HIGH); // Inactive HIGH

    // Initialize Hardware HSPI Bus: SCK=14, MISO=12, MOSI=13, SS=15
    SPI_BUS.begin(SPI_SCK_PIN, SPI_MISO_PIN, SPI_MOSI_PIN, -1);

    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, HIGH);

    setupCamera();

    xFrameQueue = xQueueCreate(2, sizeof(camera_fb_t *));

    xTaskCreatePinnedToCore(CameraTask, "CameraTask", 4096, NULL, 2, NULL, 0);
    xTaskCreatePinnedToCore(CryptoAndSpiTask, "CryptoTask", 8192, NULL, 1, NULL, 1);
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}