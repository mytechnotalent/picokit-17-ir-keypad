// MIT License
//
// Copyright (c) 2026 Kevin Thomas
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author:  Kevin Thomas
// Email:   kevin@mytechnotalent.com
// GitHub:  https://github.com/mytechnotalent/picokit-17-ir-keypad
// File:    monitor.c
// Desc:    Implements the infrared keypad state machine that accumulates
//          remote digits and pairs the value with an authenticated heartbeat.
// Created: 2026

#include "picokit_17_ir_keypad.h"
#include "monitor.h"
#include "radio.h"
#include "status_led.h"
#include "ir_remote.h"
#include "display.h"
#include "ccm.h"
#include "envelope.h"
#include "field_secrets.h"
#include "hardware/gpio.h"
#include "hardware/i2c.h"
#include "pico/time.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief NEC command code for remote keypad digits zero through nine.
 */
static const uint8_t g_digit_keys[10] = {
    0x16u, 0x0Cu, 0x18u, 0x5Eu, 0x08u,
    0x1Cu, 0x5Au, 0x42u, 0x52u, 0x4Au,
};

/**
 * @brief Module-ready flag.
 *
 * Set to true by monitor_init() once the peripherals are configured.
 * monitor_step() returns false while this flag is clear.
 */
static bool g_ready;

/**
 * @brief Accumulated keypad pin value.
 */
static uint16_t g_pin;

/**
 * @brief Number of digits currently held in the accumulator.
 */
static uint8_t g_digits;

/**
 * @brief Last decoded NEC key code.
 */
static uint8_t g_key_code;

/**
 * @brief Monotonic transmit sequence number.
 */
static uint16_t g_seq;

/**
 * @brief Absolute time in microseconds of the next infrared poll.
 */
static uint64_t g_next_poll_us;

/**
 * @brief Absolute time in microseconds of the next authenticated transmit.
 */
static uint64_t g_next_tx_us;

/**
 * @brief Inbound radio line accumulator.
 */
static char g_rx_line[RADIO_LINE_BUF_LEN];

/**
 * @brief Number of bytes currently held in the inbound line accumulator.
 */
static size_t g_rx_len;

/**
 * @brief AES-128 session key for telemetry.
 */
static uint8_t g_key[CCM_KEY_LEN];

/**
 * @brief True once the telemetry session key has been loaded.
 */
static bool g_key_ready;

/**
 * @brief First rendered LCD status line.
 */
static char g_line1[DISPLAY_LINE_LEN];

/**
 * @brief Second rendered LCD status line.
 */
static char g_line2[DISPLAY_LINE_LEN];

/**
 * @brief Probe one I2C address and report whether it acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to probe.
 * @param addr The 7-bit address to probe.
 * @return bool true when the address acknowledged.
 */
static bool i2c_probe(i2c_inst_t *i2c, uint8_t addr) {
    uint8_t dummy = 0u;
    if (i2c_write_blocking(i2c, addr, &dummy, 1u, false) < 0) {
        return false;
    }
    printf("  found 0x%02X\n", (unsigned)addr);
    return true;
}

/**
 * @brief Probe the I2C bus and print every device that acknowledges.
 *
 * @param i2c Pointer to the I2C peripheral to scan.
 * @return void
 */
static void i2c_bus_scan(i2c_inst_t *i2c) {
    uint8_t addr;
    uint8_t found = 0u;
    printf("I2C scan:\n");
    for (addr = 0x08u; addr < 0x78u; ++addr) {
        found += i2c_probe(i2c, addr) ? 1u : 0u;
    }
    if (found == 0u) {
        printf("  no devices\n");
    }
}

/**
 * @brief Initialize the I2C bus pins and scan the bus.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_bus_init(void) {
    i2c_init(PICOKIT_17_IR_KEYPAD_I2C, PICOKIT_17_IR_KEYPAD_I2C_BAUD);
    gpio_set_function(PICOKIT_17_IR_KEYPAD_I2C_SDA, GPIO_FUNC_I2C);
    gpio_set_function(PICOKIT_17_IR_KEYPAD_I2C_SCL, GPIO_FUNC_I2C);
    gpio_pull_up(PICOKIT_17_IR_KEYPAD_I2C_SDA);
    gpio_pull_up(PICOKIT_17_IR_KEYPAD_I2C_SCL);
    i2c_bus_scan(PICOKIT_17_IR_KEYPAD_I2C);
}

/**
 * @brief Configure the onboard heartbeat LED as a dark output.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init_io(void) {
    gpio_init(PICOKIT_17_IR_KEYPAD_LED_PIN);
    gpio_set_dir(PICOKIT_17_IR_KEYPAD_LED_PIN, GPIO_OUT);
    gpio_put(PICOKIT_17_IR_KEYPAD_LED_PIN, 0);
}

/**
 * @brief Reset the pin, sequence, and the poll and transmit timing.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_state_init(void) {
    uint64_t now_us = time_us_64();
    g_pin = 0u;
    g_digits = 0u;
    g_key_code = 0u;
    g_seq = 0u;
    g_next_poll_us = now_us;
    g_next_tx_us = now_us + (uint64_t)PICOKIT_17_IR_KEYPAD_TX_INTERVAL_MS * 1000u;
    g_ready = true;
}

/**
 * @brief Load the telemetry session key from the field secret.
 *
 * LAB-ONLY: production must provision the session key through OTP rather
 * than embedding a committed key.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_load_key(void) {
    static const uint8_t key[CCM_KEY_LEN] = FIELD_SECRET_KEY;
    memcpy(g_key, key, CCM_KEY_LEN);
    g_key_ready = true;
}

/**
 * @brief Print the boot banner for the infrared keypad lesson.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_banner(void) {
    printf("=== PICOKIT-17 IR KEYPAD // KEYPAD + AUTHENTICATED HEARTBEAT ===\n");
}

/**
 * @brief Derive the field key and announce a ready monitor.
 *
 * @param void No parameters.
 * @return bool true when the field key was derived and installed.
 */
static bool monitor_finish(void) {
    monitor_load_key();
    monitor_banner();
    return true;
}

/**
 * @brief Blink the onboard heartbeat LED exactly once.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_heartbeat(void) {
    gpio_put(PICOKIT_17_IR_KEYPAD_LED_PIN, 1);
    sleep_us(MONITOR_HEARTBEAT_BLINK_US);
    gpio_put(PICOKIT_17_IR_KEYPAD_LED_PIN, 0);
    sleep_us(MONITOR_HEARTBEAT_BLINK_US);
}

/**
 * @brief Clear the accumulated keypad value and digit count.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_clear(void) {
    g_pin = 0u;
    g_digits = 0u;
}

/**
 * @brief Resolve a remote key code to a numeric keypad digit.
 *
 * @param cmd Decoded eight-bit remote command code.
 * @param digit Pointer to mutable resolved digit.
 * @return bool true when the key code maps to a digit.
 */
static bool monitor_digit_for(uint8_t cmd, uint8_t *digit) {
    uint8_t i;
    for (i = 0u; i < 10u; ++i) {
        if (g_digit_keys[i] == cmd) {
            *digit = i;
            return true;
        }
    }
    return false;
}

/**
 * @brief Push one decimal digit into the keypad accumulator.
 *
 * @param digit Decimal digit value zero through nine.
 * @return void
 */
static void monitor_push_digit(uint8_t digit) {
    if (g_digits >= MONITOR_MAX_DIGITS) {
        return;
    }
    g_pin = (uint16_t)(g_pin * 10u + (uint16_t)digit);
    g_digits += 1u;
}

/**
 * @brief Render the accumulated value onto the 1602 LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_render(void) {
    snprintf(g_line1, sizeof(g_line1), "PIN %04u", (unsigned)g_pin);
    snprintf(g_line2, sizeof(g_line2), "D%u N:%u",
             (unsigned)g_digits, (unsigned)PACKET_NODE_ID);
    display_render_lines(PICOKIT_17_IR_KEYPAD_I2C,
                         PICOKIT_17_IR_KEYPAD_LCD_ADDR, g_line1, g_line2);
}

/**
 * @brief Show the accumulated value on the status LEDs and the LCD.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_show_pin(void) {
    uint8_t step = (uint8_t)(g_pin % STATUS_LED_STEP_COUNT);
    status_led_show_step(step);
    printf("PIN %u DIG %u\n", (unsigned)g_pin, (unsigned)g_digits);
    monitor_render();
}

/**
 * @brief Apply one decoded infrared remote command to the keypad.
 *
 * @param cmd Decoded eight-bit remote command code.
 * @return void
 */
static void monitor_ir_apply(uint8_t cmd) {
    uint8_t digit;
    if (monitor_digit_for(cmd, &digit)) {
        monitor_push_digit(digit);
    } else if (cmd == MONITOR_KEY_CLEAR) {
        monitor_clear();
    }
    monitor_show_pin();
}

/**
 * @brief Poll the infrared receiver and schedule the next poll.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_poll_tick(uint64_t now_us) {
    ir_command_t cmd;
    if (ir_remote_poll(&cmd)) {
        g_key_code = cmd.command;
        monitor_ir_apply(g_key_code);
    }
    g_next_poll_us = now_us + (uint64_t)MONITOR_POLL_INTERVAL_MS * 1000u;
}

/**
 * @brief Format the heartbeat JSON body for the latest keypad value.
 *
 * @param frame Pointer to the mutable frame output buffer.
 * @param frame_len Capacity of the frame output buffer in bytes.
 * @return size_t Number of JSON bytes written, or zero on overflow.
 */
static size_t monitor_build_frame(char *frame, size_t frame_len) {
    int written;
    written = snprintf(frame, frame_len, "{\"n\":%u,\"s\":%u,\"p\":%u}",
                       (unsigned)PACKET_NODE_ID, (unsigned)g_seq,
                       (unsigned)g_pin);
    return (written > 0 && (size_t)written < frame_len) ? (size_t)written : 0u;
}

/**
 * @brief Seal the current heartbeat body into a hex envelope.
 *
 * @param hex Pointer to the NUL-terminated hex output buffer.
 * @param hex_len Capacity of the hex output buffer in bytes.
 * @return bool true when the heartbeat was sealed and encoded.
 */
static bool monitor_seal_frame(char *hex, size_t hex_len) {
    char frame[PICOKIT_17_IR_KEYPAD_FRAME_SIZE];
    uint8_t nonce[ENVELOPE_NONCE_LEN];
    uint8_t ad = (uint8_t)PACKET_NODE_ID;
    size_t frame_len = monitor_build_frame(frame, sizeof(frame));
    envelope_fill_nonce(nonce);
    return envelope_seal_hex(g_key, nonce, &ad, 1u, (const uint8_t *)frame, frame_len, hex, hex_len);
}

/**
 * @brief Build and transmit the authenticated heartbeat frame.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_transmit(void) {
    char hex[ENVELOPE_MAX_HEX_LEN];
    if (!g_key_ready) {
        return;
    }
    if (monitor_seal_frame(hex, sizeof(hex))) {
        radio_send_frame(PICOKIT_17_IR_KEYPAD_UART, (const uint8_t *)hex, strlen(hex));
        g_seq += 1u;
    }
}

/**
 * @brief Transmit one heartbeat and schedule the next transmit.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_tx_tick(uint64_t now_us) {
    monitor_heartbeat();
    monitor_transmit();
    g_next_tx_us = now_us + (uint64_t)PICOKIT_17_IR_KEYPAD_TX_INTERVAL_MS * 1000u;
}

/**
 * @brief Drain inbound radio lines and log every valid +RCV report.
 *
 * @param void No parameters.
 * @return void
 */
static void monitor_rx_tick(void) {
    radio_rcv_t rcv;
    while (radio_line_pump(PICOKIT_17_IR_KEYPAD_UART, g_rx_line, &g_rx_len)) {
        if (radio_parse_rcv(g_rx_line, &rcv) == RADIO_RESULT_OK) {
            printf("RX from 0x%04X, %u bytes\n", (unsigned)rcv.sender, (unsigned)rcv.len);
        }
    }
}

/**
 * @brief Service the infrared poll and heartbeat transmit timers.
 *
 * @param now_us Current monotonic time in microseconds.
 * @return void
 */
static void monitor_service_timers(uint64_t now_us) {
    if (now_us >= g_next_poll_us) {
        monitor_poll_tick(now_us);
    }
    if (now_us >= g_next_tx_us) {
        monitor_tx_tick(now_us);
    }
}

bool monitor_init(void) {
    bool ok;
    monitor_bus_init();
    ok = status_led_init() && radio_init(PICOKIT_17_IR_KEYPAD_UART);
    ok = ok && ir_remote_init();
    monitor_state_init_io();
    monitor_state_init();
    return ok && display_init(PICOKIT_17_IR_KEYPAD_I2C, PICOKIT_17_IR_KEYPAD_LCD_ADDR) && monitor_finish();
}

void monitor_deinit(void) {
    g_ready = false;
}

bool monitor_step(void) {
    uint64_t now_us;
    if (!g_ready) {
        return false;
    }
    now_us = time_us_64();
    monitor_service_timers(now_us);
    monitor_rx_tick();
    return true;
}
