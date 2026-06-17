#include "munit.h"
#include "uart_rx_logic.h"

static MunitResult test_rx_chunk_processes_without_artificial_delay(
    const MunitParameter params[],
    void* fixture) {
    (void)params;
    (void)fixture;

    munit_assert_uint32(seader_uart_rx_inter_chunk_delay_ms(1U), ==, 0U);
    munit_assert_uint32(seader_uart_rx_inter_chunk_delay_ms(64U), ==, 0U);
    munit_assert_uint32(seader_uart_rx_inter_chunk_delay_ms(272U), ==, 0U);
    return MUNIT_OK;
}

static MunitResult test_empty_rx_chunk_does_not_delay(const MunitParameter params[], void* fixture) {
    (void)params;
    (void)fixture;

    munit_assert_uint32(seader_uart_rx_inter_chunk_delay_ms(0U), ==, 0U);
    return MUNIT_OK;
}

static MunitTest test_uart_rx_logic_cases[] = {
    {(char*)"/delay/positive-chunk-is-immediate",
     test_rx_chunk_processes_without_artificial_delay,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/delay/empty-chunk-is-immediate",
     test_empty_rx_chunk_does_not_delay,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, 0, NULL},
};

MunitSuite test_uart_rx_logic_suite = {
    "",
    test_uart_rx_logic_cases,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};
