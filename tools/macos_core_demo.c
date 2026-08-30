/* Copyright 2026 paundraP. Licensed under the Volatility Software License 1.0. */
#include <stdio.h>
#include <unistd.h>

/* Deliberate test artifacts for validating memory-forensics recovery. */
static volatile const char contest_marker[] =
    "VOL3_MACOS_CONTEST_MARKER_2026";
static volatile const char simulated_token[] =
    "DEMO_TOKEN_7f3b2a18_NOT_A_REAL_CREDENTIAL";

int main(void) {
    printf("demo pid: %d\n", getpid());
    printf("marker address: %p\n", (const void *)contest_marker);
    printf("token address: %p\n", (const void *)simulated_token);
    fflush(stdout);
    for (;;) {
        sleep(60);
    }
}
