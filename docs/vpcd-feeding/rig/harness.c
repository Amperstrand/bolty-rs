/*
 * harness.c — drives the REAL vpcd.c library through the exact call sequence
 * pcscd performs (verified against upstream ifd-vpcd.c):
 *
 *   IFDHPowerICC(IFD_RESET)  -> vicc_reset()
 *   then unconditionally     -> IFDHGetCapabilities(TAG_IFD_ATR) -> vicc_getatr()
 *   EH presence poll         -> vicc_present()  (= vicc_getatr)
 *   IFDHTransmitToICC        -> vicc_transmit()
 *
 * Verdict logic is structural (no knowledge of vpicc mode):
 *   - getatr/present responses logged (ATR counter byte tells WHICH reply landed)
 *   - transmit PASS iff response is an R-APDU (counter,0x90,0x00);
 *     FAIL (desync) iff it starts with 0x3B (an ATR) — prints the stale ATR id.
 *
 * SIGALRM after N seconds converts an indefinite blocking recv into exit code 42.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "vpcd.h"

static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void hex(const char *label, const unsigned char *b, ssize_t n) {
    printf("    %-14s [%zd B]", label, n);
    for (ssize_t i = 0; i < n && i < 24; i++) printf(" %02X", b[i]);
    if (n > 24) printf(" ...");
    printf("\n");
}

static void on_alarm(int sig) {
    (void)sig;
    const char msg[] = "VERDICT: BLOCKED — vicc_reset() still inside recvFromVICC() "
                       "after alarm; would hang pcscd indefinitely (spec-silent vpicc)\n";
    ssize_t ignored = write(2, msg, sizeof msg - 1);
    (void)ignored;
    _exit(42);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s PORT ALARM_SECS [skip_transmit]\n", argv[0]);
        return 2;
    }
    unsigned short port = (unsigned short)atoi(argv[1]);
    int alarm_secs = atoi(argv[2]);
    setvbuf(stdout, NULL, _IONBF, 0);

    struct sigaction sa = {0};
    sa.sa_handler = on_alarm;
    sigaction(SIGALRM, &sa, NULL);

    struct vicc_ctx *ctx = vicc_init(NULL, port);   /* server mode, like pcscd's vpcd */
    if (!ctx) { fprintf(stderr, "vicc_init failed\n"); return 2; }
    printf("[harness] listening on %u, waiting for vpicc...\n", port);
    if (!vicc_connect(ctx, 5, 0)) { fprintf(stderr, "no vpicc connected\n"); return 2; }
    printf("[harness] vpicc connected\n");

    unsigned char *atr = NULL, *rapdu = NULL;
    ssize_t n;

    /* --- pcscd: SCardReconnect / cold connect does POWER reset + ATR --- */
    alarm(alarm_secs);
    double t0 = now_ms();
    int rr = vicc_reset(ctx);
    double dt_reset = now_ms() - t0;
    alarm(0);
    printf("[step1] vicc_reset()            -> rc=%d  (%.1f ms)\n", rr, dt_reset);
    if (rr < 0) {
        printf("VERDICT: reset failed\n");
        if (argc > 3 && !strcmp(argv[3], "afterfail")) {
            /* regression continuation: a consuming-drain failure must
             * leave the connection ejected — present() then reconnects
             * or reports absent instead of blocking on misaligned bytes */
            alarm(alarm_secs);
            t0 = now_ms();
            int present_after_fail = vicc_present(ctx);
            alarm(0);
            printf("[step3'] vicc_present() after failure -> %d  (%.1f ms)\n",
                   present_after_fail, now_ms() - t0);
        }
        return 1;
    }

    t0 = now_ms();
    n = vicc_getatr(ctx, &atr);
    double dt_atr = now_ms() - t0;
    printf("[step2] vicc_getatr()           -> %zd  (%.1f ms)\n", n, dt_atr);
    if (n > 0) hex("ATR seen:", atr, n);

    /* --- pcscd EH presence poll --- */
    t0 = now_ms();
    int present = vicc_present(ctx);
    printf("[step3] vicc_present()          -> %d  (%.1f ms)\n", present, now_ms() - t0);

    /* --- application transmit --- */
    if (argc > 3) { printf("[step4] transmit skipped\n"); vicc_exit(ctx); return 0; }
    unsigned char apdu[] = {0x00, 0xA4, 0x04, 0x00, 0x02, 0x3B, 0x00};
    t0 = now_ms();
    n = vicc_transmit(ctx, sizeof apdu, apdu, &rapdu);
    printf("[step4] vicc_transmit()         -> %zd  (%.1f ms)\n", n, now_ms() - t0);
    if (n > 0) hex("R-APDU seen:", rapdu, n);

    if (n >= 2 && rapdu[0] != 0x3B) {
        printf("VERDICT: CLEAN — transmit got its own R-APDU (SW=%02X%02X)\n",
               rapdu[n-2], rapdu[n-1]);
    } else if (n > 0) {
        printf("VERDICT: DESYNC — transmit received a STALE ATR (id byte %02X) "
               "instead of the R-APDU; app sees garbage SW=%02X%02X (= ATR tail)\n",
               rapdu[2 < n ? 2 : 0], rapdu[n-2], rapdu[n-1]);
    } else {
        printf("VERDICT: transmit failed (rc=%zd)\n", n);
    }

    free(atr); free(rapdu);
    vicc_exit(ctx);
    return 0;
}
