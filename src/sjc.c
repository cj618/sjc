/*
 * sjc.c - file encryption using NSA SKIPJACK (80-bit key, 64-bit block)
 *
 * Copyright (c) 2026 C R Jervis - chrisxjervis@gmail.com
 *
 *
 * Format (little and boring on purpose):
 *   Header:
 *     4 bytes  magic "SJCK"
 *     1 byte   version (1)
 *     1 byte   mode (1 = CBC)
 *     2 bytes  reserved (0)
 *     8 bytes  IV
 *   Body:
 *     ciphertext (CBC), PKCS#7 padded
 *
 * Build:
 *   cc -O2 -Wall -Wextra -std=c99 -o skipjack-crypt skipjack_crypt.c
 *
 * Usage:
 *   Encrypt: sjc -e -k <20 hex chars> -i plaintext -o ciphertext.sj
 *   Decrypt: sjc -d -k <20 hex chars> -i ciphertext.sj -o plaintext
 *   Selftest: sjc -t
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__APPLE__)
  #include <unistd.h>
  #if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
    #include <stdlib.h> /* arc4random_buf */
  #endif
#endif

/* ---- SKIPJACK F-table (fixed 8-bit permutation) ---- */
static const uint8_t F[256] = {
  0xA3,0xD7,0x09,0x83,0xF8,0x48,0xF6,0xF4,0xB3,0x21,0x15,0x78,0x99,0xB1,0xAF,0xF9,
  0xE7,0x2D,0x4D,0x8A,0xCE,0x4C,0xCA,0x2E,0x52,0x95,0xD9,0x1E,0x4E,0x38,0x44,0x28,
  0x0A,0xDF,0x02,0xA0,0x17,0xF1,0x60,0x68,0x12,0xB7,0x7A,0xC3,0xE9,0xFA,0x3D,0x53,
  0x96,0x84,0x6B,0xBA,0xF2,0x63,0x9A,0x19,0x7C,0xAE,0xE5,0xF5,0xF7,0x16,0x6A,0xA2,
  0x39,0xB6,0x7B,0x0F,0xC1,0x93,0x81,0x1B,0xEE,0xB4,0x1A,0xEA,0xD0,0x91,0x2F,0xB8,
  0x55,0xB9,0xDA,0x85,0x3F,0x41,0xBF,0xE0,0x5A,0x58,0x80,0x5F,0x66,0x0B,0xD8,0x90,
  0x35,0xD5,0xC0,0xA7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6D,0x98,0x9B,0x76,
  0x97,0xFC,0xB2,0xC2,0xB0,0xFE,0xDB,0x20,0xE1,0xEB,0xD6,0xE4,0xDD,0x47,0x4A,0x1D,
  0x42,0xED,0x9E,0x6E,0x49,0x3C,0xCD,0x43,0x27,0xD2,0x07,0xD4,0xDE,0xC7,0x67,0x18,
  0x89,0xCB,0x30,0x1F,0x8D,0xC6,0x8F,0xAA,0xC8,0x74,0xDC,0xC9,0x5D,0x5C,0x31,0xA4,
  0x70,0x88,0x61,0x2C,0x9F,0x0D,0x2B,0x87,0x50,0x82,0x54,0x64,0x26,0x7D,0x03,0x40,
  0x34,0x4B,0x1C,0x73,0xD1,0xC4,0xFD,0x3B,0xCC,0xFB,0x7F,0xAB,0xE6,0x3E,0x5B,0xA5,
  0xAD,0x04,0x23,0x9C,0x14,0x51,0x22,0xF0,0x29,0x79,0x71,0x7E,0xFF,0x8C,0x0E,0xE2,
  0x0C,0xEF,0xBC,0x72,0x75,0x6F,0x37,0xA1,0xEC,0xD3,0x8E,0x62,0x8B,0x86,0x10,0xE8,
  0x08,0x77,0x11,0xBE,0x92,0x4F,0x24,0xC5,0x32,0x36,0x9D,0xCF,0xF3,0xA6,0xBB,0xAC,
  0x5E,0x6C,0xA9,0x13,0x57,0x25,0xB5,0xE3,0xBD,0xA8,0x3A,0x01,0x05,0x59,0x2A,0x46
};

/* ---- Helpers ---- */
static uint16_t load_be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static void store_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }

static void xor8(uint8_t out[8], const uint8_t a[8], const uint8_t b[8]) {
  for (int i = 0; i < 8; i++) out[i] = (uint8_t)(a[i] ^ b[i]);
}

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

static int parse_hex_key10(const char *hex, uint8_t key[10]) {
  if (!hex) return -1;
  size_t n = strlen(hex);
  if (n != 20) return -1;
  for (int i = 0; i < 10; i++) {
    int hi = hexval(hex[2*i]);
    int lo = hexval(hex[2*i + 1]);
    if (hi < 0 || lo < 0) return -1;
    key[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

/* Fill buf with random bytes (best effort) */
static int rand_bytes(uint8_t *buf, size_t len) {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
  arc4random_buf(buf, len);
  return 0;
#else
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f) return -1;
  size_t got = fread(buf, 1, len, f);
  fclose(f);
  return got == len ? 0 : -1;
#endif
}

/* ---- SKIPJACK core (NSA published spec) ---- */
/*
 * G permutation: 16-bit input -> 16-bit output using 4 rounds with F-table
 * Uses key bytes cyclically; for round r (1..32), key indices start at (4*(r-1)) mod 10.
 */
static uint16_t G(uint16_t w, const uint8_t key[10], int round) {
  uint8_t g1 = (uint8_t)(w >> 8);
  uint8_t g2 = (uint8_t)(w & 0xFF);
  int k = (4 * (round - 1)) % 10;

  uint8_t g3 = (uint8_t)(F[(uint8_t)(g2 ^ key[(k + 0) % 10])] ^ g1);
  uint8_t g4 = (uint8_t)(F[(uint8_t)(g3 ^ key[(k + 1) % 10])] ^ g2);
  uint8_t g5 = (uint8_t)(F[(uint8_t)(g4 ^ key[(k + 2) % 10])] ^ g3);
  uint8_t g6 = (uint8_t)(F[(uint8_t)(g5 ^ key[(k + 3) % 10])] ^ g4);

  return (uint16_t)((g5 << 8) | g6);
}

/* Inverse G permutation for decryption */
static uint16_t Ginv(uint16_t w, const uint8_t key[10], int round) {
  uint8_t g5 = (uint8_t)(w >> 8);
  uint8_t g6 = (uint8_t)(w & 0xFF);
  int k = (4 * (round - 1)) % 10;

  /* Reverse the 4 Feistel-like steps */
  uint8_t g4 = (uint8_t)(F[(uint8_t)(g5 ^ key[(k + 3) % 10])] ^ g6);
  uint8_t g3 = (uint8_t)(F[(uint8_t)(g4 ^ key[(k + 2) % 10])] ^ g5);
  uint8_t g2 = (uint8_t)(F[(uint8_t)(g3 ^ key[(k + 1) % 10])] ^ g4);
  uint8_t g1 = (uint8_t)(F[(uint8_t)(g2 ^ key[(k + 0) % 10])] ^ g3);

  return (uint16_t)((g1 << 8) | g2);
}

/* Encrypt one 64-bit block in place */
static void skipjack_encrypt_block(uint8_t block[8], const uint8_t key[10]) {
  uint16_t w1 = load_be16(block + 0);
  uint16_t w2 = load_be16(block + 2);
  uint16_t w3 = load_be16(block + 4);
  uint16_t w4 = load_be16(block + 6);

  for (int r = 1; r <= 32; r++) {
    if ((r >= 1 && r <= 8) || (r >= 17 && r <= 24)) {
      /* Rule A */
      uint16_t g = G(w1, key, r);
      uint16_t new_w1 = (uint16_t)(g ^ w4 ^ r);
      w4 = w3;
      w3 = w2;
      w2 = g;
      w1 = new_w1;
    } else {
      /* Rule B */
      uint16_t g = G(w1, key, r);
      uint16_t new_w1 = (uint16_t)(w4);
      uint16_t new_w4 = (uint16_t)(g ^ w2 ^ r);
      w4 = w3;
      w3 = new_w4;
      w2 = g;
      w1 = new_w1;
    }
  }

  store_be16(block + 0, w1);
  store_be16(block + 2, w2);
  store_be16(block + 4, w3);
  store_be16(block + 6, w4);
}

/* Decrypt one 64-bit block in place */
static void skipjack_decrypt_block(uint8_t block[8], const uint8_t key[10]) {
  uint16_t w1 = load_be16(block + 0);
  uint16_t w2 = load_be16(block + 2);
  uint16_t w3 = load_be16(block + 4);
  uint16_t w4 = load_be16(block + 6);

  for (int r = 32; r >= 1; r--) {
    if ((r >= 1 && r <= 8) || (r >= 17 && r <= 24)) {
      /* Inverse of Rule A */
      uint16_t old_w1 = Ginv(w2, key, r);
      uint16_t old_w4 = (uint16_t)(w1 ^ w2 ^ r);
      uint16_t old_w2 = w3;
      uint16_t old_w3 = w4;

      w1 = old_w1;
      w2 = old_w2;
      w3 = old_w3;
      w4 = old_w4;
    } else {
      /* Inverse of Rule B */
      uint16_t old_w1 = w1;              /* was w4 before forward step */
      uint16_t old_w4 = (uint16_t)(w3 ^ w2 ^ r);
      uint16_t old_w2 = Ginv(w2, key, r);
      uint16_t old_w3 = w4;

      w1 = old_w1;
      w2 = old_w2;
      w3 = old_w3;
      w4 = old_w4;
    }
  }

  store_be16(block + 0, w1);
  store_be16(block + 2, w2);
  store_be16(block + 4, w3);
  store_be16(block + 6, w4);
}

/* ---- File crypto (CBC + PKCS#7) ---- */

static int write_header(FILE *out, const uint8_t iv[8]) {
  uint8_t hdr[16];
  memcpy(hdr, "SJCK", 4);
  hdr[4] = 1;      /* version */
  hdr[5] = 1;      /* mode: 1=CBC */
  hdr[6] = 0; hdr[7] = 0;
  memcpy(hdr + 8, iv, 8);
  return (fwrite(hdr, 1, sizeof(hdr), out) == sizeof(hdr)) ? 0 : -1;
}

static int read_header(FILE *in, uint8_t iv[8]) {
  uint8_t hdr[16];
  if (fread(hdr, 1, sizeof(hdr), in) != sizeof(hdr)) return -1;
  if (memcmp(hdr, "SJCK", 4) != 0) return -1;
  if (hdr[4] != 1) return -1;
  if (hdr[5] != 1) return -1; /* CBC only */
  memcpy(iv, hdr + 8, 8);
  return 0;
}

static int encrypt_stream(FILE *in, FILE *out, const uint8_t key[10]) {
  uint8_t iv[8];
  if (rand_bytes(iv, sizeof(iv)) != 0) {
    fprintf(stderr, "failed to get random IV\n");
    return -1;
  }
  if (write_header(out, iv) != 0) return -1;

  uint8_t prev[8];
  memcpy(prev, iv, 8);

  uint8_t buf[8];
  uint8_t block[8];

  while (1) {
    size_t n = fread(buf, 1, 8, in);
    if (n == 8) {
      xor8(block, buf, prev);
      skipjack_encrypt_block(block, key);
      if (fwrite(block, 1, 8, out) != 8) return -1;
      memcpy(prev, block, 8);
      continue;
    }

    if (ferror(in)) return -1;

    /* अंतिम ब्लॉक: PKCS#7 pad */
    uint8_t pad = (uint8_t)(8 - n);
    memset(buf + n, pad, pad);
    xor8(block, buf, prev);
    skipjack_encrypt_block(block, key);
    if (fwrite(block, 1, 8, out) != 8) return -1;
    return 0;
  }
}

static int decrypt_stream(FILE *in, FILE *out, const uint8_t key[10]) {
  uint8_t iv[8];
  if (read_header(in, iv) != 0) {
    fprintf(stderr, "bad header\n");
    return -1;
  }

  uint8_t prev[8];
  memcpy(prev, iv, 8);

  uint8_t cblock[8];
  uint8_t pblock[8];
  uint8_t next_cblock[8];
  size_t n = fread(cblock, 1, 8, in);
  if (n == 0) {
    fprintf(stderr, "no ciphertext\n");
    return -1;
  }
  if (n != 8) {
    fprintf(stderr, "truncated ciphertext\n");
    return -1;
  }

  while (1) {
    size_t n2 = fread(next_cblock, 1, 8, in);

    /* decrypt current */
    memcpy(pblock, cblock, 8);
    skipjack_decrypt_block(pblock, key);
    xor8(pblock, pblock, prev);

    if (n2 == 8) {
      /* not last block, write full */
      if (fwrite(pblock, 1, 8, out) != 8) return -1;
      memcpy(prev, cblock, 8);
      memcpy(cblock, next_cblock, 8);
      continue;
    }

    if (n2 != 0) {
      fprintf(stderr, "truncated ciphertext\n");
      return -1;
    }

    /* last block: remove PKCS#7 padding */
    uint8_t pad = pblock[7];
    if (pad == 0 || pad > 8) {
      fprintf(stderr, "bad padding\n");
      return -1;
    }
    for (int i = 0; i < pad; i++) {
      if (pblock[7 - i] != pad) {
        fprintf(stderr, "bad padding\n");
        return -1;
      }
    }
    size_t outlen = 8 - pad;
    if (outlen && fwrite(pblock, 1, outlen, out) != outlen) return -1;
    return 0;
  }
}

/* ---- Self-test (single known-answer vector) ---- */
static int selftest(void) {
  /* From NIST SP 800-17 table: KEY=00..00, PT=80 00..00 => CT=9A 90 BC 0B 75 C1 37 03 */
  uint8_t key[10] = {0};
  uint8_t pt[8] = {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  uint8_t expect[8] = {0x9A,0x90,0xBC,0x0B,0x75,0xC1,0x37,0x03};

  skipjack_encrypt_block(pt, key);
  if (memcmp(pt, expect, 8) != 0) {
    fprintf(stderr, "selftest failed\n");
    fprintf(stderr, "got:    ");
    for (int i=0;i<8;i++) fprintf(stderr, "%02X%s", pt[i], (i==7)?"\n":" ");
    fprintf(stderr, "expect: ");
    for (int i=0;i<8;i++) fprintf(stderr, "%02X%s", expect[i], (i==7)?"\n":" ");
    return -1;
  }
  fprintf(stderr, "selftest ok\n");
  return 0;
}

/* ---- CLI ---- */

static void usage(const char *p) {
  fprintf(stderr,
    "usage:\n"
    "  %s -e -k <20hex> [-i infile] [-o outfile]\n"
    "  %s -d -k <20hex> [-i infile] [-o outfile]\n"
    "  %s -t\n", p, p, p);
}

int main(int argc, char **argv) {
  int enc = 0, dec = 0, test = 0;
  const char *khex = NULL;
  const char *inpath = NULL;
  const char *outpath = NULL;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-e") == 0) enc = 1;
    else if (strcmp(argv[i], "-d") == 0) dec = 1;
    else if (strcmp(argv[i], "-t") == 0) test = 1;
    else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) khex = argv[++i];
    else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) inpath = argv[++i];
    else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outpath = argv[++i];
    else {
      usage(argv[0]);
      return 2;
    }
  }

  if (test) return selftest() == 0 ? 0 : 1;

  if ((enc && dec) || (!enc && !dec) || !khex) {
    usage(argv[0]);
    return 2;
  }

  uint8_t key[10];
  if (parse_hex_key10(khex, key) != 0) {
    fprintf(stderr, "key must be exactly 20 hex chars (80-bit / 10 bytes)\n");
    return 2;
  }

  FILE *in = stdin;
  FILE *out = stdout;

  if (inpath) {
    in = fopen(inpath, "rb");
    if (!in) { fprintf(stderr, "open input: %s\n", strerror(errno)); return 1; }
  }
  if (outpath) {
    out = fopen(outpath, "wb");
    if (!out) { fprintf(stderr, "open output: %s\n", strerror(errno)); if (inpath) fclose(in); return 1; }
  }

  int rc = enc ? encrypt_stream(in, out, key) : decrypt_stream(in, out, key);

  if (inpath) fclose(in);
  if (outpath) fclose(out);

  return (rc == 0) ? 0 : 1;
}
