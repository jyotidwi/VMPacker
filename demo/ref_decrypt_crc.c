/*
 * ref_decrypt_crc.c — 纯 C 验证 decrypt_crc_info 的正确性
 *
 * 读取真实 ELF 中的 CRC_INFO (IntegrityHeader + encrypted entries),
 * 用纯 C 解密并打印结果，作为 VMP 执行的参考对照。
 *
 * 用法: aarch64-linux-gnu-gcc -O2 -static -o ref_decrypt ref_decrypt_crc.c
 *       ./ref_decrypt /path/to/packed_binary
 *
 * 也可以不带参数运行，使用硬编码的 salt 和加密值来纯验证算法。
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/* 与 integrity.c 完全相同的 rotl32 */
static uint32_t rotl32(uint32_t v, int n) {
  n = n % 32;
  return (v << n) | (v >> (32 - n));
}

/* 与 integrity.c 完全相同的 decrypt_crc_info */
static void decrypt_crc_info(uint32_t *key, uint32_t *addr, uint32_t *size,
                             uint32_t *hash) {
  uint32_t dec;

  /* addr */
  dec = *addr ^ *key;
  *key = rotl32(*key, 7) ^ dec;
  *addr = dec;

  /* size */
  dec = *size ^ *key;
  *key = rotl32(*key, 7) ^ dec;
  *size = dec;

  /* hash */
  dec = *hash ^ *key;
  *key = rotl32(*key, 7) ^ dec;
  *hash = dec;
}

/* 从文件解析并解密 CRC entries */
int main(int argc, char *argv[]) {
  const char *path = (argc > 1) ? argv[1] : NULL;

  if (!path) {
    /* 纯算法验证模式 */
    printf("=== 纯算法验证 ===\n");

    /* 先加密已知值 */
    uint32_t orig[3][3] = {
        {0x0000, 0x1000, 0xDEAD0001}, /* chunk 0 */
        {0x1000, 0x0612, 0xDEAD0002}, /* chunk 1 */
    };

    uint32_t salt = 0x59EEE963; /* 示例 salt */
    uint32_t key = salt;

    /* 加密 */
    uint32_t enc[2][3];
    for (int i = 0; i < 2; i++) {
      uint32_t a = orig[i][0], s = orig[i][1], h = orig[i][2];
      uint32_t ea = a ^ key;
      key = rotl32(key, 7) ^ a;
      uint32_t es = s ^ key;
      key = rotl32(key, 7) ^ s;
      uint32_t eh = h ^ key;
      key = rotl32(key, 7) ^ h;
      enc[i][0] = ea;
      enc[i][1] = es;
      enc[i][2] = eh;
      printf("enc[%d]: addr=0x%08X size=0x%08X hash=0x%08X\n", i, ea, es, eh);
    }

    /* 解密并验证 */
    key = salt;
    printf("\n--- 解密验证 ---\n");
    for (int i = 0; i < 2; i++) {
      uint32_t a = enc[i][0], s = enc[i][1], h = enc[i][2];
      printf("before decrypt[%d]: key=0x%08X a=0x%08X s=0x%08X h=0x%08X\n", i,
             key, a, s, h);
      decrypt_crc_info(&key, &a, &s, &h);
      printf("after  decrypt[%d]: key=0x%08X a=0x%08X s=0x%08X h=0x%08X\n", i,
             key, a, s, h);
      int ok = (a == orig[i][0] && s == orig[i][1] && h == orig[i][2]);
      printf("match: %s\n\n", ok ? "PASS" : "FAIL");
    }
    return 0;
  }

  /* 文件解析模式 */
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("open");
    return 1;
  }
  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  rewind(fp);
  uint8_t *d = malloc(fsize);
  fread(d, 1, fsize, fp);
  fclose(fp);

  /* 查找 CRC2 magic */
  uint32_t magic = 0x43524332;
  int idx = -1;
  for (int i = 0; i < fsize - 4; i++) {
    if (*(uint32_t *)(d + i) == magic) {
      idx = i;
      break;
    }
  }
  if (idx < 0) {
    printf("No CRC2 magic found\n");
    free(d);
    return 1;
  }

  printf("CRC2 found at file offset 0x%X\n", idx);

  uint32_t salt2 = *(uint32_t *)(d + idx + 8);
  uint16_t stub_cnt = *(uint16_t *)(d + idx + 12);
  uint16_t mem_cnt = *(uint16_t *)(d + idx + 14);
  uint32_t stub_off = *(uint32_t *)(d + idx + 16);
  uint32_t stub_size = *(uint32_t *)(d + idx + 20);

  printf("salt=0x%08X stub_cnt=%d mem_cnt=%d\n", salt2, stub_cnt, mem_cnt);
  printf("stub_code_offset=0x%X stub_code_size=0x%X\n", stub_off, stub_size);

  /* 解密 stub CRC entries */
  uint32_t key2 = salt2;
  int off = idx + 32;
  printf("\n--- Stub CRC entries (reference decrypt) ---\n");
  for (int j = 0; j < stub_cnt; j++) {
    uint32_t ea = *(uint32_t *)(d + off);
    uint32_t es = *(uint32_t *)(d + off + 4);
    uint32_t eh = *(uint32_t *)(d + off + 8);

    printf(
        "entry[%d] encrypted: addr=0x%08X size=0x%08X hash=0x%08X key=0x%08X\n",
        j, ea, es, eh, key2);

    decrypt_crc_info(&key2, &ea, &es, &eh);

    printf(
        "entry[%d] decrypted: addr=0x%08X size=0x%08X hash=0x%08X key=0x%08X\n",
        j, ea, es, eh, key2);

    /* 验证范围 */
    if (ea + es > stub_size) {
      printf("  *** WARNING: addr+size (0x%X) > stub_size (0x%X) ***\n",
             ea + es, stub_size);
    } else {
      printf("  OK: addr=0x%X size=0x%X within stub (0x%X)\n", ea, es,
             stub_size);
    }
    off += 12;
  }

  free(d);
  return 0;
}
