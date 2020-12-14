#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n     ":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
}
/*
static int entropy_source(void *data, uint8_t *output, size_t len, size_t *olen)
{
    uint32_t seed;

    seed = sys_rand32_get();
    if (len > sizeof(seed)) {
        len = sizeof(seed);
    }
    memcpy(output, &seed, len);

    *olen = len;
    return 0;
}*/


// 随机数生成器
// 真随机数生成器（TRNG）一般来自物理设备，伪随机数生成器（PRNG）可以分为”种子“（又称熵源）和内部结构2部分，
// 实际应用中常用真随机数作为种子，再通过伪随机数生成指定长度序列。

// CTR_DRBG
// 伪随机数生成器也称为确定性随机生成器（DRBG），一种近似随机数序列的算法。
// 具体方法有Hash_DRBG、HMAC_DRBG、CTR_DRBG、Hash_DRBG
// 使用单项散列算法作为随机数生成器基础算法、
// HMAC_DRBG使用消息认证码算法作为随机数生成器基础算法、
// CTR_DRBG使用分组密码算法的计数器模式作为随机数生成器基础算法


int main(void)
{
    int ret = 0;
    uint8_t random[64];
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const uint8_t *pers = "CTR_DRBG";  
     
    mbedtls_entropy_init(&entropy);//初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体

   /* mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                               MBEDTLS_ENTROPY_MAX_GATHER,//熵源可用阈值，随机数达到阈值时熵源才被使用
                               MBEDTLS_ENTROPY_SOURCE_STRONG);//强熵源，一般是硬件真随机数生成器
                               //添加熵源接口，设置熵源属性*/
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                (const unsigned char *) pers, strlen(pers));//根据个性化字符串跟新种子
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n");

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, random, sizeof(random));//生成指定长度随机数，随机数长度小于MBEDTLS_CTR_DRBG_MAX_REQUEST,默认1024
    assert_exit(ret == 0, ret);
    dump_buf("\n  . generate 64 byte random data ... ok", random, sizeof(random));

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);//释放随机数结构体
    mbedtls_entropy_free(&entropy);//释放熵结构体

    return 0;
}
