#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <stdio.h>
#include <string.h>

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"

// RSA算法是一种非对称加密算法，特点是加密解密算法不同 且 加密解密密钥不同，
// 即一般公钥加密，私钥解密。下面时RSA算法关键参数

// n 模数，位长度为1024比特或者2048比特
// e 公开指数，一般为3，7或者65537
// d 私密指数

// （n，e）公钥
// （n，d）私钥

// RSA私钥操作可以用中国剩余定理（CRT）进行加速执行，
// 再mbedtls配置文件中通过MBEDTLS_RSA_NO_CRT宏打开CRT加速，（默认时打开的）

// RSA填充方法
// 对于RSA加密，给定一个明文，给定一个公钥，就会得到特定密文，这样带来一定安全隐患，
// 所以RSA通常包含填充方案，通过填充动作把随机性注入明文，这样每次加密出来的密文不会相同。
// RSA有2种填充方案：RSAES-OAEP和RSAES-PKCS1-v1_5.前者目前已经不再推荐使用，
// 后者再实现过程种引入了单项散列函数。

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

static void dump_rsa_key(mbedtls_rsa_context *ctx)
{
    size_t olen;
    uint8_t buf[516];
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx->N , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("N: %s\n", buf); 

    mbedtls_mpi_write_string(&ctx->E , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->D , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("D: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->P , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("P: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->Q , 16, buf, sizeof(buf), &olen);
    mbedtls_printf("Q: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->DP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DP: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->DQ, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DQ: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->QP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("QP: %s\n", buf);
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
}

int main(void)
{
    int ret;
    size_t olen = 0;
    uint8_t out[2048/8];

    //mbedtls_platform_set_printf(printf);
    //mbedtls_platform_set_snprintf(snprintf);

    mbedtls_rsa_context ctx;    //RSA密钥结构体
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "simple_rsa";
    const char *msg = "Hello, World!";

    mbedtls_entropy_init(&entropy);//初始化熵结构体
    mbedtls_ctr_drbg_init(&ctr_drbg);//初始化随机数结构体
    //rsa结构体初始化
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, //填充方案OAEP
    						MBEDTLS_MD_SHA256); //SHA256做散列算法
    
   /* mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                               MBEDTLS_ENTROPY_MAX_GATHER,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);*/
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                                    (const uint8_t *) pers, strlen(pers));//根据个性化字符串更新种子
    assert_exit(ret == 0, ret);
    mbedtls_printf("\n  . setup rng ... ok\n");

    mbedtls_printf("\n  ! RSA Generating large primes may take minutes! \n");
	//生成RSA密钥
    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                                        &ctr_drbg, //随机数结构体
                                        2048, //模数位长度
                                        65537);//公开指数0x01001
    assert_exit(ret == 0, ret);                                    
    mbedtls_printf("\n  1. RSA generate key ... ok\n");
    dump_rsa_key(&ctx);  
    //RSA加密
    ret = mbedtls_rsa_pkcs1_encrypt(&ctx, mbedtls_ctr_drbg_random, //随机数生成接口
                            &ctr_drbg,          //随机数结构体
                            MBEDTLS_RSA_PUBLIC, //公钥操作
                            strlen(msg),        //消息长度
                            msg,                //输入消息指针
                            out);               //输出密文指针
    assert_exit(ret == 0, ret);                              
    dump_buf("\n  2. RSA encryption ... ok", out, sizeof(out));
	//RSA解密
    ret = mbedtls_rsa_pkcs1_decrypt(&ctx, mbedtls_ctr_drbg_random,//随机数生成接口
    						&ctr_drbg,          //随机数结构体
                            MBEDTLS_RSA_PRIVATE, //私钥操作
                            &olen,           //输出长度
                            out,             //输入密文指针
                            out,             //输出明文指针
                            sizeof(out));    //最大输出明文数组长度
    assert_exit(ret == 0, ret);                              
    
    out[olen] = 0;
    mbedtls_printf("\n  3. RSA decryption ... ok\n     %s\n", out);

    ret = memcmp(out, msg, olen);
    assert_exit(ret == 0, ret);      
    mbedtls_printf("\n  4. RSA Compare results and plaintext ... ok\n");

cleanup:
    mbedtls_ctr_drbg_free(&ctr_drbg);//释放随机数结构体
    mbedtls_entropy_free(&entropy); //释放熵结构体
    mbedtls_rsa_free(&ctx);         //释放rsa结构体

    return ret;
}
