#include <stdio.h>
#include "mbedtls/ssl.h"


// 密钥协商算法 ECDHE
// 身份认证算法 ECDSA
// 对称加密算法 AES_256
// 消息认证算法 GCM
// 伪随机数算法 SHA384



int main(void){
    int  index = 1;
    const int  *list;
    const char *name;
    printf("\nlist the chipersuite\n");
    list = mbedtls_ssl_list_ciphersuites();
    for(;*list;list++){
        name = mbedtls_ssl_get_ciphersuite_name(*list);
        printf("[%03d]--%s\n",index++,name);
    }
    printf("\n");
    return 0;
}