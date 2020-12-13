#include <stdio.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/platform.h"

int main(void){
    u_int8_t digest[32];
    char *msg = "abc";
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info;
    
    // 初始化md结构体
    mbedtls_md_init(&ctx);
    //根据算法类型得到信息结构体指针
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&ctx,info,0);
    printf("\n md info setup.name : %s,digestvsize:%d\n",
        mbedtls_md_get_name(info),mbedtls_md_get_size(info));

    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx,msg,strlen(msg));
    mbedtls_md_finish(&ctx,digest);
    mbedtls_md_free(&ctx);       



    printf("SHA_256:\n");
    for(int i=0;i<sizeof(digest);i++){
        printf("%X",digest[i]);
    }
    printf("\n");

    return 0;
}