#include <stdio.h>
#include <string.h>
#include "mbedtls/md.h"
#include "mbedtls/platform.h"



// 消息认证码（Massage Authentication Code）用来检查消息的完整性和真实性。
// 消息认证码的输入为任意长度的消息和发送者与接收者之间共享的密钥，输出为固定长度的数据，该数据被称作MAC值、Tag或T。
// 发送者与接收者判断这个MAC判断消息完整性和真实性

// 消息认证码的实现

// 单项散列算法实现，这类方法统称为HMAC，
// 与SHA1算法结合称为HMAC-SHA1，
// 与SHA256算法结合称为HMAC-SHA256，
// 与MD5算法结合称为HMAC-MD5

// 分组密码实现，采用CBC模式称作CBC-MAC，还有CMAC
// 认证加密算法实现，是对称加密算法和消息认证码的结合，有GCM和CCM

// HMAC-SHA256例子


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