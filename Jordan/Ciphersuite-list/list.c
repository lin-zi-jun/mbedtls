#include <stdio.h>
#include "mbedtls/ssl.h"

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