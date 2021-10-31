#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"
#include "mbedtls/base64.h"

// ECB(Electronic Code Book电子密码本)模式
// ECB模式是最早采用和最简单的模式，它将加密的数据分成若干组，每组的大小跟加密密钥长度相同，然后每组都用相同的密钥进行加密。
// 优点:
// 1.简单；　2.有利于并行计算；　3.误差不会被传送；　缺点:　1.不能隐藏明文的模式；　2.可能对明文进行主动攻击；　因此，此模式适于加密小消息。
// CBC(Cipher Block Chaining，加密块链)模式
// 优点：
// 1.不容易主动攻击,安全性好于ECB,适合传输长度长的报文,是SSL、IPSec的标准。　缺点：　1.不利于并行计算；　2.误差传递；　3.需要初始化向量IV
// CFB(Cipher FeedBack Mode，加密反馈)模式
// 优点：
// 1.隐藏了明文模式;　2.分组密码转化为流模式;　3.可以及时加密传送小于分组的数据;　缺点:　1.不利于并行计算;　2.误差传送：一个明文单元损坏影响多个单元;　3.唯一的IV;
// OFB(Output FeedBack，输出反馈)模式
// 优点:
// 1.隐藏了明文模式;　2.分组密码转化为流模式;　3.可以及时加密传送小于分组的数据;　缺点:　1.不利于并行计算;　2.对明文的主动攻击是可能的;　3.误差传送：一个明文单元损坏影响多个单元 [4]  。

/*
    # padding with pkcs7 AES_128_CBC Encrypt
    ptx = "CBC has been the most commonly used mode of operation."
    key = 06a9214036b8a15b512e03d534120006
    iv  = 3dafba429d9eb430b422da802c9fac41
*/
uint8_t key[16];
uint8_t iv[16];


static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (int i = 0; i < len; i++) {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n\t":" ", 
                        buf[i], i == len - 1 ? "\n":"");
    }
    mbedtls_printf("\n");
}

int my_aes_init(int type,mbedtls_cipher_context_t *ctx,const unsigned char *key,
        int key_bitlen, const mbedtls_operation_t operation,const unsigned char *iv, size_t iv_len)
{
    const mbedtls_cipher_info_t *info;
    mbedtls_cipher_init(ctx);
    info = mbedtls_cipher_info_from_type(type);
    mbedtls_cipher_setup(ctx, info);
    mbedtls_cipher_setkey(ctx, key, key_bitlen, operation);
    mbedtls_cipher_set_iv(ctx, iv, iv_len);
	return 0;
}


#define DEBUG_PK printf
static char *sgStandCharBlack="0123456789ABCDEF";
void DbgPrinStr( const char *iStr,void *iPD,int iLen){
    char    *tPD = (char*)iPD;
    int     _i,_j, _k, _s, _c;
    char    tTppl[4];
    char    tvPrintBuf[ 128 ];

    tTppl[2] = '\0';

    DEBUG_PK("%s\n",(char*)iStr);
    for( _i=0; _i<10; _i++ )
        tvPrintBuf[ 49 + _i ] = ' ';
    _i = 0;
    while(_i<iLen){
        _c = 0;
        for(_j=0;(_j<16)&&((_i+_j)<iLen);_j++){
            tvPrintBuf[ _c++ ] = sgStandCharBlack[(tPD[_i+_j]&0xF0)>>4];
            tvPrintBuf[ _c++ ] = sgStandCharBlack[tPD[_i+_j]&0x0F];
            tvPrintBuf[ _c++ ] = ' ';
            if(_j == 7) tvPrintBuf[ _c++ ] = ' ';
        }
        _s = 49 - (_j*3) - _j/8;
        for( _k=0;_k<_s;_k++ )
            tvPrintBuf[ _c++ ] = ' ';

        _c += 10;

        for(_j=0;(_j<16)&&(_i<iLen);_j++){
            if( ( isprint( tPD[_i] ) ) && ( tPD[_i] != '\r' ) && ( tPD[_i] != '\n' ) )
                tvPrintBuf[ _c++ ] = tPD[_i];
            else
                tvPrintBuf[ _c++ ] = '.';
            _i++;
        }
        tvPrintBuf[ _c++ ] = '\r';
        tvPrintBuf[ _c++ ] = '\n';
        tvPrintBuf[ _c++ ] = '\0';
        DEBUG_PK( "%s", tvPrintBuf );
    }
}



int main(int argc ,char *argv[])
{
  uint8_t md5_data[16]={0};
  uint8_t buf[128] = {0};

  if(argc!=4){
    printf("please input correct parameter --> key + iv + data\n");
    return -1;
  }

  if((strlen(argv[1])!=16)||(strlen(argv[2])!=16)){
    printf("%s\n",argv[1]);
    printf("please input correct 16-byte key or iv value\r\n");
    return -1;
  }
    size_t len;
    int olen = 0;
	size_t len1;
	uint8_t buf1[256];
	uint8_t buf2[1024];
	
    // MBEDTLS_CIPHER_AES_128_CBC enc
	mbedtls_cipher_context_t aes_cbc_128_ctx;
	// my_aes_init(MBEDTLS_CIPHER_AES_128_CBC,&aes_cbc_128_ctx,key,sizeof(key)*8,MBEDTLS_ENCRYPT,iv,sizeof(iv));

	// olen = 0;
	// memset(buf,0,sizeof(buf));
	// mbedtls_cipher_update(&aes_cbc_128_ctx,ptx,strlen(ptx),buf,&len);
	// olen += len;
	// mbedtls_cipher_finish(&aes_cbc_128_ctx,buf+olen,&len);
	// olen += len;
	// mbedtls_cipher_free(&aes_cbc_128_ctx);
	// DbgPrinStr("加密",buf,olen);

	
	// mbedtls_base64_encode(buf1,sizeof(buf1),&len1,buf,olen);
	// printf("base64:%s\r\n",buf1);


	// printf("key:%s\niv:%s\ndata:%s\n",argv[1],argv[2],argv[3]);
	mbedtls_base64_decode(buf2,sizeof(buf2),&len1,argv[3],strlen(argv[3]));
	DbgPrinStr("base64 decode:",buf2,len1);

    int text_olen = 0;len = 0;
    uint8_t text_buf[1024];
	my_aes_init(MBEDTLS_CIPHER_AES_128_CBC,&aes_cbc_128_ctx,argv[1],strlen(argv[1])*8,MBEDTLS_DECRYPT,argv[2],strlen(argv[2]));
	memset(text_buf,0,sizeof(text_buf));
	mbedtls_cipher_update(&aes_cbc_128_ctx,buf2,len1,text_buf,&len);
	text_olen +=len;
	mbedtls_cipher_finish(&aes_cbc_128_ctx,text_buf+text_olen,&len);
	text_olen += len;
	mbedtls_cipher_free(&aes_cbc_128_ctx);
	DbgPrinStr("AES CBC decode:",text_buf,text_olen);

    return 0;
}
