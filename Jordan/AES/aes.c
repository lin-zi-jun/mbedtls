#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "mbedtls/cipher.h"
#include "mbedtls/platform.h"

/*
    # padding with pkcs7 AES_128_CBC Encrypt
    ptx = "CBC has been the most commonly used mode of operation."
    key = 06a9214036b8a15b512e03d534120006
    iv  = 3dafba429d9eb430b422da802c9fac41
*/
char *ptx = "CBC has been the most commonly used mode of operation.";
uint8_t key[16] =
{
    0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b,
    0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06
};

uint8_t iv[16] =
{
    0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30,
    0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41
};

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
    mbedtls_printf("\n  cipher info setup, name: %s, block size: %d\n", 
                        mbedtls_cipher_get_name(ctx), 
                        mbedtls_cipher_get_block_size(ctx));

    mbedtls_cipher_setkey(ctx, key, key_bitlen, operation);
    mbedtls_cipher_set_iv(ctx, iv, iv_len);
	return 0;
}

int my_aes_update(mbedtls_cipher_context_t *ctx, const unsigned char *input,
                   size_t ilen, unsigned char *output, size_t *olen )
{
	return mbedtls_cipher_update(ctx, input,ilen, output,olen);
}

int my_aes_finish(mbedtls_cipher_context_t *ctx,unsigned char *output, size_t *olen )
{
	return mbedtls_cipher_finish(ctx,output,olen);
}

void my_aes_deinit(mbedtls_cipher_context_t *ctx)
{
	mbedtls_cipher_free(ctx);
}

int main(void)
{

    size_t len;
    int olen = 0;
    uint8_t buf[256];
	
    //MBEDTLS_CIPHER_AES_128_CBC enc
	mbedtls_cipher_context_t aes_cbc_128_ctx;
	my_aes_init(MBEDTLS_CIPHER_AES_128_CBC,&aes_cbc_128_ctx,key,sizeof(key)*8,MBEDTLS_ENCRYPT,iv,sizeof(iv));
	olen = 0;
	memset(buf,0,sizeof(buf));
	my_aes_update(&aes_cbc_128_ctx,ptx,strlen(ptx),buf,&len);
	olen += len;
    my_aes_update(&aes_cbc_128_ctx,ptx,strlen(ptx),buf+olen,&len);
	olen += len;
	my_aes_finish(&aes_cbc_128_ctx,buf+olen,&len);
	olen += len;
	my_aes_deinit(&aes_cbc_128_ctx);
	dump_buf("\n cbc cipher aes encrypt:", buf, olen);
    printf("%d\n",olen);

    int text_olen = 0;len = 0;
    uint8_t text_buf[256];
	//MBEDTLS_CIPHER_AES_128_CBC dec
	my_aes_init(MBEDTLS_CIPHER_AES_128_CBC,&aes_cbc_128_ctx,key,sizeof(key)*8,MBEDTLS_DECRYPT,iv,sizeof(iv));
	memset(text_buf,0,sizeof(text_buf));
	my_aes_update(&aes_cbc_128_ctx,buf,olen,text_buf,&len);
	text_olen +=len;
	my_aes_finish(&aes_cbc_128_ctx,text_buf+text_olen,&len);
	text_olen += len;
	my_aes_deinit(&aes_cbc_128_ctx);
	printf("text_olen :%d strlen(text_buf): %ld\n",text_olen,strlen(text_buf));
	dump_buf("\n cbc text aes decrypt:", text_buf, text_olen);
	dump_buf("\n cbc text aes decrypt:", text_buf, strlen(text_buf));

    //del padding 
    int del_cnt = text_buf[strlen(text_buf)-1];
	while(del_cnt)
	{
		text_buf[text_olen+del_cnt-1] = 0;
		del_cnt--;
	}
	printf("cbc decrypt: %s\n",text_buf);
//===========================================================
    //MBEDTLS_CIPHER_AES_128_CTR enc
	mbedtls_cipher_context_t aes_ctr_128_ctr;
	my_aes_init(MBEDTLS_CIPHER_AES_128_CTR,&aes_ctr_128_ctr,key,sizeof(key)*8,MBEDTLS_ENCRYPT,iv,sizeof(iv));
	olen = 0;
	memset(buf,0,sizeof(buf));
	my_aes_update(&aes_ctr_128_ctr,ptx,strlen(ptx),buf,&len);
	olen += len;
    my_aes_update(&aes_ctr_128_ctr,ptx,strlen(ptx),buf+olen,&len);
	olen += len;
	my_aes_finish(&aes_ctr_128_ctr,buf+olen,&len);
	olen += len;
	my_aes_deinit(&aes_ctr_128_ctr);
	dump_buf("\n ctr cipher aes encrypt:", buf, olen);
    printf("%d\n",olen);

    text_olen = 0;len = 0;
	//MBEDTLS_CIPHER_AES_128_CTR dec
	my_aes_init(MBEDTLS_CIPHER_AES_128_CTR,&aes_ctr_128_ctr,key,sizeof(key)*8,MBEDTLS_DECRYPT,iv,sizeof(iv));
	memset(text_buf,0,sizeof(text_buf));
	my_aes_update(&aes_ctr_128_ctr,buf,olen,text_buf,&len);
	text_olen +=len;
	my_aes_finish(&aes_ctr_128_ctr,text_buf+text_olen,&len);
	text_olen += len;
	my_aes_deinit(&aes_ctr_128_ctr);
	printf("text_olen :%d strlen(text_buf) :%ld\n",text_olen,strlen(text_buf));
	dump_buf("\n cbc text aes decrypt:", text_buf, text_olen);
	dump_buf("\n cbc text aes decrypt:", text_buf, strlen(text_buf));

	printf("ctr decrypt: %s\n",text_buf);

    return 0;
}
