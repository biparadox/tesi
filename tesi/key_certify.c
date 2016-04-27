/*
 */

#include <stdio.h>
#include <tss/tss_structs.h>
#include "common.h"
#include <tss/tpm.h>
#include "../include/tesi.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "key_certify.h"
#include "key_certify_desc.h"

extern TSS_HCONTEXT hContext;
extern TSS_HTPM hTPM;
extern TSS_HKEY hSRK;

int TESI_Report_CertifyKey(TSS_HKEY hKey,TSS_HKEY hAIKey, char * valdataname)
{
	TSS_RESULT result;
	BYTE buf[20];
	TSS_VALIDATION valData;

	result = TESI_Local_GetRandom(buf,20);
	if (result != TSS_SUCCESS) {
		return result;
	
	}

	valData.ulExternalDataLength = 20;
	valData.rgbExternalData = buf;

		//Call Key Certify Key
	result = Tspi_Key_CertifyKey(hKey, hAIKey, &valData);
	if (result != TSS_SUCCESS){
		printf ( "Certify Key Error! %s",tss_err_string(result));
		return result;
	}
	WriteValidation(&valData,valdataname);
	return TSS_SUCCESS;
}

int TESI_Report_GetKeyDigest(TSS_HKEY * hKey,BYTE * digest )
{
	UINT32 blob_size;
	UINT16 offset;
	BYTE *blob,pub_blob[1024];
	TSS_RESULT result;
	TPM_PUBKEY pubkey;
		
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				    &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		return result;
	}
	offset = 0;
	result = TestSuite_UnloadBlob_PUBKEY(&offset, blob, &pubkey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetAttribData", result);
		return result;
	}

	Tspi_Context_FreeMemory(hContext, blob);
	/* Free the first dangling reference, putting 'n' in its place */
	
	calculate_context_sha1(pubkey.pubKey.key,pubkey.pubKey.keyLength,digest);
	return TSS_SUCCESS;
}

void * create_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid)
{

	TSS_RESULT result;	
	char digest[DIGEST_SIZE];
	int  len;
	char filename[256];
	FILE * file;
	BYTE * buf;
	TSS_VALIDATION valData;
	TPM_CERTIFY_INFO key_info;
	

	
	void * struct_template;
	KEY_CERT * key_cert;
	key_cert = malloc(sizeof(KEY_CERT));
	if(key_cert==NULL)
		return NULL;
	
	memset(key_cert,0,sizeof(KEY_CERT));

	if((keyuuid!=NULL))
		memcpy(key_cert->keyuuid,keyuuid,DIGEST_SIZE*2);
	if((aikuuid!=NULL))
		memcpy(key_cert->aikuuid,aikuuid,DIGEST_SIZE*2);


	sprintf(filename,"%s.val",key_cert_file);

	if(calculate_sm3(filename,digest)!=0)
		return NULL;
	digest_to_uuid(digest,key_cert->uuid);

	result=ReadValidation(&valData,key_cert_file);

	if(result!=TSS_SUCCESS)
		return NULL;

	UINT16 offset=0;
	result= TestSuite_UnloadBlob_KEY_CERTIFY(&offset,valData.rgbData,&key_info);
	if(result!=TSS_SUCCESS)
		return NULL;

	key_cert->keyusage=key_info.keyUsage;
	key_cert->keyflags=key_info.keyFlags;
	key_cert->authdatausage=key_info.authDataUsage;
	key_cert->keydigestsize=20; // SHA1's digest size
	key_cert->pubkeydigest=malloc(key_cert->keydigestsize);
	if(key_cert->pubkeydigest==NULL)
	{
		free(key_cert);
		return NULL;
	}
	memcpy(key_cert->pubkeydigest,key_info.pubkeyDigest.digest,key_cert->keydigestsize);
	key_cert->PCRinfosize=key_info.PCRInfoSize;
	if(key_cert->PCRinfosize!=0)
	{
		key_cert->PCRinfos=malloc(key_cert->PCRinfosize);
		if(key_cert->PCRinfos==NULL)
		{
			free(key_cert->pubkeydigest);
			free(key_cert);
			return NULL;
		}
		memcpy(key_cert->PCRinfos,key_info.PCRInfo,key_cert->PCRinfosize);
		
	}	
	key_cert->filename=malloc(strlen(key_cert_file)+1);
	if(key_cert->filename==NULL)
	{
		free(key_cert);
		return NULL;
	}
	memcpy(key_cert->filename,key_cert_file,strlen(key_cert_file)+1);
	return key_cert;

}
void * verify_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);
