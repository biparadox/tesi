/*
 */

#include <stdio.h>
#include <tss/tss_structs.h>
#include "common.h"
#include "../include/tesi.h"
#include "../include/struct_deal.h"
#include "../include/crypto_func.h"
#include "key_certify.h"

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
