#ifndef KEY_CERTIFY_H
#define KEY_CERTIFY_H


typedef struct tagtpm_key_certify_info   // KEY CERTIFO
{
	char uuid[DIGEST_SIZE*2];
	char keyuuid[DIGEST_SIZE*2];
	char aikuuid[DIGEST_SIZE*2];
    	UINT16       keyusage;
    	UINT16	     keyflags;
    	BYTE authdatausage;
	int  keydigestsize;
	BYTE *pubkeydigest;
	int PCRinfosize;
	BYTE * PCRinfos;	
	char * filename;

}__attribute((packed)) KEY_CERT;

void * create_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);
void * verify_key_certify_struct(void * key_cert_file,char * keyuuid,char * aikuuid);

#endif
