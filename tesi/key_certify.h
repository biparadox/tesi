#ifndef KEY_CERTIFY_H
#define KEY_CERTIFY_H


static NAME2VALUE key_usage_list[] = 
{
	{"TPM_KEY_SIGNING",0x0010},
	{"TPM_KEY_STORAGE",0x0011},
	{"TPM_KEY_IDENTITY",0x0012},
	{"TPM_KEY_AUTHCHANGE",0x0013},
	{"TPM_KEY_BIND",0x0014},
	{"TPM_KEY_LEGACY",0x0015},
	{"TPM_KEY_MIGRATE",0x0016},
	{NULL,0}
};

static NAME2VALUE key_flags_list[] = 
{
	{"TPM_REDIRECTION",0x00000001},
	{"TPM_MIGRATABLE",0x00000002},
	{"TPM_VOLATILE",0x00000004},
	{"TPM_PCRIGNOREDONREAD",0x00000008},
	{"TPM_MIGRATEAUTHORITY",0x00000010},
	{NULL,0}
};

static NAME2VALUE tpm_auth_data_usage[] = 
{
	{"TPM_AUTH_NEVER",0x00},
	{"TPM_AUTH_ALWAYS",0x01},
	{"TPM_AUTH_PRIV_USE_ONLY",0x11},
	{NULL,0}
};

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


static struct struct_elem_attr key_cert_desc[]=  // TKCI
{
	{"uuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"keyuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"aikuuid",OS210_TYPE_STRING,DIGEST_SIZE*2,NULL},
	{"keyusage",TPM_TYPE_UINT16,sizeof(UINT16),NULL},
	{"keyflags",OS210_TYPE_FLAG,sizeof(UINT32),NULL},
	{"authdatausage",OS210_TYPE_UCHAR,sizeof(BYTE),NULL},
	{"keydigestsize",OS210_TYPE_INT,sizeof(int),NULL},
	{"pubkeydigest",OS210_TYPE_DEFSTR,0,"keydigestsize"},
	{"PCRinfosize",OS210_TYPE_INT,sizeof(int),NULL},
	{"PCRinfos",OS210_TYPE_DEFSTR,0,"PCRinfosize"},
	{"filename",OS210_TYPE_ESTRING,DIGEST_SIZE*2+10,NULL},
	{NULL,OS210_TYPE_ENDDATA,0,NULL}
};

void * key_certify_create_struct();

#endif
