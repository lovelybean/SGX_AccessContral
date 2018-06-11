#include "ORAM_envalve_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_SaveasBlock_t {
	char* ms_buf;
	int ms_index;
	size_t ms_len;
} ms_SaveasBlock_t;



typedef struct ms_getuserdata_t {
	int ms_retval;
	int ms_pattern;
	int ms_index;
	int ms_userid;
	enum accesstype ms_userac;
} ms_getuserdata_t;


typedef struct ms_Transferid_t {
	char* ms_data;
	int ms_index;
	size_t ms_len;
} ms_Transferid_t;

typedef struct ms_getacORAM_t {
	int ms_index;
	int ms_id;
	int ms_ac;
	int ms_lo;
	int ms_len;
	int ms_tag;
} ms_getacORAM_t;

typedef struct ms_getacPosMap_t {
	int ms_index;
	int ms_tag;
	int ms_type;
} ms_getacPosMap_t;

typedef struct ms_returnuserdata_t {
	int ms_index;
	int ms_sign;
} ms_returnuserdata_t;

typedef struct ms_createcount_t {
	uint32_t ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
} ms_createcount_t;

typedef struct ms_updatecount_t {
	uint32_t ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
} ms_updatecount_t;

typedef struct ms_DetectacData_t {
	uint32_t ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
	uint8_t* ms_Endata;
	size_t ms_outlen;
} ms_DetectacData_t;

typedef struct ms_GetServerpublickey_t {
	int ms_retval;
	uint8_t* ms_px;
	uint8_t* ms_py;
	size_t ms_len;
} ms_GetServerpublickey_t;

typedef struct ms_ComputeSharekey_t {
	int ms_retval;
	uint8_t* ms_px;
	uint8_t* ms_py;
	size_t ms_len;
} ms_ComputeSharekey_t;

typedef struct ms_gettestdata_t {
	int ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
} ms_gettestdata_t;

typedef struct ms_Insertskey_t {
	int ms_retval;
	uint8_t* ms_sealkey;
	size_t ms_len;
} ms_Insertskey_t;

typedef struct ms_AnalysisRequest_t {
	uint32_t ms_retval;
	uint8_t* ms_request;
	size_t ms_len;
	uint8_t* ms_Response;
	size_t ms_Reslen;
} ms_AnalysisRequest_t;

typedef struct ms_Buildsecurepath_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_Buildsecurepath_t;

typedef struct ms_printblock_t {
	char* ms_data;
} ms_printblock_t;

typedef struct ms_printint_t {
	int ms_i;
} ms_printint_t;

typedef struct ms_getrandnum_t {
	int ms_retval;
	int ms_num;
} ms_getrandnum_t;

typedef struct ms_acValidity_t {
	int ms_retval;
	int ms_index;
	int ms_userid;
	enum accesstype ms_userac;
} ms_acValidity_t;

typedef struct ms_transferstash_t {
	char* ms_data;
	int ms_index;
	size_t ms_len;
} ms_transferstash_t;

typedef struct ms_SerializeORAM_t {
	char* ms_data;
	int ms_i;
	int ms_index;
	int ms_tag;
	size_t ms_len;
} ms_SerializeORAM_t;

typedef struct ms_StorePosMap_t {
	int ms_pos;
	int ms_tag;
	int ms_type;
} ms_StorePosMap_t;

typedef struct ms_Transferacbucket_t {
	int ms_len;
	int ms_index;
	int ms_tag;
} ms_Transferacbucket_t;

typedef struct ms_GetVcount_t {
	uint8_t* ms_data;
	size_t ms_len;
} ms_GetVcount_t;

typedef struct ms_Getdatalen_t {
	size_t ms_retval;
	int ms_ID;
} ms_Getdatalen_t;

typedef struct ms_Getuserdatafromdisk_t {
	int ms_ID;
	uint8_t* ms_userdata;
	size_t ms_len;
} ms_Getuserdatafromdisk_t;

typedef struct ms_UpdateshujutoServerdisk_t {
	int ms_retval;
	int ms_ID;
	uint8_t* ms_data;
	size_t ms_len;
} ms_UpdateshujutoServerdisk_t;

typedef struct ms_session_request_lo_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_lo_t;

typedef struct ms_exchange_report_lo_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_lo_t;

typedef struct ms_printhash_t {
	uint8_t* ms_dhash;
	size_t ms_len;
} ms_printhash_t;

typedef struct ms_disp_t {
	uint8_t* ms_pbuf;
	size_t ms_len;
} ms_disp_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	void* ms_waiter;
	void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_SaveasBlock(void* pms)
{
	ms_SaveasBlock_t* ms = SGX_CAST(ms_SaveasBlock_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_len = ms->ms_len;
	size_t _len_buf = _tmp_len;
	char* _in_buf = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_SaveasBlock_t));
	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	if (_tmp_buf != NULL) {
		_in_buf = (char*)malloc(_len_buf);
		if (_in_buf == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_buf, _tmp_buf, _len_buf);
	}
	SaveasBlock(_in_buf, ms->ms_index, _tmp_len);
err:
	if (_in_buf) free(_in_buf);

	return status;
}

static sgx_status_t SGX_CDECL sgx_getBlock(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	getBlock();
	return status;
}

static sgx_status_t SGX_CDECL sgx_InitORAM(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	InitORAM();
	return status;
}

static sgx_status_t SGX_CDECL sgx_getuserdata(void* pms)
{
	ms_getuserdata_t* ms = SGX_CAST(ms_getuserdata_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_getuserdata_t));

	ms->ms_retval = getuserdata(ms->ms_pattern, ms->ms_index, ms->ms_userid, ms->ms_userac);


	return status;
}

static sgx_status_t SGX_CDECL sgx_setbackdata(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	setbackdata();
	return status;
}

static sgx_status_t SGX_CDECL sgx_Transferid(void* pms)
{
	ms_Transferid_t* ms = SGX_CAST(ms_Transferid_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	char* _in_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_Transferid_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	if (_tmp_data != NULL) {
		_in_data = (char*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data, _tmp_data, _len_data);
	}
	Transferid(_in_data, ms->ms_index, _tmp_len);
err:
	if (_in_data) free(_in_data);

	return status;
}

static sgx_status_t SGX_CDECL sgx_getacORAM(void* pms)
{
	ms_getacORAM_t* ms = SGX_CAST(ms_getacORAM_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_getacORAM_t));

	getacORAM(ms->ms_index, ms->ms_id, ms->ms_ac, ms->ms_lo, ms->ms_len, ms->ms_tag);


	return status;
}

static sgx_status_t SGX_CDECL sgx_getacPosMap(void* pms)
{
	ms_getacPosMap_t* ms = SGX_CAST(ms_getacPosMap_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_getacPosMap_t));

	getacPosMap(ms->ms_index, ms->ms_tag, ms->ms_type);


	return status;
}

static sgx_status_t SGX_CDECL sgx_returnuserdata(void* pms)
{
	ms_returnuserdata_t* ms = SGX_CAST(ms_returnuserdata_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_returnuserdata_t));

	returnuserdata(ms->ms_index, ms->ms_sign);


	return status;
}

static sgx_status_t SGX_CDECL sgx_createcount(void* pms)
{
	ms_createcount_t* ms = SGX_CAST(ms_createcount_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_createcount_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	if (_tmp_data != NULL) {
		if ((_in_data = (uint8_t*)malloc(_len_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_data, 0, _len_data);
	}
	ms->ms_retval = createcount(_in_data, _tmp_len);
err:
	if (_in_data) {
		memcpy(_tmp_data, _in_data, _len_data);
		free(_in_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_updatecount(void* pms)
{
	ms_updatecount_t* ms = SGX_CAST(ms_updatecount_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_updatecount_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	if (_tmp_data != NULL) {
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data, _tmp_data, _len_data);
	}
	ms->ms_retval = updatecount(_in_data, _tmp_len);
err:
	if (_in_data) {
		memcpy(_tmp_data, _in_data, _len_data);
		free(_in_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_DetectacData(void* pms)
{
	ms_DetectacData_t* ms = SGX_CAST(ms_DetectacData_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_Endata = ms->ms_Endata;
	size_t _tmp_outlen = ms->ms_outlen;
	size_t _len_Endata = _tmp_outlen;
	uint8_t* _in_Endata = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_DetectacData_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_Endata, _len_Endata);

	if (_tmp_data != NULL) {
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data, _tmp_data, _len_data);
	}
	if (_tmp_Endata != NULL) {
		if ((_in_Endata = (uint8_t*)malloc(_len_Endata)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_Endata, 0, _len_Endata);
	}
	ms->ms_retval = DetectacData(_in_data, _tmp_len, _in_Endata, _tmp_outlen);
err:
	if (_in_data) free(_in_data);
	if (_in_Endata) {
		memcpy(_tmp_Endata, _in_Endata, _len_Endata);
		free(_in_Endata);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_GetServerpublickey(void* pms)
{
	ms_GetServerpublickey_t* ms = SGX_CAST(ms_GetServerpublickey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_px = ms->ms_px;
	size_t _tmp_len = ms->ms_len;
	size_t _len_px = _tmp_len;
	uint8_t* _in_px = NULL;
	uint8_t* _tmp_py = ms->ms_py;
	size_t _len_py = _tmp_len;
	uint8_t* _in_py = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_GetServerpublickey_t));
	CHECK_UNIQUE_POINTER(_tmp_px, _len_px);
	CHECK_UNIQUE_POINTER(_tmp_py, _len_py);

	if (_tmp_px != NULL) {
		if ((_in_px = (uint8_t*)malloc(_len_px)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_px, 0, _len_px);
	}
	if (_tmp_py != NULL) {
		if ((_in_py = (uint8_t*)malloc(_len_py)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_py, 0, _len_py);
	}
	ms->ms_retval = GetServerpublickey(_in_px, _in_py, _tmp_len);
err:
	if (_in_px) {
		memcpy(_tmp_px, _in_px, _len_px);
		free(_in_px);
	}
	if (_in_py) {
		memcpy(_tmp_py, _in_py, _len_py);
		free(_in_py);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ComputeSharekey(void* pms)
{
	ms_ComputeSharekey_t* ms = SGX_CAST(ms_ComputeSharekey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_px = ms->ms_px;
	size_t _tmp_len = ms->ms_len;
	size_t _len_px = _tmp_len;
	uint8_t* _in_px = NULL;
	uint8_t* _tmp_py = ms->ms_py;
	size_t _len_py = _tmp_len;
	uint8_t* _in_py = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ComputeSharekey_t));
	CHECK_UNIQUE_POINTER(_tmp_px, _len_px);
	CHECK_UNIQUE_POINTER(_tmp_py, _len_py);

	if (_tmp_px != NULL) {
		_in_px = (uint8_t*)malloc(_len_px);
		if (_in_px == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_px, _tmp_px, _len_px);
	}
	if (_tmp_py != NULL) {
		_in_py = (uint8_t*)malloc(_len_py);
		if (_in_py == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_py, _tmp_py, _len_py);
	}
	ms->ms_retval = ComputeSharekey(_in_px, _in_py, _tmp_len);
err:
	if (_in_px) free(_in_px);
	if (_in_py) free(_in_py);

	return status;
}

static sgx_status_t SGX_CDECL sgx_gettestdata(void* pms)
{
	ms_gettestdata_t* ms = SGX_CAST(ms_gettestdata_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_gettestdata_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);

	if (_tmp_data != NULL) {
		if ((_in_data = (uint8_t*)malloc(_len_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_data, 0, _len_data);
	}
	ms->ms_retval = gettestdata(_in_data, _tmp_len);
err:
	if (_in_data) {
		memcpy(_tmp_data, _in_data, _len_data);
		free(_in_data);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_Insertskey(void* pms)
{
	ms_Insertskey_t* ms = SGX_CAST(ms_Insertskey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealkey = ms->ms_sealkey;
	size_t _tmp_len = ms->ms_len;
	size_t _len_sealkey = _tmp_len;
	uint8_t* _in_sealkey = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_Insertskey_t));
	CHECK_UNIQUE_POINTER(_tmp_sealkey, _len_sealkey);

	if (_tmp_sealkey != NULL) {
		if ((_in_sealkey = (uint8_t*)malloc(_len_sealkey)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealkey, 0, _len_sealkey);
	}
	ms->ms_retval = Insertskey(_in_sealkey, _tmp_len);
err:
	if (_in_sealkey) {
		memcpy(_tmp_sealkey, _in_sealkey, _len_sealkey);
		free(_in_sealkey);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_AnalysisRequest(void* pms)
{
	ms_AnalysisRequest_t* ms = SGX_CAST(ms_AnalysisRequest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_request = ms->ms_request;
	size_t _tmp_len = ms->ms_len;
	size_t _len_request = _tmp_len;
	uint8_t* _in_request = NULL;
	uint8_t* _tmp_Response = ms->ms_Response;
	size_t _tmp_Reslen = ms->ms_Reslen;
	size_t _len_Response = _tmp_Reslen;
	uint8_t* _in_Response = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_AnalysisRequest_t));
	CHECK_UNIQUE_POINTER(_tmp_request, _len_request);
	CHECK_UNIQUE_POINTER(_tmp_Response, _len_Response);

	if (_tmp_request != NULL) {
		_in_request = (uint8_t*)malloc(_len_request);
		if (_in_request == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_request, _tmp_request, _len_request);
	}
	if (_tmp_Response != NULL) {
		if ((_in_Response = (uint8_t*)malloc(_len_Response)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_Response, 0, _len_Response);
	}
	ms->ms_retval = AnalysisRequest(_in_request, _tmp_len, _in_Response, _tmp_Reslen);
err:
	if (_in_request) free(_in_request);
	if (_in_Response) {
		memcpy(_tmp_Response, _in_Response, _len_Response);
		free(_in_Response);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_Buildsecurepath(void* pms)
{
	ms_Buildsecurepath_t* ms = SGX_CAST(ms_Buildsecurepath_t*, pms);
	sgx_status_t status = SGX_SUCCESS;

	CHECK_REF_POINTER(pms, sizeof(ms_Buildsecurepath_t));

	ms->ms_retval = Buildsecurepath(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[18];
} g_ecall_table = {
	18,
	{
		{(void*)(uintptr_t)sgx_SaveasBlock, 0},
		{(void*)(uintptr_t)sgx_getBlock, 0},
		{(void*)(uintptr_t)sgx_InitORAM, 0},
		{(void*)(uintptr_t)sgx_getuserdata, 0},
		{(void*)(uintptr_t)sgx_setbackdata, 0},
		{(void*)(uintptr_t)sgx_Transferid, 0},
		{(void*)(uintptr_t)sgx_getacORAM, 0},
		{(void*)(uintptr_t)sgx_getacPosMap, 0},
		{(void*)(uintptr_t)sgx_returnuserdata, 0},
		{(void*)(uintptr_t)sgx_createcount, 0},
		{(void*)(uintptr_t)sgx_updatecount, 0},
		{(void*)(uintptr_t)sgx_DetectacData, 0},
		{(void*)(uintptr_t)sgx_GetServerpublickey, 0},
		{(void*)(uintptr_t)sgx_ComputeSharekey, 0},
		{(void*)(uintptr_t)sgx_gettestdata, 0},
		{(void*)(uintptr_t)sgx_Insertskey, 0},
		{(void*)(uintptr_t)sgx_AnalysisRequest, 0},
		{(void*)(uintptr_t)sgx_Buildsecurepath, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[25][18];
} g_dyn_entry_table = {
	25,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL printblock(char* data)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = data ? strlen(data) + 1 : 0;

	ms_printblock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_printblock_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_printblock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_printblock_t));

	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL printint(int i)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_printint_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_printint_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_printint_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_printint_t));

	ms->ms_i = i;
	status = sgx_ocall(1, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL getrandnum(int* retval, int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_getrandnum_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_getrandnum_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_getrandnum_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_getrandnum_t));

	ms->ms_num = num;
	status = sgx_ocall(2, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL acValidity(int* retval, int index, int userid, enum accesstype userac)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_acValidity_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_acValidity_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_acValidity_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_acValidity_t));

	ms->ms_index = index;
	ms->ms_userid = userid;
	ms->ms_userac = userac;
	status = sgx_ocall(3, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL transferstash(char* data, int index, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = len;

	ms_transferstash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_transferstash_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_transferstash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_transferstash_t));

	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_index = index;
	ms->ms_len = len;
	status = sgx_ocall(4, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL SerializeORAM(char* data, int i, int index, int tag, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = len;

	ms_SerializeORAM_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_SerializeORAM_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_SerializeORAM_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_SerializeORAM_t));

	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_i = i;
	ms->ms_index = index;
	ms->ms_tag = tag;
	ms->ms_len = len;
	status = sgx_ocall(5, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL StorePosMap(int pos, int tag, int type)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_StorePosMap_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_StorePosMap_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_StorePosMap_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_StorePosMap_t));

	ms->ms_pos = pos;
	ms->ms_tag = tag;
	ms->ms_type = type;
	status = sgx_ocall(6, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Transferacbucket(int len, int index, int tag)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Transferacbucket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Transferacbucket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Transferacbucket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Transferacbucket_t));

	ms->ms_len = len;
	ms->ms_index = index;
	ms->ms_tag = tag;
	status = sgx_ocall(7, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL GetVcount(uint8_t* data, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = len;

	ms_GetVcount_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_GetVcount_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_GetVcount_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_GetVcount_t));

	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memset(ms->ms_data, 0, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(8, ms);

	if (data) memcpy((void*)data, ms->ms_data, _len_data);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Getdatalen(size_t* retval, int ID)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_Getdatalen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Getdatalen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Getdatalen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Getdatalen_t));

	ms->ms_ID = ID;
	status = sgx_ocall(9, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL Getuserdatafromdisk(int ID, uint8_t* userdata, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_userdata = len;

	ms_Getuserdatafromdisk_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Getuserdatafromdisk_t);
	void *__tmp = NULL;

	ocalloc_size += (userdata != NULL && sgx_is_within_enclave(userdata, _len_userdata)) ? _len_userdata : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Getuserdatafromdisk_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Getuserdatafromdisk_t));

	ms->ms_ID = ID;
	if (userdata != NULL && sgx_is_within_enclave(userdata, _len_userdata)) {
		ms->ms_userdata = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_userdata);
		memset(ms->ms_userdata, 0, _len_userdata);
	} else if (userdata == NULL) {
		ms->ms_userdata = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(10, ms);

	if (userdata) memcpy((void*)userdata, ms->ms_userdata, _len_userdata);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL UpdateshujutoServerdisk(int* retval, int ID, uint8_t* data, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data = len;

	ms_UpdateshujutoServerdisk_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_UpdateshujutoServerdisk_t);
	void *__tmp = NULL;

	ocalloc_size += (data != NULL && sgx_is_within_enclave(data, _len_data)) ? _len_data : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_UpdateshujutoServerdisk_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_UpdateshujutoServerdisk_t));

	ms->ms_ID = ID;
	if (data != NULL && sgx_is_within_enclave(data, _len_data)) {
		ms->ms_data = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_data);
		memcpy(ms->ms_data, data, _len_data);
	} else if (data == NULL) {
		ms->ms_data = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(11, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL session_request_lo(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg1 = sizeof(*dh_msg1);
	size_t _len_session_id = sizeof(*session_id);

	ms_session_request_lo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_session_request_lo_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;
	ocalloc_size += (session_id != NULL && sgx_is_within_enclave(session_id, _len_session_id)) ? _len_session_id : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_session_request_lo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_session_request_lo_t));

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (sgx_dh_msg1_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (session_id != NULL && sgx_is_within_enclave(session_id, _len_session_id)) {
		ms->ms_session_id = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_session_id);
		memset(ms->ms_session_id, 0, _len_session_id);
	} else if (session_id == NULL) {
		ms->ms_session_id = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(12, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);
	if (session_id) memcpy((void*)session_id, ms->ms_session_id, _len_session_id);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_lo(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = sizeof(*dh_msg2);
	size_t _len_dh_msg3 = sizeof(*dh_msg3);

	ms_exchange_report_lo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_lo_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_lo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_lo_t));

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (sgx_dh_msg2_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (sgx_dh_msg3_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_session_id = session_id;
	status = sgx_ocall(13, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL printhash(uint8_t* dhash, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dhash = len;

	ms_printhash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_printhash_t);
	void *__tmp = NULL;

	ocalloc_size += (dhash != NULL && sgx_is_within_enclave(dhash, _len_dhash)) ? _len_dhash : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_printhash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_printhash_t));

	if (dhash != NULL && sgx_is_within_enclave(dhash, _len_dhash)) {
		ms->ms_dhash = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dhash);
		memcpy(ms->ms_dhash, dhash, _len_dhash);
	} else if (dhash == NULL) {
		ms->ms_dhash = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(14, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL disp(uint8_t* pbuf, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pbuf = len;

	ms_disp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_disp_t);
	void *__tmp = NULL;

	ocalloc_size += (pbuf != NULL && sgx_is_within_enclave(pbuf, _len_pbuf)) ? _len_pbuf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_disp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_disp_t));

	if (pbuf != NULL && sgx_is_within_enclave(pbuf, _len_pbuf)) {
		ms->ms_pbuf = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pbuf);
		memcpy(ms->ms_pbuf, pbuf, _len_pbuf);
	} else if (pbuf == NULL) {
		ms->ms_pbuf = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(15, ms);


	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(*sid);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));

	if (sid != NULL && sgx_is_within_enclave(sid, _len_sid)) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_sid);
		memset(ms->ms_sid, 0, _len_sid);
	} else if (sid == NULL) {
		ms->ms_sid = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	if (dh_msg1 != NULL && sgx_is_within_enclave(dh_msg1, _len_dh_msg1)) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		memset(ms->ms_dh_msg1, 0, _len_dh_msg1);
	} else if (dh_msg1 == NULL) {
		ms->ms_dh_msg1 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(16, ms);

	if (retval) *retval = ms->ms_retval;
	if (sid) memcpy((void*)sid, ms->ms_sid, _len_sid);
	if (dh_msg1) memcpy((void*)dh_msg1, ms->ms_dh_msg1, _len_dh_msg1);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));

	ms->ms_sid = sid;
	if (dh_msg2 != NULL && sgx_is_within_enclave(dh_msg2, _len_dh_msg2)) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		memcpy(ms->ms_dh_msg2, dh_msg2, _len_dh_msg2);
	} else if (dh_msg2 == NULL) {
		ms->ms_dh_msg2 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL && sgx_is_within_enclave(dh_msg3, _len_dh_msg3)) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		memset(ms->ms_dh_msg3, 0, _len_dh_msg3);
	} else if (dh_msg3 == NULL) {
		ms->ms_dh_msg3 = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(17, ms);

	if (retval) *retval = ms->ms_retval;
	if (dh_msg3) memcpy((void*)dh_msg3, ms->ms_dh_msg3, _len_dh_msg3);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(18, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));

	if (pse_message_req != NULL && sgx_is_within_enclave(pse_message_req, _len_pse_message_req)) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		memcpy(ms->ms_pse_message_req, pse_message_req, _len_pse_message_req);
	} else if (pse_message_req == NULL) {
		ms->ms_pse_message_req = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL && sgx_is_within_enclave(pse_message_resp, _len_pse_message_resp)) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		memset(ms->ms_pse_message_resp, 0, _len_pse_message_resp);
	} else if (pse_message_resp == NULL) {
		ms->ms_pse_message_resp = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(19, ms);

	if (retval) *retval = ms->ms_retval;
	if (pse_message_resp) memcpy((void*)pse_message_resp, ms->ms_pse_message_resp, _len_pse_message_resp);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(*cpuinfo);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	ocalloc_size += (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));

	if (cpuinfo != NULL && sgx_is_within_enclave(cpuinfo, _len_cpuinfo)) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		memcpy(ms->ms_cpuinfo, cpuinfo, _len_cpuinfo);
	} else if (cpuinfo == NULL) {
		ms->ms_cpuinfo = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(20, ms);

	if (cpuinfo) memcpy((void*)cpuinfo, ms->ms_cpuinfo, _len_cpuinfo);

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));

	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(21, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	status = sgx_ocall(22, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));

	ms->ms_waiter = SGX_CAST(void*, waiter);
	ms->ms_self = SGX_CAST(void*, self);
	status = sgx_ocall(23, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(*waiters);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;

	ocalloc_size += (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));

	if (waiters != NULL && sgx_is_within_enclave(waiters, _len_waiters)) {
		ms->ms_waiters = (void**)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		memcpy((void*)ms->ms_waiters, waiters, _len_waiters);
	} else if (waiters == NULL) {
		ms->ms_waiters = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(24, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
