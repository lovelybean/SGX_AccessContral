#include "ORAM_envalve_u.h"
#include <errno.h>

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

typedef struct ms_GetdatatoClient_t {
	int ms_retval;
	int ms_ID;
	uint8_t* ms_data;
	size_t ms_len;
	uint8_t* ms_Enuserdata;
	size_t ms_Enlen;
} ms_GetdatatoClient_t;

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

typedef struct ms_Getuserfilefromenclave2_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_dest_enclave_id;
	uint8_t* ms_data;
	size_t ms_len;
	uint8_t* ms_Enuserdata;
	size_t ms_len2;
} ms_Getuserfilefromenclave2_t;

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

static sgx_status_t SGX_CDECL ORAM_envalve_printblock(void* pms)
{
	ms_printblock_t* ms = SGX_CAST(ms_printblock_t*, pms);
	printblock(ms->ms_data);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_printint(void* pms)
{
	ms_printint_t* ms = SGX_CAST(ms_printint_t*, pms);
	printint(ms->ms_i);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_getrandnum(void* pms)
{
	ms_getrandnum_t* ms = SGX_CAST(ms_getrandnum_t*, pms);
	ms->ms_retval = getrandnum(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_acValidity(void* pms)
{
	ms_acValidity_t* ms = SGX_CAST(ms_acValidity_t*, pms);
	ms->ms_retval = acValidity(ms->ms_index, ms->ms_userid, ms->ms_userac);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_transferstash(void* pms)
{
	ms_transferstash_t* ms = SGX_CAST(ms_transferstash_t*, pms);
	transferstash(ms->ms_data, ms->ms_index, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_SerializeORAM(void* pms)
{
	ms_SerializeORAM_t* ms = SGX_CAST(ms_SerializeORAM_t*, pms);
	SerializeORAM(ms->ms_data, ms->ms_i, ms->ms_index, ms->ms_tag, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_StorePosMap(void* pms)
{
	ms_StorePosMap_t* ms = SGX_CAST(ms_StorePosMap_t*, pms);
	StorePosMap(ms->ms_pos, ms->ms_tag, ms->ms_type);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_Transferacbucket(void* pms)
{
	ms_Transferacbucket_t* ms = SGX_CAST(ms_Transferacbucket_t*, pms);
	Transferacbucket(ms->ms_len, ms->ms_index, ms->ms_tag);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_GetVcount(void* pms)
{
	ms_GetVcount_t* ms = SGX_CAST(ms_GetVcount_t*, pms);
	GetVcount(ms->ms_data, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_Getdatalen(void* pms)
{
	ms_Getdatalen_t* ms = SGX_CAST(ms_Getdatalen_t*, pms);
	ms->ms_retval = Getdatalen(ms->ms_ID);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_Getuserdatafromdisk(void* pms)
{
	ms_Getuserdatafromdisk_t* ms = SGX_CAST(ms_Getuserdatafromdisk_t*, pms);
	Getuserdatafromdisk(ms->ms_ID, ms->ms_userdata, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_UpdateshujutoServerdisk(void* pms)
{
	ms_UpdateshujutoServerdisk_t* ms = SGX_CAST(ms_UpdateshujutoServerdisk_t*, pms);
	ms->ms_retval = UpdateshujutoServerdisk(ms->ms_ID, ms->ms_data, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_session_request_lo(void* pms)
{
	ms_session_request_lo_t* ms = SGX_CAST(ms_session_request_lo_t*, pms);
	ms->ms_retval = session_request_lo(ms->ms_src_enclave_id, ms->ms_dest_enclave_id, ms->ms_dh_msg1, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_exchange_report_lo(void* pms)
{
	ms_exchange_report_lo_t* ms = SGX_CAST(ms_exchange_report_lo_t*, pms);
	ms->ms_retval = exchange_report_lo(ms->ms_src_enclave_id, ms->ms_dest_enclave_id, ms->ms_dh_msg2, ms->ms_dh_msg3, ms->ms_session_id);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_printhash(void* pms)
{
	ms_printhash_t* ms = SGX_CAST(ms_printhash_t*, pms);
	printhash(ms->ms_dhash, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_disp(void* pms)
{
	ms_disp_t* ms = SGX_CAST(ms_disp_t*, pms);
	disp(ms->ms_pbuf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_Getuserfilefromenclave2(void* pms)
{
	ms_Getuserfilefromenclave2_t* ms = SGX_CAST(ms_Getuserfilefromenclave2_t*, pms);
	ms->ms_retval = Getuserfilefromenclave2(ms->ms_dest_enclave_id, ms->ms_data, ms->ms_len, ms->ms_Enuserdata, ms->ms_len2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL ORAM_envalve_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[26];
} ocall_table_ORAM_envalve = {
	26,
	{
		(void*)(uintptr_t)ORAM_envalve_printblock,
		(void*)(uintptr_t)ORAM_envalve_printint,
		(void*)(uintptr_t)ORAM_envalve_getrandnum,
		(void*)(uintptr_t)ORAM_envalve_acValidity,
		(void*)(uintptr_t)ORAM_envalve_transferstash,
		(void*)(uintptr_t)ORAM_envalve_SerializeORAM,
		(void*)(uintptr_t)ORAM_envalve_StorePosMap,
		(void*)(uintptr_t)ORAM_envalve_Transferacbucket,
		(void*)(uintptr_t)ORAM_envalve_GetVcount,
		(void*)(uintptr_t)ORAM_envalve_Getdatalen,
		(void*)(uintptr_t)ORAM_envalve_Getuserdatafromdisk,
		(void*)(uintptr_t)ORAM_envalve_UpdateshujutoServerdisk,
		(void*)(uintptr_t)ORAM_envalve_session_request_lo,
		(void*)(uintptr_t)ORAM_envalve_exchange_report_lo,
		(void*)(uintptr_t)ORAM_envalve_printhash,
		(void*)(uintptr_t)ORAM_envalve_disp,
		(void*)(uintptr_t)ORAM_envalve_Getuserfilefromenclave2,
		(void*)(uintptr_t)ORAM_envalve_create_session_ocall,
		(void*)(uintptr_t)ORAM_envalve_exchange_report_ocall,
		(void*)(uintptr_t)ORAM_envalve_close_session_ocall,
		(void*)(uintptr_t)ORAM_envalve_invoke_service_ocall,
		(void*)(uintptr_t)ORAM_envalve_sgx_oc_cpuidex,
		(void*)(uintptr_t)ORAM_envalve_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)ORAM_envalve_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)ORAM_envalve_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)ORAM_envalve_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t SaveasBlock(sgx_enclave_id_t eid, char* buf, int index, size_t len)
{
	sgx_status_t status;
	ms_SaveasBlock_t ms;
	ms.ms_buf = buf;
	ms.ms_index = index;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_ORAM_envalve, &ms);
	return status;
}

sgx_status_t getBlock(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_ORAM_envalve, NULL);
	return status;
}

sgx_status_t InitORAM(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_ORAM_envalve, NULL);
	return status;
}

sgx_status_t getuserdata(sgx_enclave_id_t eid, int* retval, int pattern, int index, int userid, enum accesstype userac)
{
	sgx_status_t status;
	ms_getuserdata_t ms;
	ms.ms_pattern = pattern;
	ms.ms_index = index;
	ms.ms_userid = userid;
	ms.ms_userac = userac;
	status = sgx_ecall(eid, 3, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t setbackdata(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_ORAM_envalve, NULL);
	return status;
}

sgx_status_t Transferid(sgx_enclave_id_t eid, char* data, int index, size_t len)
{
	sgx_status_t status;
	ms_Transferid_t ms;
	ms.ms_data = data;
	ms.ms_index = index;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_ORAM_envalve, &ms);
	return status;
}

sgx_status_t getacORAM(sgx_enclave_id_t eid, int index, int id, int ac, int lo, int len, int tag)
{
	sgx_status_t status;
	ms_getacORAM_t ms;
	ms.ms_index = index;
	ms.ms_id = id;
	ms.ms_ac = ac;
	ms.ms_lo = lo;
	ms.ms_len = len;
	ms.ms_tag = tag;
	status = sgx_ecall(eid, 6, &ocall_table_ORAM_envalve, &ms);
	return status;
}

sgx_status_t getacPosMap(sgx_enclave_id_t eid, int index, int tag, int type)
{
	sgx_status_t status;
	ms_getacPosMap_t ms;
	ms.ms_index = index;
	ms.ms_tag = tag;
	ms.ms_type = type;
	status = sgx_ecall(eid, 7, &ocall_table_ORAM_envalve, &ms);
	return status;
}

sgx_status_t returnuserdata(sgx_enclave_id_t eid, int index, int sign)
{
	sgx_status_t status;
	ms_returnuserdata_t ms;
	ms.ms_index = index;
	ms.ms_sign = sign;
	status = sgx_ecall(eid, 8, &ocall_table_ORAM_envalve, &ms);
	return status;
}

sgx_status_t createcount(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len)
{
	sgx_status_t status;
	ms_createcount_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	status = sgx_ecall(eid, 9, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t updatecount(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len)
{
	sgx_status_t status;
	ms_updatecount_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	status = sgx_ecall(eid, 10, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t DetectacData(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len, uint8_t* Endata, size_t outlen)
{
	sgx_status_t status;
	ms_DetectacData_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	ms.ms_Endata = Endata;
	ms.ms_outlen = outlen;
	status = sgx_ecall(eid, 11, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t GetServerpublickey(sgx_enclave_id_t eid, int* retval, uint8_t* px, uint8_t* py, size_t len)
{
	sgx_status_t status;
	ms_GetServerpublickey_t ms;
	ms.ms_px = px;
	ms.ms_py = py;
	ms.ms_len = len;
	status = sgx_ecall(eid, 12, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ComputeSharekey(sgx_enclave_id_t eid, int* retval, uint8_t* px, uint8_t* py, size_t len)
{
	sgx_status_t status;
	ms_ComputeSharekey_t ms;
	ms.ms_px = px;
	ms.ms_py = py;
	ms.ms_len = len;
	status = sgx_ecall(eid, 13, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t gettestdata(sgx_enclave_id_t eid, int* retval, uint8_t* data, size_t len)
{
	sgx_status_t status;
	ms_gettestdata_t ms;
	ms.ms_data = data;
	ms.ms_len = len;
	status = sgx_ecall(eid, 14, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Insertskey(sgx_enclave_id_t eid, int* retval, uint8_t* sealkey, size_t len)
{
	sgx_status_t status;
	ms_Insertskey_t ms;
	ms.ms_sealkey = sealkey;
	ms.ms_len = len;
	status = sgx_ecall(eid, 15, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t GetdatatoClient(sgx_enclave_id_t eid, int* retval, int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen)
{
	sgx_status_t status;
	ms_GetdatatoClient_t ms;
	ms.ms_ID = ID;
	ms.ms_data = data;
	ms.ms_len = len;
	ms.ms_Enuserdata = Enuserdata;
	ms.ms_Enlen = Enlen;
	status = sgx_ecall(eid, 16, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Buildsecurepath(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status;
	ms_Buildsecurepath_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ecall(eid, 17, &ocall_table_ORAM_envalve, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

