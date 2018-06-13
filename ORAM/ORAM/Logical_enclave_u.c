#include "Logical_enclave_u.h"
#include <errno.h>

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_Encryptuserfile_t {
	uint32_t ms_retval;
	uint8_t* ms_file;
	size_t ms_len;
	uint8_t* ms_Entemfile;
	size_t ms_outlen;
} ms_Encryptuserfile_t;

typedef struct ms_GetdatatoClient_t {
	uint32_t ms_retval;
	int ms_ID;
	uint8_t* ms_data;
	size_t ms_len;
	uint8_t* ms_Enuserdata;
	size_t ms_Enlen;
} ms_GetdatatoClient_t;

typedef struct ms_Deblocking_t {
	uint32_t ms_retval;
	int ms_tdataid;
} ms_Deblocking_t;

typedef struct ms_WritebackdatatoDisk_t {
	uint32_t ms_retval;
} ms_WritebackdatatoDisk_t;

typedef struct ms_Encryptusershuju_t {
	int ms_retval;
	int ms_dataid;
	uint8_t* ms_usershuju;
	size_t ms_len;
} ms_Encryptusershuju_t;

typedef struct ms_disp_t {
	uint8_t* ms_pbuf;
	size_t ms_len;
} ms_disp_t;

typedef struct ms_Updatefileindisk_t {
	int ms_retval;
	int ms_dataid;
	uint8_t* ms_file;
	size_t ms_len;
} ms_Updatefileindisk_t;

typedef struct ms_TransferRequestToL_t {
	uint32_t ms_retval;
	uint8_t* ms_request;
	size_t ms_len;
	uint8_t* ms_Response;
	size_t ms_Reslen;
} ms_TransferRequestToL_t;

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

static sgx_status_t SGX_CDECL Logical_enclave_Encryptusershuju(void* pms)
{
	ms_Encryptusershuju_t* ms = SGX_CAST(ms_Encryptusershuju_t*, pms);
	ms->ms_retval = Encryptusershuju(ms->ms_dataid, ms->ms_usershuju, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_disp(void* pms)
{
	ms_disp_t* ms = SGX_CAST(ms_disp_t*, pms);
	disp(ms->ms_pbuf, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_Updatefileindisk(void* pms)
{
	ms_Updatefileindisk_t* ms = SGX_CAST(ms_Updatefileindisk_t*, pms);
	ms->ms_retval = Updatefileindisk(ms->ms_dataid, ms->ms_file, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_TransferRequestToL(void* pms)
{
	ms_TransferRequestToL_t* ms = SGX_CAST(ms_TransferRequestToL_t*, pms);
	ms->ms_retval = TransferRequestToL(ms->ms_request, ms->ms_len, ms->ms_Response, ms->ms_Reslen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_create_session_ocall(void* pms)
{
	ms_create_session_ocall_t* ms = SGX_CAST(ms_create_session_ocall_t*, pms);
	ms->ms_retval = create_session_ocall(ms->ms_sid, ms->ms_dh_msg1, ms->ms_dh_msg1_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_exchange_report_ocall(void* pms)
{
	ms_exchange_report_ocall_t* ms = SGX_CAST(ms_exchange_report_ocall_t*, pms);
	ms->ms_retval = exchange_report_ocall(ms->ms_sid, ms->ms_dh_msg2, ms->ms_dh_msg2_size, ms->ms_dh_msg3, ms->ms_dh_msg3_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_close_session_ocall(void* pms)
{
	ms_close_session_ocall_t* ms = SGX_CAST(ms_close_session_ocall_t*, pms);
	ms->ms_retval = close_session_ocall(ms->ms_sid, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_invoke_service_ocall(void* pms)
{
	ms_invoke_service_ocall_t* ms = SGX_CAST(ms_invoke_service_ocall_t*, pms);
	ms->ms_retval = invoke_service_ocall(ms->ms_pse_message_req, ms->ms_pse_message_req_size, ms->ms_pse_message_resp, ms->ms_pse_message_resp_size, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall((const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall((const void*)ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall((const void*)ms->ms_waiter, (const void*)ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Logical_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall((const void**)ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[13];
} ocall_table_Logical_enclave = {
	13,
	{
		(void*)(uintptr_t)Logical_enclave_Encryptusershuju,
		(void*)(uintptr_t)Logical_enclave_disp,
		(void*)(uintptr_t)Logical_enclave_Updatefileindisk,
		(void*)(uintptr_t)Logical_enclave_TransferRequestToL,
		(void*)(uintptr_t)Logical_enclave_create_session_ocall,
		(void*)(uintptr_t)Logical_enclave_exchange_report_ocall,
		(void*)(uintptr_t)Logical_enclave_close_session_ocall,
		(void*)(uintptr_t)Logical_enclave_invoke_service_ocall,
		(void*)(uintptr_t)Logical_enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Logical_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Logical_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Logical_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Logical_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t session_request(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status;
	ms_session_request_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 0, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t exchange_report(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status;
	ms_exchange_report_t ms;
	ms.ms_src_enclave_id = src_enclave_id;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_session_id = session_id;
	status = sgx_ecall(eid, 1, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Encryptuserfile(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* file, size_t len, uint8_t* Entemfile, size_t outlen)
{
	sgx_status_t status;
	ms_Encryptuserfile_t ms;
	ms.ms_file = file;
	ms.ms_len = len;
	ms.ms_Entemfile = Entemfile;
	ms.ms_outlen = outlen;
	status = sgx_ecall(eid, 2, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t GetdatatoClient(sgx_enclave_id_t eid, uint32_t* retval, int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen)
{
	sgx_status_t status;
	ms_GetdatatoClient_t ms;
	ms.ms_ID = ID;
	ms.ms_data = data;
	ms.ms_len = len;
	ms.ms_Enuserdata = Enuserdata;
	ms.ms_Enlen = Enlen;
	status = sgx_ecall(eid, 3, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Deblocking(sgx_enclave_id_t eid, uint32_t* retval, int tdataid)
{
	sgx_status_t status;
	ms_Deblocking_t ms;
	ms.ms_tdataid = tdataid;
	status = sgx_ecall(eid, 4, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t WritebackdatatoDisk(sgx_enclave_id_t eid, uint32_t* retval)
{
	sgx_status_t status;
	ms_WritebackdatatoDisk_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Logical_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

