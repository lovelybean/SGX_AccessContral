#include "Logical_enclave_t.h"

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

typedef struct ms_FindfileTOuser_t {
	uint32_t ms_retval;
	uint8_t* ms_data;
	size_t ms_len;
	uint8_t* ms_Enuserdata;
	size_t ms_len2;
} ms_FindfileTOuser_t;

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

static sgx_status_t SGX_CDECL sgx_session_request(void* pms)
{
	ms_session_request_t* ms = SGX_CAST(ms_session_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg1_t* _tmp_dh_msg1 = ms->ms_dh_msg1;
	size_t _len_dh_msg1 = sizeof(*_tmp_dh_msg1);
	sgx_dh_msg1_t* _in_dh_msg1 = NULL;
	uint32_t* _tmp_session_id = ms->ms_session_id;
	size_t _len_session_id = sizeof(*_tmp_session_id);
	uint32_t* _in_session_id = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_session_request_t));
	CHECK_UNIQUE_POINTER(_tmp_dh_msg1, _len_dh_msg1);
	CHECK_UNIQUE_POINTER(_tmp_session_id, _len_session_id);

	if (_tmp_dh_msg1 != NULL) {
		if ((_in_dh_msg1 = (sgx_dh_msg1_t*)malloc(_len_dh_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg1, 0, _len_dh_msg1);
	}
	if (_tmp_session_id != NULL) {
		if ((_in_session_id = (uint32_t*)malloc(_len_session_id)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_session_id, 0, _len_session_id);
	}
	ms->ms_retval = session_request(ms->ms_src_enclave_id, _in_dh_msg1, _in_session_id);
err:
	if (_in_dh_msg1) {
		memcpy(_tmp_dh_msg1, _in_dh_msg1, _len_dh_msg1);
		free(_in_dh_msg1);
	}
	if (_in_session_id) {
		memcpy(_tmp_session_id, _in_session_id, _len_session_id);
		free(_in_session_id);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_exchange_report(void* pms)
{
	ms_exchange_report_t* ms = SGX_CAST(ms_exchange_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg2_t* _tmp_dh_msg2 = ms->ms_dh_msg2;
	size_t _len_dh_msg2 = sizeof(*_tmp_dh_msg2);
	sgx_dh_msg2_t* _in_dh_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_dh_msg3 = ms->ms_dh_msg3;
	size_t _len_dh_msg3 = sizeof(*_tmp_dh_msg3);
	sgx_dh_msg3_t* _in_dh_msg3 = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_exchange_report_t));
	CHECK_UNIQUE_POINTER(_tmp_dh_msg2, _len_dh_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg3, _len_dh_msg3);

	if (_tmp_dh_msg2 != NULL) {
		_in_dh_msg2 = (sgx_dh_msg2_t*)malloc(_len_dh_msg2);
		if (_in_dh_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_dh_msg2, _tmp_dh_msg2, _len_dh_msg2);
	}
	if (_tmp_dh_msg3 != NULL) {
		if ((_in_dh_msg3 = (sgx_dh_msg3_t*)malloc(_len_dh_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg3, 0, _len_dh_msg3);
	}
	ms->ms_retval = exchange_report(ms->ms_src_enclave_id, _in_dh_msg2, _in_dh_msg3, ms->ms_session_id);
err:
	if (_in_dh_msg2) free(_in_dh_msg2);
	if (_in_dh_msg3) {
		memcpy(_tmp_dh_msg3, _in_dh_msg3, _len_dh_msg3);
		free(_in_dh_msg3);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_FindfileTOuser(void* pms)
{
	ms_FindfileTOuser_t* ms = SGX_CAST(ms_FindfileTOuser_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_data = ms->ms_data;
	size_t _tmp_len = ms->ms_len;
	size_t _len_data = _tmp_len;
	uint8_t* _in_data = NULL;
	uint8_t* _tmp_Enuserdata = ms->ms_Enuserdata;
	size_t _tmp_len2 = ms->ms_len2;
	size_t _len_Enuserdata = _tmp_len2;
	uint8_t* _in_Enuserdata = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_FindfileTOuser_t));
	CHECK_UNIQUE_POINTER(_tmp_data, _len_data);
	CHECK_UNIQUE_POINTER(_tmp_Enuserdata, _len_Enuserdata);

	if (_tmp_data != NULL) {
		_in_data = (uint8_t*)malloc(_len_data);
		if (_in_data == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_data, _tmp_data, _len_data);
	}
	if (_tmp_Enuserdata != NULL) {
		if ((_in_Enuserdata = (uint8_t*)malloc(_len_Enuserdata)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_Enuserdata, 0, _len_Enuserdata);
	}
	ms->ms_retval = FindfileTOuser(_in_data, _tmp_len, _in_Enuserdata, _tmp_len2);
err:
	if (_in_data) free(_in_data);
	if (_in_Enuserdata) {
		memcpy(_tmp_Enuserdata, _in_Enuserdata, _len_Enuserdata);
		free(_in_Enuserdata);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_session_request, 0},
		{(void*)(uintptr_t)sgx_exchange_report, 0},
		{(void*)(uintptr_t)sgx_FindfileTOuser, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][3];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL Encryptusershuju(int* retval, int dataid, uint8_t* usershuju, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_usershuju = len;

	ms_Encryptusershuju_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_Encryptusershuju_t);
	void *__tmp = NULL;

	ocalloc_size += (usershuju != NULL && sgx_is_within_enclave(usershuju, _len_usershuju)) ? _len_usershuju : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_Encryptusershuju_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_Encryptusershuju_t));

	ms->ms_dataid = dataid;
	if (usershuju != NULL && sgx_is_within_enclave(usershuju, _len_usershuju)) {
		ms->ms_usershuju = (uint8_t*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_usershuju);
		memset(ms->ms_usershuju, 0, _len_usershuju);
	} else if (usershuju == NULL) {
		ms->ms_usershuju = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;
	if (usershuju) memcpy((void*)usershuju, ms->ms_usershuju, _len_usershuju);

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
	status = sgx_ocall(1, ms);


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
	status = sgx_ocall(2, ms);

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
	status = sgx_ocall(3, ms);

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
	status = sgx_ocall(4, ms);

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
	status = sgx_ocall(5, ms);

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
	status = sgx_ocall(6, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
