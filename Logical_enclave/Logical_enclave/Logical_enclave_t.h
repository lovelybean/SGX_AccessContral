#ifndef LOGICAL_ENCLAVE_T_H__
#define LOGICAL_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "sgx_dh.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


uint32_t session_request(sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
uint32_t exchange_report(sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
uint32_t Encryptuserfile(uint8_t* file, size_t len, uint8_t* Entemfile, size_t outlen);
uint32_t GetdatatoClient(int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen);
uint32_t Deblocking(int tdataid);
uint32_t WritebackdatatoDisk();

sgx_status_t SGX_CDECL Encryptusershuju(int* retval, int dataid, uint8_t* usershuju, size_t len);
sgx_status_t SGX_CDECL disp(uint8_t* pbuf, size_t len);
sgx_status_t SGX_CDECL Updatefileindisk(int* retval, int dataid, uint8_t* file, size_t len);
sgx_status_t SGX_CDECL TransferRequestToL(uint32_t* retval, uint8_t* request, size_t len, uint8_t* Response, size_t Reslen);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
