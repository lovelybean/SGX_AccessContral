#ifndef ORAM_ENVALVE_U_H__
#define ORAM_ENVALVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "AccessRight.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, printblock, (char* data));
void SGX_UBRIDGE(SGX_NOCONVENTION, printint, (int i));
int SGX_UBRIDGE(SGX_NOCONVENTION, getrandnum, (int num));
int SGX_UBRIDGE(SGX_NOCONVENTION, acValidity, (int index, int userid, enum accesstype userac));
void SGX_UBRIDGE(SGX_NOCONVENTION, transferstash, (char* data, int index, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, SerializeORAM, (char* data, int i, int index, int tag, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, StorePosMap, (int pos, int tag, int type));
void SGX_UBRIDGE(SGX_NOCONVENTION, Transferacbucket, (int len, int index, int tag));
void SGX_UBRIDGE(SGX_NOCONVENTION, GetVcount, (uint8_t* data, size_t len));
size_t SGX_UBRIDGE(SGX_NOCONVENTION, Getdatalen, (int ID));
void SGX_UBRIDGE(SGX_NOCONVENTION, Getuserdatafromdisk, (int ID, uint8_t* userdata, size_t len));
int SGX_UBRIDGE(SGX_NOCONVENTION, UpdateshujutoServerdisk, (int ID, uint8_t* data, size_t len));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, session_request_lo, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_lo, (sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id));
void SGX_UBRIDGE(SGX_NOCONVENTION, printhash, (uint8_t* dhash, size_t len));
void SGX_UBRIDGE(SGX_NOCONVENTION, disp, (uint8_t* pbuf, size_t len));
uint32_t SGX_UBRIDGE(SGX_NOCONVENTION, Getuserfilefromenclave2, (sgx_enclave_id_t dest_enclave_id, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t len2));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, create_session_ocall, (uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, exchange_report_ocall, (uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, close_session_ocall, (uint32_t sid, uint32_t timeout));
sgx_status_t SGX_UBRIDGE(SGX_NOCONVENTION, invoke_service_ocall, (uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout));
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));

sgx_status_t SaveasBlock(sgx_enclave_id_t eid, char* buf, int index, size_t len);
sgx_status_t getBlock(sgx_enclave_id_t eid);
sgx_status_t InitORAM(sgx_enclave_id_t eid);
sgx_status_t getuserdata(sgx_enclave_id_t eid, int* retval, int pattern, int index, int userid, enum accesstype userac);
sgx_status_t setbackdata(sgx_enclave_id_t eid);
sgx_status_t Transferid(sgx_enclave_id_t eid, char* data, int index, size_t len);
sgx_status_t getacORAM(sgx_enclave_id_t eid, int index, int id, int ac, int lo, int len, int tag);
sgx_status_t getacPosMap(sgx_enclave_id_t eid, int index, int tag, int type);
sgx_status_t returnuserdata(sgx_enclave_id_t eid, int index, int sign);
sgx_status_t createcount(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len);
sgx_status_t updatecount(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len);
sgx_status_t DetectacData(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* data, size_t len, uint8_t* Endata, size_t outlen);
sgx_status_t GetServerpublickey(sgx_enclave_id_t eid, int* retval, uint8_t* px, uint8_t* py, size_t len);
sgx_status_t ComputeSharekey(sgx_enclave_id_t eid, int* retval, uint8_t* px, uint8_t* py, size_t len);
sgx_status_t gettestdata(sgx_enclave_id_t eid, int* retval, uint8_t* data, size_t len);
sgx_status_t Insertskey(sgx_enclave_id_t eid, int* retval, uint8_t* sealkey, size_t len);
sgx_status_t GetdatatoClient(sgx_enclave_id_t eid, int* retval, int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen);
sgx_status_t Buildsecurepath(sgx_enclave_id_t eid, uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
