#ifndef ORAM_ENVALVE_T_H__
#define ORAM_ENVALVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "AccessRight.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void SaveasBlock(char* buf, int index, size_t len);
void getBlock();
void InitORAM();
int getuserdata(int pattern, int index, int userid, enum accesstype userac);
void setbackdata();
void Transferid(char* data, int index, size_t len);
void getacORAM(int index, int id, int ac, int lo, int len, int tag);
void getacPosMap(int index, int tag, int type);
void returnuserdata(int index, int sign);
uint32_t createcount(uint8_t* data, size_t len);
uint32_t updatecount(uint8_t* data, size_t len);
uint32_t DetectacData(uint8_t* data, size_t len, uint8_t* Endata, size_t outlen);
int GetServerpublickey(uint8_t* px, uint8_t* py, size_t len);
int ComputeSharekey(uint8_t* px, uint8_t* py, size_t len);
int gettestdata(uint8_t* data, size_t len);
int Insertskey(uint8_t* sealkey, size_t len);
int GetdatatoClient(int ID, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t Enlen);
uint32_t Buildsecurepath(sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id);

sgx_status_t SGX_CDECL printblock(char* data);
sgx_status_t SGX_CDECL printint(int i);
sgx_status_t SGX_CDECL getrandnum(int* retval, int num);
sgx_status_t SGX_CDECL acValidity(int* retval, int index, int userid, enum accesstype userac);
sgx_status_t SGX_CDECL transferstash(char* data, int index, size_t len);
sgx_status_t SGX_CDECL SerializeORAM(char* data, int i, int index, int tag, size_t len);
sgx_status_t SGX_CDECL StorePosMap(int pos, int tag, int type);
sgx_status_t SGX_CDECL Transferacbucket(int len, int index, int tag);
sgx_status_t SGX_CDECL GetVcount(uint8_t* data, size_t len);
sgx_status_t SGX_CDECL Getdatalen(size_t* retval, int ID);
sgx_status_t SGX_CDECL Getuserdatafromdisk(int ID, uint8_t* userdata, size_t len);
sgx_status_t SGX_CDECL UpdateshujutoServerdisk(int* retval, int ID, uint8_t* data, size_t len);
sgx_status_t SGX_CDECL session_request_lo(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id);
sgx_status_t SGX_CDECL exchange_report_lo(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id);
sgx_status_t SGX_CDECL printhash(uint8_t* dhash, size_t len);
sgx_status_t SGX_CDECL disp(uint8_t* pbuf, size_t len);
sgx_status_t SGX_CDECL Getuserfilefromenclave2(uint32_t* retval, sgx_enclave_id_t dest_enclave_id, uint8_t* data, size_t len, uint8_t* Enuserdata, size_t len2);
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
