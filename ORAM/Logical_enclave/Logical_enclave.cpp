#include "Logical_enclave_t.h"

#include "sgx_trts.h"
#include <string>
sgx_key_128bit_t dh_aek;   // Session key
sgx_dh_session_t sgx_dh_session;
uint32_t session_request(sgx_enclave_id_t src_enclave_id, sgx_dh_msg1_t *dh_msg1, uint32_t *session_id)
{


	sgx_status_t status = SGX_SUCCESS;


	//Intialize the session as a session responder
	status = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &sgx_dh_session);
	if (SGX_SUCCESS != status)
	{
		return status;
	}

	//get a new SessionID
	*session_id = 1;

	//Generate Message1 that will be returned to Source Enclave
	status = sgx_dh_responder_gen_msg1((sgx_dh_msg1_t*)dh_msg1, &sgx_dh_session);
	return status;
}
uint32_t exchange_report(sgx_enclave_id_t src_enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, uint32_t session_id)
{
	sgx_dh_session_enclave_identity_t initiator_identity;
	uint32_t rs = 0;
	memset(&dh_aek, 0, sizeof(sgx_key_128bit_t));
	do
	{
		dh_msg3->msg3_body.additional_prop_length = 0;
		//Process message 2 from source enclave and obtain message 3
		sgx_status_t se_ret = sgx_dh_responder_proc_msg2(dh_msg2, dh_msg3, &sgx_dh_session, &dh_aek, &initiator_identity);
		if (SGX_SUCCESS != se_ret)
		{
			rs = -1;
			break;
		}
	} while (0);
	//printint(dh_aek, sizeof(sgx_aes_ctr_128bit_key_t));
	return rs;
}