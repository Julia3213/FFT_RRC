/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_HandoverFromUTRANCommand_GSM_r3_IEs_H_
#define	_HandoverFromUTRANCommand_GSM_r3_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "ActivationTime.h"
#include "Frequency-Band.h"
#include <constr_SEQUENCE.h>
#include "GSM-MessageList.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR {
	HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR_NOTHING,	/* No components present */
	HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR_single_GSM_Message,
	HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR_gsm_MessageList
} HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR;

/* Forward declarations */
struct RAB_Info;

/* HandoverFromUTRANCommand-GSM-r3-IEs */
typedef struct HandoverFromUTRANCommand_GSM_r3_IEs {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	ActivationTime_t	*activationTime	/* OPTIONAL */;
	struct RAB_Info	*toHandoverRAB_Info	/* OPTIONAL */;
	Frequency_Band_t	 frequency_band;
	struct HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message {
		HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_PR present;
		union HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message_u {
			struct HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message__single_GSM_Message {
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} single_GSM_Message;
			struct HandoverFromUTRANCommand_GSM_r3_IEs__gsm_message__gsm_MessageList {
				GSM_MessageList_t	 gsm_Messages;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} gsm_MessageList;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} gsm_message;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HandoverFromUTRANCommand_GSM_r3_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HandoverFromUTRANCommand_GSM_r3_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_HandoverFromUTRANCommand_GSM_r3_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_HandoverFromUTRANCommand_GSM_r3_IEs_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _HandoverFromUTRANCommand_GSM_r3_IEs_H_ */
#include <asn_internal.h>
