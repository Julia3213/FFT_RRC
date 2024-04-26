/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IdentificationOfReceivedMessage_H_
#define	_IdentificationOfReceivedMessage_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RRC-TransactionIdentifier.h"
#include "ReceivedMessageType.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IdentificationOfReceivedMessage */
typedef struct IdentificationOfReceivedMessage {
	RRC_TransactionIdentifier_t	 rrc_TransactionIdentifier;
	ReceivedMessageType_t	 receivedMessageType;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IdentificationOfReceivedMessage_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IdentificationOfReceivedMessage;
extern asn_SEQUENCE_specifics_t asn_SPC_IdentificationOfReceivedMessage_specs_1;
extern asn_TYPE_member_t asn_MBR_IdentificationOfReceivedMessage_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _IdentificationOfReceivedMessage_H_ */
#include <asn_internal.h>