/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_CipheringModeInfo_H_
#define	_CipheringModeInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "CipheringModeCommand.h"
#include "ActivationTime.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RB_ActivationTimeInfoList;

/* CipheringModeInfo */
typedef struct CipheringModeInfo {
	CipheringModeCommand_t	 cipheringModeCommand;
	ActivationTime_t	*activationTimeForDPCH	/* OPTIONAL */;
	struct RB_ActivationTimeInfoList	*rb_DL_CiphActivationTimeInfo	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CipheringModeInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CipheringModeInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_CipheringModeInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_CipheringModeInfo_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _CipheringModeInfo_H_ */
#include <asn_internal.h>
