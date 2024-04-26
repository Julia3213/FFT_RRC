/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UCSM_Info_H_
#define	_UCSM_Info_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MinimumSpreadingFactor.h"
#include "NF-Max.h"
#include "ChannelReqParamsForUCSM.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* UCSM-Info */
typedef struct UCSM_Info {
	MinimumSpreadingFactor_t	 minimumSpreadingFactor;
	NF_Max_t	 nf_Max;
	ChannelReqParamsForUCSM_t	 channelReqParamsForUCSM;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UCSM_Info_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UCSM_Info;
extern asn_SEQUENCE_specifics_t asn_SPC_UCSM_Info_specs_1;
extern asn_TYPE_member_t asn_MBR_UCSM_Info_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _UCSM_Info_H_ */
#include <asn_internal.h>