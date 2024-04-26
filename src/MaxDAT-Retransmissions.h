/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MaxDAT_Retransmissions_H_
#define	_MaxDAT_Retransmissions_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MaxDAT.h"
#include "TimerMRW.h"
#include "MaxMRW.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MaxDAT-Retransmissions */
typedef struct MaxDAT_Retransmissions {
	MaxDAT_t	 maxDAT;
	TimerMRW_t	 timerMRW;
	MaxMRW_t	 maxMRW;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MaxDAT_Retransmissions_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MaxDAT_Retransmissions;
extern asn_SEQUENCE_specifics_t asn_SPC_MaxDAT_Retransmissions_specs_1;
extern asn_TYPE_member_t asn_MBR_MaxDAT_Retransmissions_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _MaxDAT_Retransmissions_H_ */
#include <asn_internal.h>