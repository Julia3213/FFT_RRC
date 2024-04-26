/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_TM_SignallingInfo_H_
#define	_TM_SignallingInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MessType.h"
#include <NULL.h>
#include "UL-ControlledTrChList.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TM_SignallingInfo__tm_SignallingMode_PR {
	TM_SignallingInfo__tm_SignallingMode_PR_NOTHING,	/* No components present */
	TM_SignallingInfo__tm_SignallingMode_PR_mode1,
	TM_SignallingInfo__tm_SignallingMode_PR_mode2
} TM_SignallingInfo__tm_SignallingMode_PR;

/* TM-SignallingInfo */
typedef struct TM_SignallingInfo {
	MessType_t	 messType;
	struct TM_SignallingInfo__tm_SignallingMode {
		TM_SignallingInfo__tm_SignallingMode_PR present;
		union TM_SignallingInfo__tm_SignallingMode_u {
			NULL_t	 mode1;
			struct TM_SignallingInfo__tm_SignallingMode__mode2 {
				UL_ControlledTrChList_t	 ul_controlledTrChList;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} mode2;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tm_SignallingMode;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TM_SignallingInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TM_SignallingInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_TM_SignallingInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_TM_SignallingInfo_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _TM_SignallingInfo_H_ */
#include <asn_internal.h>
