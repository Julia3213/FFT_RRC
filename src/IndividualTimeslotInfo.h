/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IndividualTimeslotInfo_H_
#define	_IndividualTimeslotInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TimeslotNumber.h"
#include <BOOLEAN.h>
#include "MidambleShiftAndBurstType.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* IndividualTimeslotInfo */
typedef struct IndividualTimeslotInfo {
	TimeslotNumber_t	 timeslotNumber;
	BOOLEAN_t	 tfci_Existence;
	MidambleShiftAndBurstType_t	 midambleShiftAndBurstType;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IndividualTimeslotInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IndividualTimeslotInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_IndividualTimeslotInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_IndividualTimeslotInfo_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _IndividualTimeslotInfo_H_ */
#include <asn_internal.h>
