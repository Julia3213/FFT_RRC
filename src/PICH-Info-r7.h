/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PICH_Info_r7_H_
#define	_PICH_Info_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ChannelisationCode256.h"
#include "PI-CountPerFrame.h"
#include <BOOLEAN.h>
#include <constr_SEQUENCE.h>
#include "TDD-PICH-CCode.h"
#include "TimeslotNumber.h"
#include "MidambleShiftAndBurstType.h"
#include "PagingIndicatorLength.h"
#include "N-GAP.h"
#include "N-PCH.h"
#include "TDD768-PICH-CCode.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PICH_Info_r7_PR {
	PICH_Info_r7_PR_NOTHING,	/* No components present */
	PICH_Info_r7_PR_fdd,
	PICH_Info_r7_PR_tdd384,
	PICH_Info_r7_PR_tdd768
} PICH_Info_r7_PR;

/* Forward declarations */
struct RepPerLengthOffset_PICH;

/* PICH-Info-r7 */
typedef struct PICH_Info_r7 {
	PICH_Info_r7_PR present;
	union PICH_Info_r7_u {
		struct PICH_Info_r7__fdd {
			ChannelisationCode256_t	 channelisationCode256;
			PI_CountPerFrame_t	 pi_CountPerFrame;
			BOOLEAN_t	 sttd_Indicator;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} fdd;
		struct PICH_Info_r7__tdd384 {
			TDD_PICH_CCode_t	*channelisationCode	/* OPTIONAL */;
			TimeslotNumber_t	*timeslot	/* OPTIONAL */;
			MidambleShiftAndBurstType_t	 midambleShiftAndBurstType;
			struct RepPerLengthOffset_PICH	*repetitionPeriodLengthOffset	/* OPTIONAL */;
			PagingIndicatorLength_t	 pagingIndicatorLength	/* DEFAULT 0 */;
			N_GAP_t	*n_GAP	/* DEFAULT 1 */;
			N_PCH_t	*n_PCH	/* DEFAULT 2 */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} tdd384;
		struct PICH_Info_r7__tdd768 {
			TDD768_PICH_CCode_t	*channelisationCode	/* OPTIONAL */;
			TimeslotNumber_t	*timeslot	/* OPTIONAL */;
			MidambleShiftAndBurstType_t	 midambleShiftAndBurstType;
			struct RepPerLengthOffset_PICH	*repetitionPeriodLengthOffset	/* OPTIONAL */;
			PagingIndicatorLength_t	 pagingIndicatorLength	/* DEFAULT 0 */;
			N_GAP_t	*n_GAP	/* DEFAULT 1 */;
			N_PCH_t	*n_PCH	/* DEFAULT 2 */;
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} tdd768;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PICH_Info_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PICH_Info_r7;
extern asn_CHOICE_specifics_t asn_SPC_PICH_Info_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PICH_Info_r7_1[3];
extern asn_per_constraints_t asn_PER_type_PICH_Info_r7_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _PICH_Info_r7_H_ */
#include <asn_internal.h>