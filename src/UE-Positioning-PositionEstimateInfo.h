/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_PositionEstimateInfo_H_
#define	_UE_Positioning_PositionEstimateInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PositionEstimate.h"
#include "UTRAN-GPSReferenceTimeResult.h"
#include <NativeInteger.h>
#include "PrimaryCPICH-Info.h"
#include <constr_SEQUENCE.h>
#include "CellAndChannelIdentity.h"
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_PositionEstimateInfo__referenceTime_PR {
	UE_Positioning_PositionEstimateInfo__referenceTime_PR_NOTHING,	/* No components present */
	UE_Positioning_PositionEstimateInfo__referenceTime_PR_utran_GPSReferenceTimeResult,
	UE_Positioning_PositionEstimateInfo__referenceTime_PR_gps_ReferenceTimeOnly,
	UE_Positioning_PositionEstimateInfo__referenceTime_PR_cell_Timing
} UE_Positioning_PositionEstimateInfo__referenceTime_PR;
typedef enum UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR {
	UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR_NOTHING,	/* No components present */
	UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR_fdd,
	UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR_tdd
} UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR;

/* UE-Positioning-PositionEstimateInfo */
typedef struct UE_Positioning_PositionEstimateInfo {
	struct UE_Positioning_PositionEstimateInfo__referenceTime {
		UE_Positioning_PositionEstimateInfo__referenceTime_PR present;
		union UE_Positioning_PositionEstimateInfo__referenceTime_u {
			UTRAN_GPSReferenceTimeResult_t	 utran_GPSReferenceTimeResult;
			long	 gps_ReferenceTimeOnly;
			struct UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing {
				long	 sfn;
				struct UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo {
					UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_PR present;
					union UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo_u {
						struct UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo__fdd {
							PrimaryCPICH_Info_t	 primaryCPICH_Info;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} fdd;
						struct UE_Positioning_PositionEstimateInfo__referenceTime__cell_Timing__modeSpecificInfo__tdd {
							CellAndChannelIdentity_t	 cellAndChannelIdentity;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} tdd;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} modeSpecificInfo;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} cell_Timing;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} referenceTime;
	PositionEstimate_t	 positionEstimate;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_PositionEstimateInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_PositionEstimateInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_PositionEstimateInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_PositionEstimateInfo_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_PositionEstimateInfo_H_ */
#include <asn_internal.h>
