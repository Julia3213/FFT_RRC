/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasuredResults_LCR_r4_H_
#define	_MeasuredResults_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "IntraFreqMeasuredResultsList.h"
#include "InterFreqMeasuredResultsList.h"
#include "InterRATMeasuredResultsList.h"
#include "TrafficVolumeMeasuredResultsList.h"
#include "QualityMeasuredResults.h"
#include "UE-InternalMeasuredResults-LCR-r4.h"
#include "UE-Positioning-MeasuredResults.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasuredResults_LCR_r4_PR {
	MeasuredResults_LCR_r4_PR_NOTHING,	/* No components present */
	MeasuredResults_LCR_r4_PR_intraFreqMeasuredResultsList,
	MeasuredResults_LCR_r4_PR_interFreqMeasuredResultsList,
	MeasuredResults_LCR_r4_PR_interRATMeasuredResultsList,
	MeasuredResults_LCR_r4_PR_trafficVolumeMeasuredResultsList,
	MeasuredResults_LCR_r4_PR_qualityMeasuredResults,
	MeasuredResults_LCR_r4_PR_ue_InternalMeasuredResults,
	MeasuredResults_LCR_r4_PR_ue_positioniing_MeasuredResults,
	MeasuredResults_LCR_r4_PR_spare
} MeasuredResults_LCR_r4_PR;

/* MeasuredResults-LCR-r4 */
typedef struct MeasuredResults_LCR_r4 {
	MeasuredResults_LCR_r4_PR present;
	union MeasuredResults_LCR_r4_u {
		IntraFreqMeasuredResultsList_t	 intraFreqMeasuredResultsList;
		InterFreqMeasuredResultsList_t	 interFreqMeasuredResultsList;
		InterRATMeasuredResultsList_t	 interRATMeasuredResultsList;
		TrafficVolumeMeasuredResultsList_t	 trafficVolumeMeasuredResultsList;
		QualityMeasuredResults_t	 qualityMeasuredResults;
		UE_InternalMeasuredResults_LCR_r4_t	 ue_InternalMeasuredResults;
		UE_Positioning_MeasuredResults_t	 ue_positioniing_MeasuredResults;
		NULL_t	 spare;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasuredResults_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasuredResults_LCR_r4;
extern asn_CHOICE_specifics_t asn_SPC_MeasuredResults_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasuredResults_LCR_r4_1[8];
extern asn_per_constraints_t asn_PER_type_MeasuredResults_LCR_r4_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _MeasuredResults_LCR_r4_H_ */
#include <asn_internal.h>