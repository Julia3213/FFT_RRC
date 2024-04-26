/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UE_Positioning_GPS_MeasurementResults_H_
#define	_UE_Positioning_GPS_MeasurementResults_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GPS-MeasurementParamList.h"
#include "UTRAN-GPSReferenceTimeResult.h"
#include <NativeInteger.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UE_Positioning_GPS_MeasurementResults__referenceTime_PR {
	UE_Positioning_GPS_MeasurementResults__referenceTime_PR_NOTHING,	/* No components present */
	UE_Positioning_GPS_MeasurementResults__referenceTime_PR_utran_GPSReferenceTimeResult,
	UE_Positioning_GPS_MeasurementResults__referenceTime_PR_gps_ReferenceTimeOnly
} UE_Positioning_GPS_MeasurementResults__referenceTime_PR;

/* UE-Positioning-GPS-MeasurementResults */
typedef struct UE_Positioning_GPS_MeasurementResults {
	struct UE_Positioning_GPS_MeasurementResults__referenceTime {
		UE_Positioning_GPS_MeasurementResults__referenceTime_PR present;
		union UE_Positioning_GPS_MeasurementResults__referenceTime_u {
			UTRAN_GPSReferenceTimeResult_t	 utran_GPSReferenceTimeResult;
			long	 gps_ReferenceTimeOnly;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} referenceTime;
	GPS_MeasurementParamList_t	 gps_MeasurementParamList;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UE_Positioning_GPS_MeasurementResults_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UE_Positioning_GPS_MeasurementResults;
extern asn_SEQUENCE_specifics_t asn_SPC_UE_Positioning_GPS_MeasurementResults_specs_1;
extern asn_TYPE_member_t asn_MBR_UE_Positioning_GPS_MeasurementResults_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UE_Positioning_GPS_MeasurementResults_H_ */
#include <asn_internal.h>