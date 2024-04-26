/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_MeasurementControlSysInfo_H_
#define	_MeasurementControlSysInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum MeasurementControlSysInfo__use_of_HCS_PR {
	MeasurementControlSysInfo__use_of_HCS_PR_NOTHING,	/* No components present */
	MeasurementControlSysInfo__use_of_HCS_PR_hcs_not_used,
	MeasurementControlSysInfo__use_of_HCS_PR_hcs_used
} MeasurementControlSysInfo__use_of_HCS_PR;
typedef enum MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR {
	MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR_NOTHING,	/* No components present */
	MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR_cpich_RSCP,
	MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR_cpich_Ec_N0
} MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR;
typedef enum MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR {
	MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR_NOTHING,	/* No components present */
	MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR_cpich_RSCP,
	MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR_cpich_Ec_N0
} MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR;

/* Forward declarations */
struct TrafficVolumeMeasSysInfo;
struct UE_InternalMeasurementSysInfo;
struct InterRATMeasurementSysInfo_B;
struct IntraFreqMeasurementSysInfo_RSCP;
struct InterFreqMeasurementSysInfo_RSCP;
struct IntraFreqMeasurementSysInfo_ECN0;
struct InterFreqMeasurementSysInfo_ECN0;
struct InterRATMeasurementSysInfo;
struct IntraFreqMeasurementSysInfo_HCS_RSCP;
struct InterFreqMeasurementSysInfo_HCS_RSCP;
struct IntraFreqMeasurementSysInfo_HCS_ECN0;
struct InterFreqMeasurementSysInfo_HCS_ECN0;

/* MeasurementControlSysInfo */
typedef struct MeasurementControlSysInfo {
	struct MeasurementControlSysInfo__use_of_HCS {
		MeasurementControlSysInfo__use_of_HCS_PR present;
		union MeasurementControlSysInfo__use_of_HCS_u {
			struct MeasurementControlSysInfo__use_of_HCS__hcs_not_used {
				struct MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure {
					MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_PR present;
					union MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure_u {
						struct MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure__cpich_RSCP {
							struct IntraFreqMeasurementSysInfo_RSCP	*intraFreqMeasurementSysInfo	/* OPTIONAL */;
							struct InterFreqMeasurementSysInfo_RSCP	*interFreqMeasurementSysInfo	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} cpich_RSCP;
						struct MeasurementControlSysInfo__use_of_HCS__hcs_not_used__cellSelectQualityMeasure__cpich_Ec_N0 {
							struct IntraFreqMeasurementSysInfo_ECN0	*intraFreqMeasurementSysInfo	/* OPTIONAL */;
							struct InterFreqMeasurementSysInfo_ECN0	*interFreqMeasurementSysInfo	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} cpich_Ec_N0;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} cellSelectQualityMeasure;
				struct InterRATMeasurementSysInfo_B	*interRATMeasurementSysInfo	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} hcs_not_used;
			struct MeasurementControlSysInfo__use_of_HCS__hcs_used {
				struct MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure {
					MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_PR present;
					union MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure_u {
						struct MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure__cpich_RSCP {
							struct IntraFreqMeasurementSysInfo_HCS_RSCP	*intraFreqMeasurementSysInfo	/* OPTIONAL */;
							struct InterFreqMeasurementSysInfo_HCS_RSCP	*interFreqMeasurementSysInfo	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} cpich_RSCP;
						struct MeasurementControlSysInfo__use_of_HCS__hcs_used__cellSelectQualityMeasure__cpich_Ec_N0 {
							struct IntraFreqMeasurementSysInfo_HCS_ECN0	*intraFreqMeasurementSysInfo	/* OPTIONAL */;
							struct InterFreqMeasurementSysInfo_HCS_ECN0	*interFreqMeasurementSysInfo	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} cpich_Ec_N0;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} cellSelectQualityMeasure;
				struct InterRATMeasurementSysInfo	*interRATMeasurementSysInfo	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} hcs_used;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} use_of_HCS;
	struct TrafficVolumeMeasSysInfo	*trafficVolumeMeasSysInfo	/* OPTIONAL */;
	struct UE_InternalMeasurementSysInfo	*dummy	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} MeasurementControlSysInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_MeasurementControlSysInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_MeasurementControlSysInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_MeasurementControlSysInfo_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _MeasurementControlSysInfo_H_ */
#include <asn_internal.h>
