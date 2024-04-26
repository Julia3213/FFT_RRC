/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_H_
#define	_IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "MaxReportedCellsOnRACH.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntraFreqCellInfoSI_List_HCS_ECN0_LCR_r4;
struct IntraFreqMeasQuantity;
struct IntraFreqReportingQuantityForRACH;
struct ReportingInfoForCellDCH_LCR_r4;

/* IntraFreqMeasurementSysInfo-HCS-ECN0-LCR-r4 */
typedef struct IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4 {
	MeasurementIdentity_t	*intraFreqMeasurementID	/* DEFAULT 1 */;
	struct IntraFreqCellInfoSI_List_HCS_ECN0_LCR_r4	*intraFreqCellInfoSI_List	/* OPTIONAL */;
	struct IntraFreqMeasQuantity	*intraFreqMeasQuantity	/* OPTIONAL */;
	struct IntraFreqReportingQuantityForRACH	*intraFreqReportingQuantityForRACH	/* OPTIONAL */;
	MaxReportedCellsOnRACH_t	*maxReportedCellsOnRACH	/* OPTIONAL */;
	struct ReportingInfoForCellDCH_LCR_r4	*reportingInfoForCellDCH	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4;
extern asn_SEQUENCE_specifics_t asn_SPC_IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_specs_1;
extern asn_TYPE_member_t asn_MBR_IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_1[6];

#ifdef __cplusplus
}
#endif

#endif	/* _IntraFreqMeasurementSysInfo_HCS_ECN0_LCR_r4_H_ */
#include <asn_internal.h>
