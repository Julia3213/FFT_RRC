/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_IntraFreqMeasurementSysInfo_HCS_RSCP_H_
#define	_IntraFreqMeasurementSysInfo_HCS_RSCP_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MeasurementIdentity.h"
#include "MaxReportedCellsOnRACH.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct IntraFreqCellInfoSI_List_HCS_RSCP;
struct IntraFreqMeasQuantity;
struct IntraFreqReportingQuantityForRACH;
struct ReportingInfoForCellDCH;

/* IntraFreqMeasurementSysInfo-HCS-RSCP */
typedef struct IntraFreqMeasurementSysInfo_HCS_RSCP {
	MeasurementIdentity_t	*intraFreqMeasurementID	/* DEFAULT 1 */;
	struct IntraFreqCellInfoSI_List_HCS_RSCP	*intraFreqCellInfoSI_List	/* OPTIONAL */;
	struct IntraFreqMeasQuantity	*intraFreqMeasQuantity	/* OPTIONAL */;
	struct IntraFreqReportingQuantityForRACH	*intraFreqReportingQuantityForRACH	/* OPTIONAL */;
	MaxReportedCellsOnRACH_t	*maxReportedCellsOnRACH	/* OPTIONAL */;
	struct ReportingInfoForCellDCH	*reportingInfoForCellDCH	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} IntraFreqMeasurementSysInfo_HCS_RSCP_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_IntraFreqMeasurementSysInfo_HCS_RSCP;
extern asn_SEQUENCE_specifics_t asn_SPC_IntraFreqMeasurementSysInfo_HCS_RSCP_specs_1;
extern asn_TYPE_member_t asn_MBR_IntraFreqMeasurementSysInfo_HCS_RSCP_1[6];

#ifdef __cplusplus
}
#endif

#endif	/* _IntraFreqMeasurementSysInfo_HCS_RSCP_H_ */
#include <asn_internal.h>
