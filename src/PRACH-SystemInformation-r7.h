/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PRACH_SystemInformation_r7_H_
#define	_PRACH_SystemInformation_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PRACH-RACH-Info-r7.h"
#include "TransportChannelIdentity.h"
#include <NULL.h>
#include "PrimaryCPICH-TX-Power.h"
#include "ConstantValue.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PRACH_SystemInformation_r7__modeSpecificInfo_PR {
	PRACH_SystemInformation_r7__modeSpecificInfo_PR_NOTHING,	/* No components present */
	PRACH_SystemInformation_r7__modeSpecificInfo_PR_fdd,
	PRACH_SystemInformation_r7__modeSpecificInfo_PR_tdd
} PRACH_SystemInformation_r7__modeSpecificInfo_PR;

/* Forward declarations */
struct TransportFormatSet;
struct TFCS;
struct PRACH_Partitioning_r7;
struct PersistenceScalingFactorList;
struct AC_To_ASC_MappingTable;
struct PRACH_PowerOffset;
struct RACH_TransmissionParameters;
struct AICH_Info;

/* PRACH-SystemInformation-r7 */
typedef struct PRACH_SystemInformation_r7 {
	PRACH_RACH_Info_r7_t	 prach_RACH_Info;
	TransportChannelIdentity_t	 transportChannelIdentity;
	struct TransportFormatSet	*rach_TransportFormatSet	/* OPTIONAL */;
	struct TFCS	*rach_TFCS	/* OPTIONAL */;
	struct PRACH_Partitioning_r7	*prach_Partitioning	/* OPTIONAL */;
	struct PersistenceScalingFactorList	*persistenceScalingFactorList	/* OPTIONAL */;
	struct AC_To_ASC_MappingTable	*ac_To_ASC_MappingTable	/* OPTIONAL */;
	struct PRACH_SystemInformation_r7__modeSpecificInfo {
		PRACH_SystemInformation_r7__modeSpecificInfo_PR present;
		union PRACH_SystemInformation_r7__modeSpecificInfo_u {
			struct PRACH_SystemInformation_r7__modeSpecificInfo__fdd {
				PrimaryCPICH_TX_Power_t	*primaryCPICH_TX_Power	/* OPTIONAL */;
				ConstantValue_t	*constantValue	/* OPTIONAL */;
				struct PRACH_PowerOffset	*prach_PowerOffset	/* OPTIONAL */;
				struct RACH_TransmissionParameters	*rach_TransmissionParameters	/* OPTIONAL */;
				struct AICH_Info	*aich_Info	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			NULL_t	 tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PRACH_SystemInformation_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PRACH_SystemInformation_r7;
extern asn_SEQUENCE_specifics_t asn_SPC_PRACH_SystemInformation_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_PRACH_SystemInformation_r7_1[8];

#ifdef __cplusplus
}
#endif

#endif	/* _PRACH_SystemInformation_r7_H_ */
#include <asn_internal.h>