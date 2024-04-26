/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_DPCH_Info_r7_H_
#define	_UL_DPCH_Info_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "ScramblingCodeType.h"
#include "UL-ScramblingCode.h"
#include "NumberOfDPDCH.h"
#include "SpreadingFactor.h"
#include <BOOLEAN.h>
#include "NumberOfFBI-Bits.h"
#include "PuncturingLimit.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_DPCH_Info_r7__modeSpecificInfo_PR {
	UL_DPCH_Info_r7__modeSpecificInfo_PR_NOTHING,	/* No components present */
	UL_DPCH_Info_r7__modeSpecificInfo_PR_fdd,
	UL_DPCH_Info_r7__modeSpecificInfo_PR_tdd
} UL_DPCH_Info_r7__modeSpecificInfo_PR;
typedef enum UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR {
	UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR_NOTHING,	/* No components present */
	UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR_present,
	UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR_notPresent
} UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR;

/* Forward declarations */
struct UL_DPCH_PowerControlInfo_r6;
struct UL_TimingAdvanceControl_r7;
struct UL_CCTrCHList_r7;
struct UL_CCTrCHListToRemove;

/* UL-DPCH-Info-r7 */
typedef struct UL_DPCH_Info_r7 {
	struct UL_DPCH_PowerControlInfo_r6	*ul_DPCH_PowerControlInfo	/* OPTIONAL */;
	struct UL_DPCH_Info_r7__modeSpecificInfo {
		UL_DPCH_Info_r7__modeSpecificInfo_PR present;
		union UL_DPCH_Info_r7__modeSpecificInfo_u {
			struct UL_DPCH_Info_r7__modeSpecificInfo__fdd {
				ScramblingCodeType_t	 scramblingCodeType;
				UL_ScramblingCode_t	 scramblingCode;
				struct UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence {
					UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_PR present;
					union UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence_u {
						struct UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence__present {
							NumberOfDPDCH_t	*numberOfDPDCH	/* DEFAULT 1 */;
							SpreadingFactor_t	 spreadingFactor;
							BOOLEAN_t	 tfci_Existence;
							NumberOfFBI_Bits_t	*numberOfFBI_Bits	/* OPTIONAL */;
							PuncturingLimit_t	 puncturingLimit;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} present;
						struct UL_DPCH_Info_r7__modeSpecificInfo__fdd__dpdchPresence__notPresent {
							BOOLEAN_t	 tfci_Existence;
							NumberOfFBI_Bits_t	*numberOfFBI_Bits	/* OPTIONAL */;
							
							/* Context for parsing across buffer boundaries */
							asn_struct_ctx_t _asn_ctx;
						} notPresent;
					} choice;
					
					/* Context for parsing across buffer boundaries */
					asn_struct_ctx_t _asn_ctx;
				} dpdchPresence;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} fdd;
			struct UL_DPCH_Info_r7__modeSpecificInfo__tdd {
				struct UL_TimingAdvanceControl_r7	*ul_TimingAdvance	/* OPTIONAL */;
				struct UL_CCTrCHList_r7	*ul_CCTrCHList	/* OPTIONAL */;
				struct UL_CCTrCHListToRemove	*ul_CCTrCHListToRemove	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} modeSpecificInfo;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_DPCH_Info_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_DPCH_Info_r7;
extern asn_SEQUENCE_specifics_t asn_SPC_UL_DPCH_Info_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_DPCH_Info_r7_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _UL_DPCH_Info_r7_H_ */
#include <asn_internal.h>
