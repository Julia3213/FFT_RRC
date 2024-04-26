/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_UL_CCTrCH_r7_H_
#define	_UL_CCTrCH_r7_H_


#include <asn_application.h>

/* Including external dependencies */
#include "TFCS-IdentityPlain.h"
#include "UL-TargetSIR.h"
#include "TimeInfo.h"
#include <constr_SEQUENCE.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum UL_CCTrCH_r7__tddOption_PR {
	UL_CCTrCH_r7__tddOption_PR_NOTHING,	/* No components present */
	UL_CCTrCH_r7__tddOption_PR_tdd384,
	UL_CCTrCH_r7__tddOption_PR_tdd768,
	UL_CCTrCH_r7__tddOption_PR_tdd128
} UL_CCTrCH_r7__tddOption_PR;

/* Forward declarations */
struct CommonTimeslotInfo;
struct UplinkTimeslotsCodes;
struct UplinkTimeslotsCodes_VHCR;
struct UplinkTimeslotsCodes_LCR_r7;

/* UL-CCTrCH-r7 */
typedef struct UL_CCTrCH_r7 {
	TFCS_IdentityPlain_t	*tfcs_ID	/* DEFAULT 1 */;
	UL_TargetSIR_t	 ul_TargetSIR;
	TimeInfo_t	 timeInfo;
	struct CommonTimeslotInfo	*commonTimeslotInfo	/* OPTIONAL */;
	struct UL_CCTrCH_r7__tddOption {
		UL_CCTrCH_r7__tddOption_PR present;
		union UL_CCTrCH_r7__tddOption_u {
			struct UL_CCTrCH_r7__tddOption__tdd384 {
				struct UplinkTimeslotsCodes	*ul_CCTrCH_TimeslotsCodes	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd384;
			struct UL_CCTrCH_r7__tddOption__tdd768 {
				struct UplinkTimeslotsCodes_VHCR	*ul_CCTrCH_TimeslotsCodes	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd768;
			struct UL_CCTrCH_r7__tddOption__tdd128 {
				struct UplinkTimeslotsCodes_LCR_r7	*ul_CCTrCH_TimeslotsCodes	/* OPTIONAL */;
				
				/* Context for parsing across buffer boundaries */
				asn_struct_ctx_t _asn_ctx;
			} tdd128;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} tddOption;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UL_CCTrCH_r7_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UL_CCTrCH_r7;
extern asn_SEQUENCE_specifics_t asn_SPC_UL_CCTrCH_r7_specs_1;
extern asn_TYPE_member_t asn_MBR_UL_CCTrCH_r7_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _UL_CCTrCH_r7_H_ */
#include <asn_internal.h>
