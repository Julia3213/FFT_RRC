/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_LosslessSRNS_RelocSupport_H_
#define	_LosslessSRNS_RelocSupport_H_


#include <asn_application.h>

/* Including external dependencies */
#include "MaxPDCP-SN-WindowSize.h"
#include <NULL.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LosslessSRNS_RelocSupport_PR {
	LosslessSRNS_RelocSupport_PR_NOTHING,	/* No components present */
	LosslessSRNS_RelocSupport_PR_supported,
	LosslessSRNS_RelocSupport_PR_notSupported
} LosslessSRNS_RelocSupport_PR;

/* LosslessSRNS-RelocSupport */
typedef struct LosslessSRNS_RelocSupport {
	LosslessSRNS_RelocSupport_PR present;
	union LosslessSRNS_RelocSupport_u {
		MaxPDCP_SN_WindowSize_t	 supported;
		NULL_t	 notSupported;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LosslessSRNS_RelocSupport_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LosslessSRNS_RelocSupport;
extern asn_CHOICE_specifics_t asn_SPC_LosslessSRNS_RelocSupport_specs_1;
extern asn_TYPE_member_t asn_MBR_LosslessSRNS_RelocSupport_1[2];
extern asn_per_constraints_t asn_PER_type_LosslessSRNS_RelocSupport_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _LosslessSRNS_RelocSupport_H_ */
#include <asn_internal.h>
