/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PDU-definitions"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_RadioBearerReconfigurationComplete_v7xyext_IEs_H_
#define	_RadioBearerReconfigurationComplete_v7xyext_IEs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct EXT_UL_TimingAdvance;

/* RadioBearerReconfigurationComplete-v7xyext-IEs */
typedef struct RadioBearerReconfigurationComplete_v7xyext_IEs {
	struct EXT_UL_TimingAdvance	*ext_ul_TimingAdvance	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RadioBearerReconfigurationComplete_v7xyext_IEs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RadioBearerReconfigurationComplete_v7xyext_IEs;
extern asn_SEQUENCE_specifics_t asn_SPC_RadioBearerReconfigurationComplete_v7xyext_IEs_specs_1;
extern asn_TYPE_member_t asn_MBR_RadioBearerReconfigurationComplete_v7xyext_IEs_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _RadioBearerReconfigurationComplete_v7xyext_IEs_H_ */
#include <asn_internal.h>
