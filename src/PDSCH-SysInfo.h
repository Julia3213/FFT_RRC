/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#ifndef	_PDSCH_SysInfo_H_
#define	_PDSCH_SysInfo_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDSCH-Identity.h"
#include "PDSCH-Info.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TransportFormatSet;
struct TFCS;

/* PDSCH-SysInfo */
typedef struct PDSCH_SysInfo {
	PDSCH_Identity_t	 pdsch_Identity;
	PDSCH_Info_t	 pdsch_Info;
	struct TransportFormatSet	*dsch_TFS	/* OPTIONAL */;
	struct TFCS	*dsch_TFCS	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDSCH_SysInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDSCH_SysInfo;
extern asn_SEQUENCE_specifics_t asn_SPC_PDSCH_SysInfo_specs_1;
extern asn_TYPE_member_t asn_MBR_PDSCH_SysInfo_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _PDSCH_SysInfo_H_ */
#include <asn_internal.h>
