/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "SysInfoType5bis.h"

/*
 * This type is implemented using SysInfoType5,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_SysInfoType5bis_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SysInfoType5bis = {
	"SysInfoType5bis",
	"SysInfoType5bis",
	&asn_OP_SEQUENCE,
	asn_DEF_SysInfoType5bis_tags_1,
	sizeof(asn_DEF_SysInfoType5bis_tags_1)
		/sizeof(asn_DEF_SysInfoType5bis_tags_1[0]), /* 1 */
	asn_DEF_SysInfoType5bis_tags_1,	/* Same as above */
	sizeof(asn_DEF_SysInfoType5bis_tags_1)
		/sizeof(asn_DEF_SysInfoType5bis_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_SysInfoType5_1,
	8,	/* Elements count */
	&asn_SPC_SysInfoType5_specs_1	/* Additional specs */
};

