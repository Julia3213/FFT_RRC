/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "Rb-timer-indicator.h"

asn_TYPE_member_t asn_MBR_Rb_timer_indicator_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Rb_timer_indicator, t314_expired),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t314-expired"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Rb_timer_indicator, t315_expired),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BOOLEAN,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"t315-expired"
		},
};
static const ber_tlv_tag_t asn_DEF_Rb_timer_indicator_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Rb_timer_indicator_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* t314-expired */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* t315-expired */
};
asn_SEQUENCE_specifics_t asn_SPC_Rb_timer_indicator_specs_1 = {
	sizeof(struct Rb_timer_indicator),
	offsetof(struct Rb_timer_indicator, _asn_ctx),
	asn_MAP_Rb_timer_indicator_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Rb_timer_indicator = {
	"Rb-timer-indicator",
	"Rb-timer-indicator",
	&asn_OP_SEQUENCE,
	asn_DEF_Rb_timer_indicator_tags_1,
	sizeof(asn_DEF_Rb_timer_indicator_tags_1)
		/sizeof(asn_DEF_Rb_timer_indicator_tags_1[0]), /* 1 */
	asn_DEF_Rb_timer_indicator_tags_1,	/* Same as above */
	sizeof(asn_DEF_Rb_timer_indicator_tags_1)
		/sizeof(asn_DEF_Rb_timer_indicator_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Rb_timer_indicator_1,
	2,	/* Elements count */
	&asn_SPC_Rb_timer_indicator_specs_1	/* Additional specs */
};
