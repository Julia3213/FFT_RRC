/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "InformationElements"
 * 	found in "rrcstr.asn1"
 * 	`asn1c -D src -fcompound-names -fno-include-deps`
 */

#include "UE-RadioAccessCapabilityComp2.h"

static asn_TYPE_member_t asn_MBR_fddPhysicalChannelCapab_hspdsch_edch_2[] = {
	{ ATF_POINTER, 1, offsetof(struct UE_RadioAccessCapabilityComp2__fddPhysicalChannelCapab_hspdsch_edch, dl_CapabilityWithSimultaneousHS_DSCHConfig),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DL_CapabilityWithSimultaneousHS_DSCHConfig,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dl-CapabilityWithSimultaneousHS-DSCHConfig"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_RadioAccessCapabilityComp2__fddPhysicalChannelCapab_hspdsch_edch, physicalChannelCapabComp_hspdsch_r6),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HSDSCH_physical_layer_category,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"physicalChannelCapabComp-hspdsch-r6"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct UE_RadioAccessCapabilityComp2__fddPhysicalChannelCapab_hspdsch_edch, physicalChannelCapability_edch_r6),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PhysicalChannelCapability_edch_r6,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"physicalChannelCapability-edch-r6"
		},
};
static const int asn_MAP_fddPhysicalChannelCapab_hspdsch_edch_oms_2[] = { 0 };
static const ber_tlv_tag_t asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2[] = {
	(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_fddPhysicalChannelCapab_hspdsch_edch_tag2el_2[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dl-CapabilityWithSimultaneousHS-DSCHConfig */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* physicalChannelCapabComp-hspdsch-r6 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* physicalChannelCapability-edch-r6 */
};
static asn_SEQUENCE_specifics_t asn_SPC_fddPhysicalChannelCapab_hspdsch_edch_specs_2 = {
	sizeof(struct UE_RadioAccessCapabilityComp2__fddPhysicalChannelCapab_hspdsch_edch),
	offsetof(struct UE_RadioAccessCapabilityComp2__fddPhysicalChannelCapab_hspdsch_edch, _asn_ctx),
	asn_MAP_fddPhysicalChannelCapab_hspdsch_edch_tag2el_2,
	3,	/* Count of tags in the map */
	asn_MAP_fddPhysicalChannelCapab_hspdsch_edch_oms_2,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_2 = {
	"fddPhysicalChannelCapab-hspdsch-edch",
	"fddPhysicalChannelCapab-hspdsch-edch",
	&asn_OP_SEQUENCE,
	asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2,
	sizeof(asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2)
		/sizeof(asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2[0]) - 1, /* 1 */
	asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2,	/* Same as above */
	sizeof(asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2)
		/sizeof(asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_tags_2[0]), /* 2 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_fddPhysicalChannelCapab_hspdsch_edch_2,
	3,	/* Elements count */
	&asn_SPC_fddPhysicalChannelCapab_hspdsch_edch_specs_2	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_UE_RadioAccessCapabilityComp2_1[] = {
	{ ATF_POINTER, 1, offsetof(struct UE_RadioAccessCapabilityComp2, fddPhysicalChannelCapab_hspdsch_edch),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		0,
		&asn_DEF_fddPhysicalChannelCapab_hspdsch_edch_2,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"fddPhysicalChannelCapab-hspdsch-edch"
		},
};
static const int asn_MAP_UE_RadioAccessCapabilityComp2_oms_1[] = { 0 };
static const ber_tlv_tag_t asn_DEF_UE_RadioAccessCapabilityComp2_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_UE_RadioAccessCapabilityComp2_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* fddPhysicalChannelCapab-hspdsch-edch */
};
asn_SEQUENCE_specifics_t asn_SPC_UE_RadioAccessCapabilityComp2_specs_1 = {
	sizeof(struct UE_RadioAccessCapabilityComp2),
	offsetof(struct UE_RadioAccessCapabilityComp2, _asn_ctx),
	asn_MAP_UE_RadioAccessCapabilityComp2_tag2el_1,
	1,	/* Count of tags in the map */
	asn_MAP_UE_RadioAccessCapabilityComp2_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_UE_RadioAccessCapabilityComp2 = {
	"UE-RadioAccessCapabilityComp2",
	"UE-RadioAccessCapabilityComp2",
	&asn_OP_SEQUENCE,
	asn_DEF_UE_RadioAccessCapabilityComp2_tags_1,
	sizeof(asn_DEF_UE_RadioAccessCapabilityComp2_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapabilityComp2_tags_1[0]), /* 1 */
	asn_DEF_UE_RadioAccessCapabilityComp2_tags_1,	/* Same as above */
	sizeof(asn_DEF_UE_RadioAccessCapabilityComp2_tags_1)
		/sizeof(asn_DEF_UE_RadioAccessCapabilityComp2_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_UE_RadioAccessCapabilityComp2_1,
	1,	/* Elements count */
	&asn_SPC_UE_RadioAccessCapabilityComp2_specs_1	/* Additional specs */
};

