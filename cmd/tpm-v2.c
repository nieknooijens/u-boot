// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2018 Bootlin
 * Author: Miquel Raynal <miquel.raynal@bootlin.com>
 */

#include <common.h>
#include <command.h>
#include <dm.h>
#include <log.h>
#include <mapmem.h>
#include <tpm-common.h>
#include <tpm-v2.h>
#include "tpm-user-utils.h"

static int do_tpm2_startup(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[])
{
	enum tpm2_startup_types mode;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc != 2)
		return CMD_RET_USAGE;

	if (!strcasecmp("TPM2_SU_CLEAR", argv[1])) {
		mode = TPM2_SU_CLEAR;
	} else if (!strcasecmp("TPM2_SU_STATE", argv[1])) {
		mode = TPM2_SU_STATE;
	} else {
		printf("Couldn't recognize mode string: %s\n", argv[1]);
		return CMD_RET_FAILURE;
	}

	return report_return_code(tpm2_startup(dev, mode));
}

static int do_tpm2_self_test(struct cmd_tbl *cmdtp, int flag, int argc,
			     char *const argv[])
{
	enum tpm2_yes_no full_test;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc != 2)
		return CMD_RET_USAGE;

	if (!strcasecmp("full", argv[1])) {
		full_test = TPMI_YES;
	} else if (!strcasecmp("continue", argv[1])) {
		full_test = TPMI_NO;
	} else {
		printf("Couldn't recognize test mode: %s\n", argv[1]);
		return CMD_RET_FAILURE;
	}

	return report_return_code(tpm2_self_test(dev, full_test));
}

static int do_tpm2_clear(struct cmd_tbl *cmdtp, int flag, int argc,
			 char *const argv[])
{
	u32 handle = 0;
	const char *pw = (argc < 3) ? NULL : argv[2];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 2 || argc > 3)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1]))
		handle = TPM2_RH_LOCKOUT;
	else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1]))
		handle = TPM2_RH_PLATFORM;
	else
		return CMD_RET_USAGE;

	return report_return_code(tpm2_clear(dev, handle, pw, pw_sz));
}

static int do_tpm2_pcr_extend(struct cmd_tbl *cmdtp, int flag, int argc,
			      char *const argv[])
{
	struct udevice *dev;
	struct tpm_chip_priv *priv;
	u32 index = simple_strtoul(argv[1], NULL, 0);
	void *digest = map_sysmem(simple_strtoul(argv[2], NULL, 0), 0);
	int ret;
	u32 rc;

	if (argc != 3)
		return CMD_RET_USAGE;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	priv = dev_get_uclass_priv(dev);
	if (!priv)
		return -EINVAL;

	if (index >= priv->pcr_count)
		return -EINVAL;

	rc = tpm2_pcr_extend(dev, index, TPM2_ALG_SHA256, digest,
			     TPM2_DIGEST_LEN);

	unmap_sysmem(digest);

	return report_return_code(rc);
}

static int do_tpm_pcr_read(struct cmd_tbl *cmdtp, int flag, int argc,
			   char *const argv[])
{
	struct udevice *dev;
	struct tpm_chip_priv *priv;
	u32 index, rc;
	unsigned int updates;
	void *data;
	int ret;

	if (argc != 3)
		return CMD_RET_USAGE;
	ret = get_tpm(&dev);
	if (ret)
		return ret;
	priv = dev_get_uclass_priv(dev);
	if (!priv)
		return -EINVAL;
	index = simple_strtoul(argv[1], NULL, 0);
	if (index >= priv->pcr_count)
		return -EINVAL;

	data = map_sysmem(simple_strtoul(argv[2], NULL, 0), 0);

	rc = tpm2_pcr_read(dev, index, priv->pcr_select_min, TPM2_ALG_SHA256,
			   data, TPM2_DIGEST_LEN, &updates);
	if (!rc) {
		printf("PCR #%u content (%u known updates):\n", index, updates);
		print_byte_string(data, TPM2_DIGEST_LEN);
	}

	unmap_sysmem(data);

	return report_return_code(rc);
}

static int do_tpm_get_capability(struct cmd_tbl *cmdtp, int flag, int argc,
				 char *const argv[])
{
	u32 capability, property, rc;
	u8 *data;
	size_t count;
	int i, j;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc != 5)
		return CMD_RET_USAGE;

	capability = simple_strtoul(argv[1], NULL, 0);
	property = simple_strtoul(argv[2], NULL, 0);
	data = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);
	count = simple_strtoul(argv[4], NULL, 0);

	rc = tpm2_get_capability(dev, capability, property, data, count);
	if (rc)
		goto unmap_data;

	printf("Capabilities read from TPM:\n");
	for (i = 0; i < count; i++) {
		printf("Property 0x");
		for (j = 0; j < 4; j++)
			printf("%02x", data[(i * 8) + j + sizeof(u32)]);
		printf(": 0x");
		for (j = 4; j < 8; j++)
			printf("%02x", data[(i * 8) + j + sizeof(u32)]);
		printf("\n");
	}

unmap_data:
	unmap_sysmem(data);

	return report_return_code(rc);
}

static int do_tpm_dam_reset(struct cmd_tbl *cmdtp, int flag, int argc,
			    char *const argv[])
{
	const char *pw = (argc < 2) ? NULL : argv[1];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc > 2)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	return report_return_code(tpm2_dam_reset(dev, pw, pw_sz));
}

static int do_tpm_dam_parameters(struct cmd_tbl *cmdtp, int flag, int argc,
				 char *const argv[])
{
	const char *pw = (argc < 5) ? NULL : argv[4];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	/*
	 * No Dictionary Attack Mitigation (DAM) means:
	 * maxtries = 0xFFFFFFFF, recovery_time = 1, lockout_recovery = 0
	 */
	unsigned long int max_tries;
	unsigned long int recovery_time;
	unsigned long int lockout_recovery;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 4 || argc > 5)
		return CMD_RET_USAGE;

	if (pw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (strict_strtoul(argv[1], 0, &max_tries))
		return CMD_RET_USAGE;

	if (strict_strtoul(argv[2], 0, &recovery_time))
		return CMD_RET_USAGE;

	if (strict_strtoul(argv[3], 0, &lockout_recovery))
		return CMD_RET_USAGE;

	log(LOGC_NONE, LOGL_INFO, "Changing dictionary attack parameters:\n");
	log(LOGC_NONE, LOGL_INFO, "- maxTries: %lu", max_tries);
	log(LOGC_NONE, LOGL_INFO, "- recoveryTime: %lu\n", recovery_time);
	log(LOGC_NONE, LOGL_INFO, "- lockoutRecovery: %lu\n", lockout_recovery);

	return report_return_code(tpm2_dam_parameters(dev, pw, pw_sz, max_tries,
						      recovery_time,
						      lockout_recovery));
}

static int do_tpm_change_auth(struct cmd_tbl *cmdtp, int flag, int argc,
			      char *const argv[])
{
	u32 handle;
	const char *newpw = argv[2];
	const char *oldpw = (argc == 3) ? NULL : argv[3];
	const ssize_t newpw_sz = strlen(newpw);
	const ssize_t oldpw_sz = oldpw ? strlen(oldpw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	if (newpw_sz > TPM2_DIGEST_LEN || oldpw_sz > TPM2_DIGEST_LEN)
		return -EINVAL;

	if (!strcasecmp("TPM2_RH_LOCKOUT", argv[1]))
		handle = TPM2_RH_LOCKOUT;
	else if (!strcasecmp("TPM2_RH_ENDORSEMENT", argv[1]))
		handle = TPM2_RH_ENDORSEMENT;
	else if (!strcasecmp("TPM2_RH_OWNER", argv[1]))
		handle = TPM2_RH_OWNER;
	else if (!strcasecmp("TPM2_RH_PLATFORM", argv[1]))
		handle = TPM2_RH_PLATFORM;
	else
		return CMD_RET_USAGE;

	return report_return_code(tpm2_change_auth(dev, handle, newpw, newpw_sz,
						   oldpw, oldpw_sz));
}

static int do_tpm_pcr_setauthpolicy(struct cmd_tbl *cmdtp, int flag, int argc,
				    char *const argv[])
{
	u32 index = simple_strtoul(argv[1], NULL, 0);
	char *key = argv[2];
	const char *pw = (argc < 4) ? NULL : argv[3];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (strlen(key) != TPM2_DIGEST_LEN)
		return -EINVAL;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	return report_return_code(tpm2_pcr_setauthpolicy(dev, pw, pw_sz, index,
							 key));
}

static int do_tpm_pcr_setauthvalue(struct cmd_tbl *cmdtp, int flag,
				   int argc, char *const argv[])
{
	u32 index = simple_strtoul(argv[1], NULL, 0);
	char *key = argv[2];
	const ssize_t key_sz = strlen(key);
	const char *pw = (argc < 4) ? NULL : argv[3];
	const ssize_t pw_sz = pw ? strlen(pw) : 0;
	struct udevice *dev;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	if (strlen(key) != TPM2_DIGEST_LEN)
		return -EINVAL;

	if (argc < 3 || argc > 4)
		return CMD_RET_USAGE;

	return report_return_code(tpm2_pcr_setauthvalue(dev, pw, pw_sz, index,
							key, key_sz));
}

static int do_tpm_nv_define(struct cmd_tbl *cmdtp, int flag,
			int argc, char *const argv[])
{
	struct udevice *dev;
	struct tpm_chip_priv *priv;
	u32 nv_addr, nv_size, rc;
	void *policy_addr = NULL;
	size_t policy_size = 0;
	int ret;

	u32 nv_attributes = TPMA_NV_PLATFORMCREATE | TPMA_NV_OWNERWRITE |\
			TPMA_NV_OWNERREAD | TPMA_NV_PPWRITE | TPMA_NV_PPREAD;

	if (argc < 3 && argc > 7)
		return CMD_RET_USAGE;

	ret = get_tpm(&dev);
	if (ret)
		return ret;

	priv = dev_get_uclass_priv(dev);
	if (!priv)
		return -EINVAL;

	nv_addr = simple_strtoul(argv[1], NULL, 0);
	nv_size = simple_strtoul(argv[2], NULL, 0);
	if (argc > 3)
		nv_attributes = simple_strtoul(argv[3], NULL, 0);
	if (argc > 4) {
		policy_addr = map_sysmem(simple_strtoul(argv[4], NULL, 0), 0);
		//POLICYREAD and POLICYWRITE are obligated when providing policy, so just force it
		nv_attributes |= (TPMA_NV_POLICYREAD | TPMA_NV_POLICYWRITE);
		if (argc < 5)
			return CMD_RET_USAGE;
		policy_size = simple_strtoul(argv[5], NULL, 0);
	}

	rc = tpm2_nv_define_space(dev, nv_addr, nv_size, nv_attributes, policy_addr, policy_size);
	if (rc)
		printf("ERROR: nv_define #%u returns: 0x%x\n", nv_addr, rc);

	unmap_sysmem(policy_addr);

	return report_return_code(rc);
}

static int do_tpm_nv_undefine(struct cmd_tbl *cmdtp, int flag,
				int argc, char *const argv[])
{
	struct udevice *dev;
	u32 nv_addr, ret, rc;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc != 2)
		return CMD_RET_USAGE;

	nv_addr = simple_strtoul(argv[1], NULL, 0);
	rc = tpm2_nv_undefine_space(dev, nv_addr);

	return report_return_code(rc);
}

static int do_tpm_nv_read_value(struct cmd_tbl *cmdtp, int flag,
				int argc, char *const argv[])
{
	struct udevice *dev;
	u32 nv_addr, nv_size, rc;
	void *session_addr = NULL;
	int ret;
	void *out_data;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc < 4)
		return CMD_RET_USAGE;

	nv_addr = simple_strtoul(argv[1], NULL, 0);
	nv_size = simple_strtoul(argv[2], NULL, 0);
	out_data = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);
	if (argc == 5)
		session_addr = map_sysmem(simple_strtoul(argv[4], NULL, 0), 0);
	//if session handle is NULL, Password authorization is used
	rc = tpm2_nv_read_value(dev, nv_addr, out_data, nv_size, session_addr);

	if (rc)
		printf("ERROR: nv_read #%u returns: #%u\n", nv_addr, rc);

	unmap_sysmem(out_data);
	return report_return_code(rc);
}

static int do_tpm_nv_write_value(struct cmd_tbl *cmdtp, int flag,
				int argc, char *const argv[])
{
	struct udevice *dev;
	u32 nv_addr, nv_size, rc;
	void *session_addr = NULL, *data_to_write = NULL;
	int ret;

	ret = get_tpm(&dev);
	if (ret)
		return ret;
	if (argc < 4)
		return CMD_RET_USAGE;

	nv_addr = simple_strtoul(argv[1], NULL, 0); //tpm_addr
	nv_size = simple_strtoul(argv[2], NULL, 0); //size
	data_to_write = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);

	if (argc == 5)
		session_addr = map_sysmem(simple_strtoul(argv[4], NULL, 0), 0);

	rc = tpm2_nv_write_value(dev, nv_addr, data_to_write, nv_size, session_addr);
	if (rc)
		printf("ERROR: nv_write #%u returns: #%u\n", nv_addr, rc);

	unmap_sysmem(session_addr);
	unmap_sysmem(data_to_write);
	return report_return_code(rc);
}

static int do_start_auth_session(struct cmd_tbl *cmdtp, int flag,
int argc, char *const argv[])
{
	struct udevice *dev;
	u32 rc;
	u8 session_type = TPM_SE_POLICY;
	int ret;
	void *data_to_write;

	ret = get_tpm(&dev);
	if (argc < 2)
		return CMD_RET_USAGE;

	data_to_write = map_sysmem(simple_strtoul(argv[1], NULL, 0), 0);
	if (argc > 2)
		session_type = simple_strtoul(argv[2], NULL, 0);

	rc = tpm2_start_auth_session(dev, data_to_write, session_type);
	if (rc)
		printf("ERROR: start_auth_session returns: #%u\n", rc);

	unmap_sysmem(data_to_write);
	return report_return_code(rc);
}

static int do_flush_context(struct cmd_tbl *cmdtp, int flag,
				int argc, char *const argv[])
{
	struct udevice *dev;
	u32 rc;
	int ret;
	void *data_to_read;

	ret = get_tpm(&dev);

	if (argc < 2)
		return CMD_RET_USAGE;

	data_to_read = map_sysmem(simple_strtoul(argv[1], NULL, 0), 0);
	u32 session_handle = *((u32 *)data_to_read);

	rc = tpm2_flush_context(dev, session_handle);

	if (rc)
		printf("ERROR: flush_context returns: #%u\n", rc);

	unmap_sysmem(data_to_read);
	return report_return_code(rc);
}

static int do_policy_pcr(struct cmd_tbl *cmdtp, int flag,
			int argc, char *const argv[])
{
	struct udevice *dev;
	u32 rc, pcr, session_handle;
	int ret;
	void *data_to_read, *out_digest;

	ret = get_tpm(&dev);

	if (argc != 4)
		return CMD_RET_USAGE;

	data_to_read = map_sysmem(simple_strtoul(argv[1], NULL, 0), 0);
	session_handle = *((u32 *)data_to_read);
	pcr = simple_strtoul(argv[2], NULL, 0);
	out_digest = map_sysmem(simple_strtoul(argv[3], NULL, 0), 0);
	rc = tpm2_set_policy_pcr(dev, session_handle, pcr, out_digest);

	if (rc)
		printf("ERROR: policy_pcr returns: #%u\n", rc);

	unmap_sysmem(data_to_read);
	unmap_sysmem(out_digest);
	return report_return_code(rc);
}

static struct cmd_tbl tpm2_commands[] = {
	U_BOOT_CMD_MKENT(device, 0, 1, do_tpm_device, "", ""),
	U_BOOT_CMD_MKENT(info, 0, 1, do_tpm_info, "", ""),
	U_BOOT_CMD_MKENT(state, 0, 1, do_tpm_report_state, "", ""),
	U_BOOT_CMD_MKENT(init, 0, 1, do_tpm_init, "", ""),
	U_BOOT_CMD_MKENT(startup, 0, 1, do_tpm2_startup, "", ""),
	U_BOOT_CMD_MKENT(self_test, 0, 1, do_tpm2_self_test, "", ""),
	U_BOOT_CMD_MKENT(clear, 0, 1, do_tpm2_clear, "", ""),
	U_BOOT_CMD_MKENT(pcr_extend, 0, 1, do_tpm2_pcr_extend, "", ""),
	U_BOOT_CMD_MKENT(pcr_read, 0, 1, do_tpm_pcr_read, "", ""),
	U_BOOT_CMD_MKENT(get_capability, 0, 1, do_tpm_get_capability, "", ""),
	U_BOOT_CMD_MKENT(dam_reset, 0, 1, do_tpm_dam_reset, "", ""),
	U_BOOT_CMD_MKENT(dam_parameters, 0, 1, do_tpm_dam_parameters, "", ""),
	U_BOOT_CMD_MKENT(change_auth, 0, 1, do_tpm_change_auth, "", ""),
	U_BOOT_CMD_MKENT(autostart, 0, 1, do_tpm_autostart, "", ""),
	U_BOOT_CMD_MKENT(pcr_setauthpolicy, 0, 1,
			 do_tpm_pcr_setauthpolicy, "", ""),
	U_BOOT_CMD_MKENT(pcr_setauthvalue, 0, 1,
			 do_tpm_pcr_setauthvalue, "", ""),
	U_BOOT_CMD_MKENT(nv_define, 0, 1, do_tpm_nv_define, "", ""),
	U_BOOT_CMD_MKENT(nv_undefine, 0, 1, do_tpm_nv_undefine, "", ""),
	U_BOOT_CMD_MKENT(nv_read, 0, 1, do_tpm_nv_read_value, "", ""),
	U_BOOT_CMD_MKENT(nv_write, 0, 1, do_tpm_nv_write_value, "", ""),
	U_BOOT_CMD_MKENT(start_auth_session, 0, 1, do_start_auth_session, "", ""),
	U_BOOT_CMD_MKENT(flush_context, 0, 1, do_flush_context, "", ""),
	U_BOOT_CMD_MKENT(policy_pcr, 0, 1, do_policy_pcr, "", ""),
};

struct cmd_tbl *get_tpm2_commands(unsigned int *size)
{
	*size = ARRAY_SIZE(tpm2_commands);

	return tpm2_commands;
}

U_BOOT_CMD(tpm2, CONFIG_SYS_MAXARGS, 1, do_tpm, "Issue a TPMv2.x command",
"<command> [<arguments>]\n"
"\n"
"device [num device]\n"
"    Show all devices or set the specified device\n"
"info\n"
"    Show information about the TPM.\n"
"state\n"
"    Show internal state from the TPM (if available)\n"
"autostart\n"
"    Initalize the tpm, perform a Startup(clear) and run a full selftest\n"
"    sequence\n"
"init\n"
"    Initialize the software stack. Always the first command to issue.\n"
"    'tpm startup' is the only acceptable command after a 'tpm init' has been\n"
"    issued\n"
"startup <mode>\n"
"    Issue a TPM2_Startup command.\n"
"    <mode> is one of:\n"
"        * TPM2_SU_CLEAR (reset state)\n"
"        * TPM2_SU_STATE (preserved state)\n"
"self_test <type>\n"
"    Test the TPM capabilities.\n"
"    <type> is one of:\n"
"        * full (perform all tests)\n"
"        * continue (only check untested tests)\n"
"clear <hierarchy>\n"
"    Issue a TPM2_Clear command.\n"
"    <hierarchy> is one of:\n"
"        * TPM2_RH_LOCKOUT\n"
"        * TPM2_RH_PLATFORM\n"
"pcr_extend <pcr> <digest_addr>\n"
"    Extend PCR #<pcr> with digest at <digest_addr>.\n"
"    <pcr>: index of the PCR\n"
"    <digest_addr>: address of a 32-byte SHA256 digest\n"
"pcr_read <pcr> <digest_addr>\n"
"    Read PCR #<pcr> to memory address <digest_addr>.\n"
"    <pcr>: index of the PCR\n"
"    <digest_addr>: address to store the a 32-byte SHA256 digest\n"
"get_capability <capability> <property> <addr> <count>\n"
"    Read and display <count> entries indexed by <capability>/<property>.\n"
"    Values are 4 bytes long and are written at <addr>.\n"
"    <capability>: capability\n"
"    <property>: property\n"
"    <addr>: address to store <count> entries of 4 bytes\n"
"    <count>: number of entries to retrieve\n"
"dam_reset [<password>]\n"
"    If the TPM is not in a LOCKOUT state, reset the internal error counter.\n"
"    <password>: optional password\n"
"dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]\n"
"    If the TPM is not in a LOCKOUT state, set the DAM parameters\n"
"    <maxTries>: maximum number of failures before lockout,\n"
"                0 means always locking\n"
"    <recoveryTime>: time before decrement of the error counter,\n"
"                    0 means no lockout\n"
"    <lockoutRecovery>: time of a lockout (before the next try),\n"
"                       0 means a reboot is needed\n"
"    <password>: optional password of the LOCKOUT hierarchy\n"
"change_auth <hierarchy> <new_pw> [<old_pw>]\n"
"    <hierarchy>: the hierarchy\n"
"    <new_pw>: new password for <hierarchy>\n"
"    <old_pw>: optional previous password of <hierarchy>\n"
"pcr_setauthpolicy|pcr_setauthvalue <pcr> <key> [<password>]\n"
"    Change the <key> to access PCR #<pcr>.\n"
"    hierarchy and may be empty.\n"
"    /!\\WARNING: untested function, use at your own risks !\n"
"    <pcr>: index of the PCR\n"
"    <key>: secret to protect the access of PCR #<pcr>\n"
"    <password>: optional password of the PLATFORM hierarchy\n"
"\n"
"nv_define <tpm_addr> <size> [<attributes> <policy_digest_addr> <policy_size>]\n"
"    Define new nv index in the TPM at <tpm_addr> with size <size>\n"
"    <tpm_addr>: the internal address used within the TPM for the NV-index\n"
"    <attributes>: is described in tpm-v2.h enum tpm_index_attrs. Note; Always use TPMA_NV_PLATFORMCREATE!\n"
"                  will default to: TPMA_NV_PLATFORMCREATE|TPMA_NV_OWNERWRITE|TPMA_NV_OWNERREAD|TPMA_NV_PPWRITE|TPMA_NV_PPREAD\n"
"    <policy_digest_addr>: address to a policy digest. (e.g. a PCR value)\n"
"    <policy_size>: size of the digest in bytes\n"
"nv_undefine <tpm_addr>\n"
"	delete nv index\n"
"nv_read <tpm_addr> <size> <data_addr> [<session_handle_addr>]\n"
"    Read data stored in TPM nv_memory at <tpm_addr> with size <size>\n"
"    <tpm_addr>: the internal address used within the TPM for the NV-index\n"
"    <size>: datasize in bytes\n"
"    <data_addr>: memory address where to store the data read from the TPM\n"
"    <session_handle_addr>: addr where the session handle is stored\n"
"nv_write <tpm_addr> <size> <data_addr> [<session_handle_addr>]\n"
"    Write data to the TPM's nv_memory at <tpm_addr> with size <size>\n"
"    <tpm_addr>: the internal address used within the TPM for the NV-index\n"
"    <size>: datasize in bytes\n"
"    <data_addr>: memory address of the data to be written to the TPM's NV-index\n"
"    <session_handle_addr>: addr where the session handle is stored\n"
"start_auth_session <session_handle_addr> [<session_type>]\n"
"    Start an authorization session and store it's handle at <session_handle_addr>\n"
"	 <session_handle_addr>: addr where to store the handle data (4 bytes)\n"
"	 <session_type>: type of session: 0x00 for HMAC, 0x01 for policy, 0x03 for trial\n"
"                    will default to 0x01 (TPM_SE_POLICY) if not provided\n"
"                    to create a policy, use TPM_SE_TRIAL (0x03), to authenticate TPM_SE_POLICY (0x01)\n"
"flush_context <session_handle_addr>\n"
"    flush/terminate a session which's handle is stored at <session_handle_addr>\n"
"	 <session_handle_addr>: addr where the session handle is stored\n"
"policy_pcr <session_handle_addr> <pcr> <digest_addr>\n"
"    create a policy to authorize using a PCR\n"
"    <session_handle_addr>: addr where the session handle is stored\n"
"    <pcr>: index of the PCR\n"
"    <digest_addr>: addr where to store the policy digest (for nv_define/nv_read/write)\n"
);
