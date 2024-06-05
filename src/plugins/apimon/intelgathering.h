#ifndef INTELGATHERING_H
#define INTELGATHERING_H

#include <vector>
#include <map>
#include <memory>
#include <unordered_map>
#include <optional>
#include <glib.h>
#include <libusermode/userhook.hpp>
#include "plugins/plugins_ex.h"
#include "apimon.h"
#include <libvmi/libvmi.h>
#include <ctime>
#include "deceptions.h"
#include "deception_utils.h"

typedef struct process {
  std::string name;
  vmi_pid_t pid;
} process;

typedef struct LUID {
	uint32_t LowPart;
	long HighPart;
} LUID;

typedef struct LSA_UNICODE_STRING {
	uint16_t Length;
	uint16_t MaximumLength;
	addr_t Buffer;
} LSA_UNICODE_STRING;


typedef struct _KIWI_MSV1_0_LIST_63 {
	addr_t Flink;	//off_2C5718
	addr_t Blink; //off_277380
	addr_t unk0; // unk_2C0AC8
	uint64_t unk1; // 0FFFFFFFFh
	addr_t unk2; // 0
	uint32_t unk3; // 0
	uint32_t unk4; // 0
	uint64_t unk5; // 0A0007D0h
	addr_t hSemaphore6; // 0F9Ch
	addr_t unk7; // 0
	uint64_t hSemaphore8; // 0FB8h
	addr_t unk9; // 0
	addr_t unk10; // 0
	uint32_t unk11; // 0
	uint32_t unk12; // 0 
	addr_t unk13; // unk_2C0A28
	LUID LocallyUniqueIdentifier;
	LUID SecondaryLocallyUniqueIdentifier;
	uint8_t waza[16]; // to do (maybe align)
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domain;
	addr_t unk14;
	addr_t unk15;
	LSA_UNICODE_STRING Type;
	addr_t  pSid;
	uint64_t LogonType;
	addr_t unk18;
	uint64_t Session;
	int64_t LogonTime; // autoalign x86
	LSA_UNICODE_STRING LogonServer;
	addr_t Credentials;
	addr_t unk19;
	addr_t unk20;
	addr_t unk21;
	uint32_t unk22;
	uint32_t unk23;
	uint32_t unk24;
	uint32_t unk25;
	uint32_t unk26;
	addr_t unk27;
	addr_t unk28;
	addr_t unk29;
	addr_t CredentialManager;
} KIWI_MSV1_0_LIST_63, *PKIWI_MSV1_0_LIST_63;

typedef struct system_info {
    vmi_pid_t lsass_pid;
} system_info;

typedef struct simple_user {
	addr_t pstruct_addr;
	std::string user_name;
	std::string domain;
	std::string logon_server;
	addr_t pcredential_blob;
	int64_t logon_time;
	uint64_t session;
	uint64_t logon_type;
	std::string type;
} simple_user;

std::vector<process> list_running_processes(vmi_instance_t vmi, system_info* sysinfo, deception_plugin_config* config);
std::vector<simple_user> list_users(drakvuf_t drakvuf, vmi_instance_t vmi, system_info* sysinfo);

#endif