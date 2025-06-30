from enum import IntEnum


class LinuxExitCodes(IntEnum):
    """
    Common exit codes used on Linux/Unix systems. Includes both typical shell
    return codes and the 'sysexits' convention from BSD-derived systems.
    """

    # --------------------------------------------------------------------------
    # Generic / Shell-Related Exit Codes
    # --------------------------------------------------------------------------

    EX_OK = 0
    """Successful completion."""

    EX_GENERAL_ERROR = 1
    """Generic or unspecified error."""

    EX_MISUSE_BUILTIN = 2
    """Misuse of shell builtins (e.g., bash command line error)."""

    # Bash reserves codes 3-125 for user-defined purposes, though not standardized.
    # We won't define them all here, but you can add as needed.

    EX_CMD_NOT_EXECUTABLE = 126
    """Command found but not executable."""

    EX_CMD_NOT_FOUND = 127
    """Command not found. Also used by 'which' or 'type' if a command doesn't exist."""

    EX_INVALID_EXIT_ARG = 128
    """Invalid argument to 'exit' (e.g., exit 300 on a system that only allows 0–255)."""

    # 128 + SIG: if a process is terminated by a signal n, the exit status is generally 128 + n.
    # Some common signals:
    EX_SIGHUP = 128 + 1
    """Hangup detected on controlling terminal or death of controlling process (SIGHUP)."""

    EX_SIGINT = 128 + 2
    """Interrupted by Ctrl-C or SIGINT."""

    EX_SIGQUIT = 128 + 3
    """Quit from keyboard (SIGQUIT)."""

    EX_SIGILL = 128 + 4
    """Illegal Instruction (SIGILL)."""

    EX_SIGABRT = 128 + 6
    """Abort signal (SIGABRT)."""

    EX_SIGFPE = 128 + 8
    """Floating-point exception (SIGFPE)."""

    EX_SIGKILL = 128 + 9
    """Kill signal (SIGKILL)."""

    EX_SIGSEGV = 128 + 11
    """Segmentation violation (SIGSEGV)."""

    EX_SIGPIPE = 128 + 13
    """Broken pipe: write to pipe with no readers (SIGPIPE)."""

    EX_SIGALRM = 128 + 14
    """Timer signal from alarm (SIGALRM)."""

    EX_SIGTERM = 128 + 15
    """Termination signal (SIGTERM)."""

    # 130 is commonly SIGINT, included above.
    # You can add other signals as needed.

    EX_OUT_OF_RANGE = 255
    """Exit status out of range (e.g., negative or > 255) or 'exit -1' in POSIX shells."""

    # --------------------------------------------------------------------------
    # BSD "sysexits" (from /usr/include/sysexits.h)
    # --------------------------------------------------------------------------
    EX_USAGE = 64
    """Command line usage error (bad arguments, etc.)."""

    EX_DATAERR = 65
    """Data format error (input data was incorrect in some way)."""

    EX_NOINPUT = 66
    """Cannot open input."""

    EX_NOUSER = 67
    """Addressee unknown. (User not found.)"""

    EX_NOHOST = 68
    """Host name unknown."""

    EX_UNAVAILABLE = 69
    """Service unavailable (e.g., a necessary daemon not running)."""

    EX_SOFTWARE = 70
    """Internal software error."""

    EX_OSERR = 71
    """System error (e.g., cannot fork, cannot pipe, lost connection)."""

    EX_OSFILE = 72
    """Critical OS file missing (e.g., /etc/passwd, /etc/hosts)."""

    EX_CANTCREAT = 73
    """Cannot create user output file."""

    EX_IOERR = 74
    """I/O error during operation."""

    EX_TEMPFAIL = 75
    """Temporary failure, indicating something that may succeed if retried later."""

    EX_PROTOCOL = 76
    """Remote error in protocol exchange."""

    EX_NOPERM = 77
    """Permission denied."""

    EX_CONFIG = 78
    """Configuration error."""
