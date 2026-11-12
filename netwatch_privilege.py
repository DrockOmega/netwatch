"""Linux capability split: only the capture worker keeps raw-socket privilege.

The systemd unit grants CAP_NET_RAW/CAP_NET_ADMIN as ambient capabilities to an
unprivileged user. Spawned workers inherit them on exec; non-capture workers
clear every set at start, and the supervisor/API process clears its effective
set but keeps permitted+inheritable+ambient so it can respawn capture. Other
platforms are a no-op reported as ``unverified``.
"""

import ctypes
import sys

_CAP_VERSION_3 = 0x20080522
_PR_SET_NO_NEW_PRIVS = 38
_PR_CAP_AMBIENT = 47
_PR_CAP_AMBIENT_RAISE = 2
_PR_CAP_AMBIENT_CLEAR_ALL = 4


class _Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _Data(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _check(result, what):
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"{what} failed")


def _capset(libc, update):
    header, data = _Header(_CAP_VERSION_3, 0), (_Data * 2)()
    _check(libc.capget(ctypes.byref(header), data), "capget")
    for word in data:
        update(word)
    _check(libc.capset(ctypes.byref(header), data), "capset")


def get_privilege_state():
    """Effective privilege of this process, for service health."""
    if not sys.platform.startswith("linux"):
        return {"status": "unverified", "platform": sys.platform}
    fields = {"CapEff": "effective", "CapPrm": "permitted", "CapInh": "inheritable",
              "CapAmb": "ambient", "NoNewPrivs": "no_new_privs"}
    state = {}
    with open("/proc/self/status") as status:
        for line in status:
            key, _, value = line.partition(":")
            if key in fields:
                state[fields[key]] = value.strip()
    state["no_new_privs"] = state.get("no_new_privs") == "1"
    bits = {name: int(state.get(name, "0"), 16) for name in ("effective", "permitted", "ambient")}
    # dormant: not usable now, but the process could raise it again (supervisor holding it for capture respawn).
    state["status"] = ("privileged" if bits["effective"] else
                       "dormant" if bits["permitted"] or bits["ambient"] else "unprivileged")
    return state


def drop_privileges():
    """Irreversibly clear all capabilities and forbid regaining them (non-capture workers)."""
    if sys.platform.startswith("linux"):
        libc = _libc()
        _check(libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0), "clear ambient capabilities")
        _check(libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "set no_new_privs")

        def clear(word):
            word.effective = word.permitted = word.inheritable = 0
        _capset(libc, clear)
    return get_privilege_state()


def drop_effective_privileges():
    """Clear the effective set only; permitted/ambient stay so capture can be respawned."""
    if sys.platform.startswith("linux"):
        def clear(word):
            word.effective = 0
        _capset(_libc(), clear)
    return get_privilege_state()


def run_without_ambient(start):
    """Run ``start`` with ambient capabilities cleared, then raise them again.

    Helpers the supervisor execs outside the worker path (multiprocessing's resource
    tracker) would otherwise turn the ambient set into effective raw-socket privilege.
    """
    if not sys.platform.startswith("linux"):
        return start()
    with open("/proc/self/status") as status:
        ambient = next((int(line.split(":")[1], 16) for line in status if line.startswith("CapAmb:")), 0)
    libc = _libc()
    _check(libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0), "clear ambient capabilities")
    try:
        return start()
    finally:
        for cap in range(64):
            if ambient >> cap & 1:
                _check(libc.prctl(_PR_CAP_AMBIENT, _PR_CAP_AMBIENT_RAISE, cap, 0, 0), "raise ambient capability")
