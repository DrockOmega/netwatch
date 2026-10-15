# Windows service path — UNVERIFIED

Nothing here has been run on Windows. Every statement below is UNVERIFIED until checked on the sensor.

- UNVERIFIED: `sc.exe create` cannot host `python -m netwatch_service` directly: python.exe does not
  answer the Service Control Manager, so SCM kills it after its start timeout. pywin32 is not a
  dependency, so no native service wrapper ships.
- UNVERIFIED: dependency-free path is a boot-time scheduled task:

  ```
  schtasks /Create /TN NetWatch /SC ONSTART /RU SYSTEM /RL HIGHEST ^
    /TR "C:\Dev\network_monitor\.venv\Scripts\python.exe -m netwatch_service --base-dir C:\ProgramData\NetWatch"
  schtasks /Delete /TN NetWatch /F
  ```

  The service refuses to load an API secret whose ACL grants anyone but SYSTEM and Administrators
  (inherited entries for those two are fine); a looser file must be fixed with `icacls` first.
- UNVERIFIED: Windows has no per-process capability split here. Npcap capture needs Administrator
  (or Npcap installed with "restrict to Administrators" off), and `netwatch_privilege` is a no-op that
  reports `unverified`, so every worker runs with the task account's full token. Running capture under
  a separate account from the console needs a separate capture service plus an authenticated local
  channel; that is not built.
- UNVERIFIED: the console (`python -m netwatch_client`) must run elevated (as Administrator): it reads
  the secret, and only SYSTEM and Administrators may.
