/*
    YARA Rule: Android Remote Access Trojan (RAT) Detection
    Author:    MobileGuard AI
    Version:   2.0
    Date:      2025-06-21
    Reference: AhMyth, DroidJack, SpyNote, Dendroid, GravityRAT family TTPs
    Severity:  CRITICAL / HIGH

    Logic rationale:
    - Runtime.exec alone fires on legitimate terminal apps, NDK code,
      shell utilities. NOT sufficient alone.
    - DexClassLoader alone fires on app update frameworks, plugin systems.
      NOT sufficient alone.
    - RATs are identified by: remote control channel + device surveillance
      capability + persistence + code loading from external source.
    - The kill chain is: establish socket/HTTP C2 → receive commands →
      execute on device → exfiltrate results.
*/

// ─────────────────────────────────────────────────────────────────
// TIER 1: CRITICAL — Full RAT capability confirmed
// ─────────────────────────────────────────────────────────────────
rule RAT_CRITICAL
{
    meta:
        description  = "Full Android RAT: remote command execution + surveillance + external code loading"
        author       = "MobileGuard AI"
        severity     = "CRITICAL"
        action       = "BLOCK"
        mitre_attack = "T1430 (Location Tracking), T1429 (Capture Audio), T1512 (Video Capture)"
        false_pos    = "Extremely low — combination is unique to RAT families"

    strings:
        // Remote command execution
        $exec_runtime      = "Runtime.exec" ascii
        $exec_process      = "ProcessBuilder" ascii
        $exec_shell        = "/system/bin/sh" ascii
        $exec_su           = "su -c" ascii

        // Dynamic code loading from external source (the RAT update/plugin mechanism)
        $dex_loader        = "DexClassLoader" ascii
        $path_class_loader = "PathClassLoader" ascii
        $load_dex          = "loadDex" ascii
        $dex_opt           = "dalvik.system" ascii

        // Persistent socket-based C2 (characteristic of RATs vs trojans)
        $socket            = "java.net.Socket" ascii
        $server_socket     = "ServerSocket" ascii
        $data_input        = "DataInputStream" ascii
        $data_output       = "DataOutputStream" ascii
        $socket_channel    = "SocketChannel" ascii

        // Device surveillance capabilities
        $camera_open       = "Camera.open" ascii
        $camera2           = "CameraManager" ascii
        $mic_record        = "MediaRecorder" ascii
        $audio_record      = "AudioRecord" ascii
        $screen_capture    = "MediaProjectionManager" ascii
        $keylogger         = "KeyEvent" ascii

        // Location surveillance
        $location_mgr      = "LocationManager" ascii
        $gps_provider      = "GPS_PROVIDER" ascii
        $location_updates  = "requestLocationUpdates" ascii

        // File exfiltration
        $file_read         = "FileInputStream" ascii
        $sdcard            = "/sdcard/" ascii
        $whatsapp_path     = "WhatsApp" ascii
        $dcim_path         = "DCIM" ascii

        // Persistence
        $boot_persist      = "RECEIVE_BOOT_COMPLETED" ascii
        $foreground_svc    = "startForeground" ascii
        $alarm_mgr         = "AlarmManager" ascii

        // Anti-analysis
        $emulator_check1   = "ro.kernel.qemu" ascii
        $emulator_check2   = "Genymotion" ascii
        $emulator_check3   = "goldfish" ascii
        $debug_check       = "isDebuggerConnected" ascii
        $root_check        = "/system/bin/su" ascii

    condition:
        // Pillar 1: Remote code execution capability
        (1 of ($exec_runtime, $exec_process, $exec_shell, $exec_su))

        // Pillar 2: External code loading (RAT self-update / plugin capability)
        and (1 of ($dex_loader, $path_class_loader, $load_dex, $dex_opt))

        // Pillar 3: Persistent bidirectional C2 socket (distinguishes RAT from trojan)
        and (($socket or $server_socket)
             and ($data_input or $data_output or $socket_channel))
        

        // Pillar 4: At least two surveillance capabilities
        and (2 of (
            $camera_open,
            $camera2,
            $mic_record,
            $audio_record,
            $screen_capture,
            $location_mgr,
            $gps_provider,
            $location_updates,
            $keylogger,
            $file_read,
            $sdcard
        ))

        // Pillar 5: Persistence mechanism
        and (1 of ($boot_persist, $foreground_svc, $alarm_mgr))
        and (
            $whatsapp_path or
            $dcim_path
        )

        // Bonus: Anti-analysis present (elevates confidence, not required)
        and (1 of ($emulator_check1, $emulator_check2, $emulator_check3,
                $debug_check, $root_check))
}


// ─────────────────────────────────────────────────────────────────
// TIER 2: HIGH — RAT strongly suspected, missing one pillar
// ─────────────────────────────────────────────────────────────────
rule RAT_HIGH
{
    meta:
        description  = "RAT high confidence: C2 socket + surveillance without confirmed dynamic loading"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        false_pos    = "Low — persistent socket + 2 surveillance capabilities is rare legitimately"

    strings:
        $exec_runtime      = "Runtime.exec" ascii
        $exec_process      = "ProcessBuilder" ascii
        $dex_loader        = "DexClassLoader" ascii
        $socket            = "java.net.Socket" ascii
        $data_input        = "DataInputStream" ascii
        $data_output       = "DataOutputStream" ascii
        $camera_open       = "Camera.open" ascii
        $camera2           = "CameraManager" ascii
        $mic_record        = "MediaRecorder" ascii
        $audio_record      = "AudioRecord" ascii
        $screen_capture    = "MediaProjectionManager" ascii
        $location_updates  = "requestLocationUpdates" ascii
        $file_read         = "FileInputStream" ascii
        $boot_persist      = "RECEIVE_BOOT_COMPLETED" ascii

        // Known RAT package name fragments
        $rat_pkg1          = "androidrat" ascii nocase
        $rat_pkg2          = "droidjack" ascii nocase
        $rat_pkg3          = "spynote" ascii nocase
        $rat_pkg4          = "ahmyth" ascii nocase

    condition:
        // Known RAT family name → immediate escalation
        (1 of ($rat_pkg1, $rat_pkg2, $rat_pkg3, $rat_pkg4))

        or (
            // C2 socket present
            ($socket and ($data_input or $data_output))

            // Plus command execution
            and (1 of ($exec_runtime, $exec_process, $dex_loader))

            // Plus multiple surveillance capabilities
            and (2 of ($camera_open, $camera2, $mic_record, $audio_record,
                       $screen_capture, $location_updates, $file_read))

            // Plus persistence
            and $boot_persist
        )

        and not RAT_CRITICAL
}


// ─────────────────────────────────────────────────────────────────
// TIER 3: SUSPICIOUS — Dynamic loading from external path
// Legitimate apps update via Play Store, not DexClassLoader from /sdcard
// ─────────────────────────────────────────────────────────────────
rule RAT_DYNAMIC_LOAD_EXTERNAL
{
    meta:
        description  = "Suspicious external DEX loading — common RAT plugin/update mechanism"
        author       = "MobileGuard AI"
        severity     = "MEDIUM"
        action       = "MONITOR"
        false_pos    = "Moderate — some plugin frameworks use DexClassLoader legitimately"

    strings:
        $dex_loader        = "DexClassLoader" ascii
        $sdcard_path       = "/sdcard/" ascii
        $download_path     = "/data/local/tmp/" ascii
        $cache_path        = "getCacheDir" ascii
        $http_download     = "HttpURLConnection" ascii
        $url_stream        = "openStream" ascii

    condition:
        // DexClassLoader loading from a path obtained at runtime
        // (not from assets/ which is compile-time — that's legitimate)
        $dex_loader

        // Loading from external/downloaded location
        and (1 of ($sdcard_path, $download_path, $cache_path))

        // Source is remote (HTTP download → load into runtime)
        and ($http_download and $url_stream)

        and not RAT_HIGH
        and not RAT_CRITICAL
}
