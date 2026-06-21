/*
    YARA Rule: Android Spyware Detection
    Author:    MobileGuard AI
    Version:   2.0
    Date:      2025-06-21
    Reference: Pegasus (Android), Predator, Hermit, SpyNote, Stalkerware TTPs
    Severity:  CRITICAL / HIGH

    Logic rationale:
    - READ_CONTACTS alone fires on every address book app, every social
      app, every dialler. Not a malware signal alone.
    - READ_SMS alone fires on SMS backup apps, parental control apps,
      legitimate dual-SIM managers. Not a signal alone.
    - ACCESS_FINE_LOCATION alone fires on maps, weather, delivery apps.
    - Spyware is identified by: covert surveillance (no UI, no notification)
      + multi-vector data collection + silent exfiltration.
    - Key distinguisher: legitimate apps show permission rationale dialogs
      and display what they're doing. Spyware runs as background service,
      hides its icon, and exfiltrates without user awareness.
*/

// ─────────────────────────────────────────────────────────────────
// TIER 1: CRITICAL — Full covert spyware: multi-vector + hidden + exfil
// ─────────────────────────────────────────────────────────────────
rule SPYWARE_CRITICAL
{
    meta:
        description  = "Full covert spyware: multi-vector surveillance + icon hiding + silent exfiltration"
        author       = "MobileGuard AI"
        severity     = "CRITICAL"
        action       = "BLOCK"
        mitre_attack = "T1430 (Location Tracking), T1636 (Protected User Data), T1429 (Capture Audio)"
        false_pos    = "Extremely low — icon hiding + multi-vector + exfil is unambiguous"

    strings:
        // Covert operation: hide launcher icon (spyware hallmark)
        $hide_icon1        = "COMPONENT_ENABLED_STATE_DISABLED" ascii
        $hide_icon2        = "setComponentEnabledSetting" ascii
        $hide_icon3        = "PackageManager.DONT_KILL_APP" ascii

        // Covert operation: run as background service with no UI
        $bg_service        = "startForeground" ascii
        $wakelock          = "WAKE_LOCK" ascii
        $no_notification   = "FOREGROUND_SERVICE" ascii

        // Location surveillance
        $loc_fine          = "ACCESS_FINE_LOCATION" ascii
        $loc_coarse        = "ACCESS_COARSE_LOCATION" ascii
        $loc_background    = "ACCESS_BACKGROUND_LOCATION" ascii
        $loc_updates       = "requestLocationUpdates" ascii
        $loc_last          = "getLastKnownLocation" ascii
        $loc_fused         = "FusedLocationProviderClient" ascii

        // Communication surveillance
        $read_sms          = "READ_SMS" ascii
        $read_contacts     = "READ_CONTACTS" ascii
        $read_call_log     = "READ_CALL_LOG" ascii
        $call_log_content  = "CallLog.Calls" ascii
        $read_calendar     = "READ_CALENDAR" ascii

        // Media surveillance
        $camera_open       = "Camera.open" ascii
        $camera2_mgr       = "CameraManager" ascii
        $mic_record        = "MediaRecorder" ascii
        $audio_record      = "AudioRecord" ascii
        $screen_capture    = "MediaProjectionManager" ascii

        // File / app surveillance
        $file_access       = "FileInputStream" ascii
        $get_installed     = "getInstalledPackages" ascii
        $get_installed2    = "getInstalledApplications" ascii

        // Silent exfiltration (no user-visible upload progress)
        $http_post1        = "HttpURLConnection" ascii
        $http_post2        = "OkHttpClient" ascii
        $ftp_upload        = "org.apache.commons.net.ftp" ascii
        $email_exfil       = "javax.mail" ascii
        $telegram_bot      = "api.telegram.org" ascii
        $firebase_exfil    = "firebaseio.com" ascii

        // Anti-removal: device admin to prevent uninstall
        $device_admin      = "BIND_DEVICE_ADMIN" ascii
        $remove_prevent    = "onDisableRequested" ascii

        // Persistence
        $boot_persist      = "RECEIVE_BOOT_COMPLETED" ascii

    condition:
        // Pillar 1: Actively hiding from the user (not just background — covert)
        (($hide_icon1 and $hide_icon2)
         or ($hide_icon2 and $hide_icon3))

        // Pillar 2: Multi-vector surveillance (3+ distinct data types)
        and (3 of ($loc_fine, $loc_coarse, $loc_background, $loc_updates,
                   $loc_last, $loc_fused,
                   $read_sms, $read_contacts, $read_call_log, $call_log_content,
                   $read_calendar, $camera_open, $camera2_mgr,
                   $mic_record, $audio_record, $screen_capture,
                   $file_access, $get_installed, $get_installed2))

        // Pillar 3: Silent exfiltration channel
        and (1 of ($http_post1, $http_post2, $ftp_upload,
                   $email_exfil, $telegram_bot, $firebase_exfil))
        and $bg_service
        and $no_notification
        and ($device_admin or $remove_prevent)

        // Pillar 4: Persistence (long-term covert surveillance)
        and ($boot_persist or $wakelock)
}


// ─────────────────────────────────────────────────────────────────
// TIER 2: HIGH — Stalkerware (commercially available covert monitoring)
// ─────────────────────────────────────────────────────────────────
rule SPYWARE_STALKERWARE_HIGH
{
    meta:
        description  = "Stalkerware: intimate partner surveillance tool, covert installation design"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        mitre_attack = "T1430, T1636"
        false_pos    = "Low — covert install design + location + comms is definitive stalkerware"

    strings:
        // Stalkerware-specific: instructions to hide from victim
        $hide_str1         = "hide icon" ascii nocase
        $hide_str2         = "invisible mode" ascii nocase
        $hide_str3         = "stealth mode" ascii nocase
        $hide_str4         = "hidden from" ascii nocase
        $hide_str5         = "undetectable" ascii nocase
        $hide_str6         = "target won" ascii nocase  // "target won't know"

        // Covert icon hiding API
        $hide_api          = "setComponentEnabledSetting" ascii
        $hide_api2         = "COMPONENT_ENABLED_STATE_DISABLED" ascii

        // Location tracking
        $loc_updates       = "requestLocationUpdates" ascii
        $loc_fused         = "FusedLocationProviderClient" ascii

        // Communication access
        $read_sms          = "READ_SMS" ascii
        $read_call_log     = "READ_CALL_LOG" ascii
        $read_contacts     = "READ_CONTACTS" ascii

        // Known stalkerware package fragments
        $pkg1              = "spyware" ascii nocase
        $pkg2              = "mspy" ascii nocase
        $pkg3              = "flexispy" ascii nocase
        $pkg4              = "spyic" ascii nocase
        $pkg5              = "cocospy" ascii nocase
        $pkg6              = "trackview" ascii nocase

    condition:
        // Known commercial stalkerware → immediate escalation
        (1 of ($pkg1, $pkg2, $pkg3, $pkg4, $pkg5, $pkg6))

        or (
            // Covert install design (either via strings or API)
            (1 of ($hide_str1, $hide_str2, $hide_str3, $hide_str4,
                   $hide_str5, $hide_str6)
             or ($hide_api and $hide_api2))

            // Location tracking
            and (1 of ($loc_updates, $loc_fused))

            // Access to private communications
            and (2 of ($read_sms, $read_call_log, $read_contacts))
        )

        and not SPYWARE_CRITICAL
}


// ─────────────────────────────────────────────────────────────────
// TIER 3: HIGH — Audio/Camera surveillance without UI
// ─────────────────────────────────────────────────────────────────
rule SPYWARE_AV_SURVEILLANCE_HIGH
{
    meta:
        description  = "Covert audio or camera recording without user-visible activity"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        false_pos    = "Low — background AV recording without any media UI is very rare legitimately"

    strings:
        // Audio recording APIs
        $mic_record        = "MediaRecorder" ascii
        $audio_record      = "AudioRecord" ascii
        $mic_perm          = "RECORD_AUDIO" ascii
        $audio_start       = "startRecording" ascii

        // Camera APIs
        $camera_open       = "Camera.open" ascii
        $camera2           = "CameraDevice" ascii
        $camera_perm       = "CAMERA" ascii
        $capture_session   = "CameraCaptureSession" ascii

        // Background / hidden recording indicators
        $bg_service        = "Service" ascii
        $no_ui_activity    = "android:exported=\"false\"" ascii
        $wake_lock         = "WAKE_LOCK" ascii
        $foreground_svc    = "startForeground" ascii

        // Exfiltration of recorded media
        $file_write        = "FileOutputStream" ascii
        $http_upload       = "HttpURLConnection" ascii
        $multipart         = "multipart/form-data" ascii

    condition:
        // Audio or camera recording capability
        (($mic_perm and ($mic_record or $audio_record) and $audio_start)
         or ($camera_perm and ($camera_open or $camera2) and $capture_session))

        // Running in background without visible UI
        and ($bg_service and ($wake_lock or $foreground_svc))
        and $no_ui_activity

        // Uploading the recorded content
        and ($file_write and $http_upload and $multipart)

        and not SPYWARE_CRITICAL
}


// ─────────────────────────────────────────────────────────────────
// TIER 4: MEDIUM — Broad surveillance capability, analyst review
// ─────────────────────────────────────────────────────────────────
rule SPYWARE_SUSPICIOUS
{
    meta:
        description  = "Broad data collection across 3+ sensitive dimensions — analyst review required"
        author       = "MobileGuard AI"
        severity     = "MEDIUM"
        action       = "MONITOR"
        false_pos    = "Moderate — social/productivity apps with broad permissions may trigger"

    strings:
        $loc_perm          = "ACCESS_FINE_LOCATION" ascii
        $sms_perm          = "READ_SMS" ascii
        $contacts_perm     = "READ_CONTACTS" ascii
        $call_log_perm     = "READ_CALL_LOG" ascii
        $camera_perm       = "CAMERA" ascii
        $mic_perm          = "RECORD_AUDIO" ascii
        $storage_perm      = "READ_EXTERNAL_STORAGE" ascii
        $boot_perm         = "RECEIVE_BOOT_COMPLETED" ascii
        $http_conn         = "HttpURLConnection" ascii

    condition:
        // At least 4 distinct sensitive permission/capability types
        4 of ($loc_perm, $sms_perm, $contacts_perm, $call_log_perm,
              $camera_perm, $mic_perm, $storage_perm)

        // With outbound network (required for exfiltration)
        and $http_conn

        // With persistence (long-term surveillance indicator)
        and $boot_perm

        and not SPYWARE_STALKERWARE_HIGH
        and not SPYWARE_AV_SURVEILLANCE_HIGH
        and not SPYWARE_CRITICAL
}
