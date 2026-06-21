/*
    YARA Rule: Android Banking Trojan Detection
    Author:    MobileGuard AI
    Version:   2.0
    Date:      2025-06-21
    Reference: BankBot, Anubis, Cerberus, Gustuff, Sharkbot family TTPs
    Severity:  CRITICAL

    Logic rationale:
    - Accessibility abuse alone is NOT sufficient (legitimate apps for
      disabled users use this). Must combine with overlay or SMS theft.
    - Overlay attack (SYSTEM_ALERT_WINDOW) + credential harvesting APIs
      is the core banking trojan kill chain.
    - C2 communication patterns (HTTP POST with device identifiers) must
      co-occur with financial targeting strings.
    - Rules are structured in tiers: CRITICAL requires all pillars,
      HIGH requires two, MEDIUM is for analyst triage only.
*/

// ─────────────────────────────────────────────────────────────────
// TIER 1: CRITICAL — Full banking trojan kill chain confirmed
// Requires: overlay capability + SMS/OTP theft + C2 exfil pattern
// ─────────────────────────────────────────────────────────────────
rule BANKING_TROJAN_CRITICAL
{
    meta:
        description  = "Full banking trojan kill chain: overlay attack + OTP interception + C2 exfiltration"
        author       = "MobileGuard AI"
        severity     = "CRITICAL"
        action       = "BLOCK"
        certintel    = "file with CERT-In if confirmed"
        mitre_attack = "T1417 (Input Capture), T1411 (User Interface Spoofing)"
        false_pos    = "Extremely low — combination is unique to malware"

    strings:
        // Overlay attack capability
        $overlay_perm      = "SYSTEM_ALERT_WINDOW" ascii
        $overlay_api       = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay_api_old   = "TYPE_PHONE" ascii          // pre-API 26 overlay type

        // Accessibility abuse for credential/OTP harvesting
        $a11y_perm         = "BIND_ACCESSIBILITY_SERVICE" ascii
        $a11y_service      = "AccessibilityService" ascii
        $a11y_event        = "onAccessibilityEvent" ascii
        $a11y_node         = "findAccessibilityNodeInfosByText" ascii
        $a11y_perform      = "performAction" ascii

        // SMS/OTP interception
        $sms_receive_perm  = "RECEIVE_SMS" ascii
        $sms_read_perm     = "READ_SMS" ascii
        $sms_receiver      = "SmsReceiver" ascii
        $sms_intcpt        = "android.provider.Telephony.SMS_RECEIVED" ascii
        $sms_body          = "getMessageBody" ascii
        $otp_keyword1      = "OTP" ascii nocase
        $otp_keyword2      = "one-time" ascii nocase
        $otp_keyword3      = "verification code" ascii nocase

        // Device fingerprinting for C2 registration
        $device_id         = "getDeviceId" ascii
        $imei              = "getImei" ascii
        $sub_id            = "getSubscriberId" ascii
        $android_id        = "ANDROID_ID" ascii

        // C2 communication patterns
        $http_post         = "HttpURLConnection" ascii
        $okhttp            = "OkHttpClient" ascii
        $volley            = "com.android.volley" ascii
        $c2_cmd            = "command" ascii nocase
        $c2_bot            = "bot_id" ascii nocase
        $c2_register       = "register" ascii nocase

        // Anti-analysis / persistence
        $boot_persist      = "RECEIVE_BOOT_COMPLETED" ascii
        $device_admin      = "BIND_DEVICE_ADMIN" ascii
        $kill_switch       = "uninstallPackage" ascii

    condition:        
        // Pillar 1: Overlay capability (either form)
        $a11y_event and
        (
            ($overlay_perm and $overlay_api)
            or
            ($overlay_perm and $overlay_api_old)
        )

        // Pillar 2: Accessibility abuse chain (not just declared — actually used)
        and ($a11y_perm and $a11y_service and ($a11y_node or $a11y_perform))

        // Pillar 3: OTP/SMS interception
        and (($sms_receive_perm or $sms_read_perm)
             and ($sms_body or $sms_intcpt or $sms_receiver)
             and (1 of ($otp_keyword*)))

        // Pillar 4: Device fingerprinting (C2 registration indicator)
        and (2 of ($device_id, $imei, $sub_id, $android_id))

        // Pillar 5: Outbound C2 communication
        and (1 of ($http_post, $okhttp, $volley))
        and (1 of ($c2_cmd, $c2_bot, $c2_register))

        // Pillar 6: Persistence and Anti-Analysis (Integrating your orphaned strings)
        and (1 of ($boot_persist, $device_admin, $kill_switch))

}


// ─────────────────────────────────────────────────────────────────
// TIER 2: HIGH — Banking trojan strongly suspected, two pillars
// ─────────────────────────────────────────────────────────────────
rule BANKING_TROJAN_HIGH
{
    meta:
        description  = "Banking trojan high confidence: overlay + OTP theft without confirmed C2"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        false_pos    = "Low — overlay + SMS combo is rare in legitimate apps"

    strings:
        $overlay_perm      = "SYSTEM_ALERT_WINDOW" ascii
        $a11y_perm         = "BIND_ACCESSIBILITY_SERVICE" ascii
        $a11y_node         = "findAccessibilityNodeInfosByText" ascii
        $sms_receive_perm  = "RECEIVE_SMS" ascii
        $sms_body          = "getMessageBody" ascii
        $device_id         = "getDeviceId" ascii
        $imei              = "getImei" ascii

        // Indian banking target strings — high signal for India-targeting trojans
        $target_upi        = "upi" ascii nocase
        $target_bhim       = "bhim" ascii nocase
        $target_paytm      = "paytm" ascii nocase
        $target_gpay       = "googlepay" ascii nocase
        $target_phonepe    = "phonepe" ascii nocase
        $target_boi        = "bankofindia" ascii nocase
        $target_sbi        = "onlinesbi" ascii nocase

    condition:
        // Must have overlay + accessibility (core kill chain)
        $overlay_perm
        and ($a11y_perm and $a11y_node)

        // Plus at least one of: OTP interception or device fingerprinting
        and (($sms_receive_perm and $sms_body) or ($device_id or $imei))

        // Bonus: Indian financial app targeting elevates to this tier
        and ($target_upi or
            $target_bhim or
            $target_paytm or
            $target_gpay or
            $target_phonepe or
            $target_boi or
            $target_sbi)

        // Must NOT already match CRITICAL rule (avoid double-firing)
        and not BANKING_TROJAN_CRITICAL
}


// ─────────────────────────────────────────────────────────────────
// TIER 3: MEDIUM — Suspicious, warrants analyst review
// ─────────────────────────────────────────────────────────────────
rule BANKING_TROJAN_SUSPICIOUS
{
    meta:
        description  = "Suspicious banking-trojan-like behaviour requiring analyst review"
        author       = "MobileGuard AI"
        severity     = "MEDIUM"
        action       = "MONITOR"
        false_pos    = "Moderate — screen readers and OTP apps may trigger this"

    strings:
        $overlay_perm      = "SYSTEM_ALERT_WINDOW" ascii
        $a11y_perm         = "BIND_ACCESSIBILITY_SERVICE" ascii
        $sms_read_perm     = "READ_SMS" ascii
        $install_pkg       = "REQUEST_INSTALL_PACKAGES" ascii
        $device_admin      = "BIND_DEVICE_ADMIN" ascii
        $kill_other_apps   = "forceStopPackage" ascii
        $read_notifications = "BIND_NOTIFICATION_LISTENER_SERVICE" ascii

    condition:
        // Any two of these high-risk capabilities co-occurring
        (
            2 of ($overlay_perm, $a11y_perm, $sms_read_perm)
            or
            ($device_admin and $install_pkg)
            or
            ($kill_other_apps and $read_notifications)
        )

        and not BANKING_TROJAN_HIGH
        and not BANKING_TROJAN_CRITICAL
}
