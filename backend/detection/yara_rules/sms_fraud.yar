/*
    YARA Rule: Android SMS Fraud Detection
    Author:    MobileGuard AI
    Version:   2.0
    Date:      2025-06-21
    Reference: FluBot, TangleBot, Roaming Mantis, FakeSpy TTPs
    Severity:  CRITICAL / HIGH

    Logic rationale:
    - SmsManager alone fires on every legitimate SMS/OTP app on the planet.
      WhatsApp, Truecaller, banking apps, 2FA apps all use it.
      NEVER flag on SmsManager alone.
    - SMS fraud is identified by: bulk sending capability + premium/harvested
      recipient list + financial payload + self-propagation via SMS links.
    - Key distinction from banking trojan: SMS fraud monetises via
      premium SMS charges or worm propagation, not credential theft.
    - sendMultipartTextMessage / sendTextMessage to harvested contacts
      combined with financial strings is the definitive kill chain.
*/

// ─────────────────────────────────────────────────────────────────
// TIER 1: CRITICAL — SMS fraud with self-propagation (worm behaviour)
// ─────────────────────────────────────────────────────────────────
rule SMS_FRAUD_WORM_CRITICAL
{
    meta:
        description  = "SMS worm: harvests contact list, sends fraud messages with APK download link"
        author       = "MobileGuard AI"
        severity     = "CRITICAL"
        action       = "BLOCK"
        mitre_attack = "T1582 (SMS Control), T1636.004 (Contact List)"
        false_pos    = "Extremely low — self-propagating SMS is unambiguous malware"

    strings:
        // SMS sending APIs (required — but not sufficient alone)
        $sms_send_single   = "sendTextMessage" ascii
        $sms_send_multi    = "sendMultipartTextMessage" ascii
        $sms_manager       = "SmsManager.getDefault" ascii

        // Contact harvesting (getting recipients)
        $contacts_perm     = "READ_CONTACTS" ascii
        $contacts_query    = "ContactsContract" ascii
        $contacts_phone    = "CommonDataKinds.Phone" ascii
        $contacts_cursor   = "CONTENT_URI" ascii

        // Self-propagation payload — APK download link in SMS body
        $apk_link1         = ".apk" ascii nocase
        $apk_link2         = "download" ascii nocase
        $apk_link3         = "install" ascii nocase
        $short_url1        = "bit.ly" ascii
        $short_url2        = "tinyurl" ascii
        $short_url3        = "t.me" ascii

        // Fraud payload strings (Indian context)
        $fraud_str1        = "prize" ascii nocase
        $fraud_str2        = "winner" ascii nocase
        $fraud_str3        = "lottery" ascii nocase
        $fraud_str4        = "loan" ascii nocase
        $fraud_str5        = "KYC" ascii nocase
        $fraud_str6        = "account suspended" ascii nocase
        $fraud_str7        = "verify now" ascii nocase
        $fraud_str8        = "click here" ascii nocase

        // Bulk sending indicators
        $thread_pool       = "ExecutorService" ascii
        $async_task        = "AsyncTask" ascii

    condition:
        // Must actually send SMS (not just have permission)
        (1 of ($sms_send_single, $sms_send_multi))
        and $sms_manager

        // Must harvest contacts (getting recipient list = bulk fraud)
        and ($contacts_perm
             and (1 of ($contacts_query, $contacts_phone, $contacts_cursor)))

        // Must include propagation payload (APK link or fraud lure)
        and (1 of ($apk_link1, $apk_link2, $apk_link3, $short_url1, $short_url2, $short_url3)
             or 2 of ($fraud_str1, $fraud_str2, $fraud_str3, $fraud_str4,
                      $fraud_str5, $fraud_str6, $fraud_str7, $fraud_str8))

        // Pillar: Must utilize background threads for bulk sending
        and (1 of ($thread_pool, $async_task))
}


// ─────────────────────────────────────────────────────────────────
// TIER 2: HIGH — Premium SMS fraud (toll fraud)
// ─────────────────────────────────────────────────────────────────
rule SMS_FRAUD_PREMIUM_HIGH
{
    meta:
        description  = "Premium SMS toll fraud: silently subscribes user to paid SMS services"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        mitre_attack = "T1582 (SMS Control)"
        false_pos    = "Low — premium number strings combined with silent send is definitive"

    strings:
        $sms_send_single   = "sendTextMessage" ascii
        $sms_send_multi    = "sendMultipartTextMessage" ascii
        $sms_manager       = "SmsManager.getDefault" ascii

        // Intercept delivery/status reports (to hide premium charge confirmation)
        $sent_intent       = "SMS_SENT" ascii
        $delivered_intent  = "SMS_DELIVERED" ascii
        $intercept_report  = "abortBroadcast" ascii

        // Premium SMS short code patterns (5-6 digit numbers)
        // Indian premium codes: 56070, 58888, 53030 etc.
        $premium_code1     = /\b5[0-9]{4}\b/ ascii
        $premium_code2     = /\b[A-Z]{5,11}\b/ ascii  // alphanumeric sender IDs

        // Hiding the send from user (no UI, background thread)
        $background_send   = "sendTextMessageWithoutPersisting" ascii
        $hide_from_log     = "deleteMessage" ascii

        // Disable incoming SMS display to hide confirmation
        $intercept_sms     = "SMS_RECEIVED" ascii
        $priority_high     = "android:priority=\"1000\"" ascii

    condition:
        // Must use SMS sending API
        (1 of ($sms_send_single, $sms_send_multi))
        and $sms_manager

        and (1 of ($premium_code*))

        // Tier A: Silent premium send (highest confidence)
        and (
            ($background_send or $hide_from_log)
            or
            // Tier B: Intercept delivery report to hide charge from user
            ($intercept_report and (1 of ($sent_intent, $delivered_intent)))
            or
            // Tier C: Block incoming confirmation SMS + high-priority receiver
            ($intercept_sms and $priority_high)
        )
}


// ─────────────────────────────────────────────────────────────────
// TIER 3: HIGH — OTP Relay fraud (SIM swap / account takeover)
// ─────────────────────────────────────────────────────────────────
rule SMS_FRAUD_OTP_RELAY_HIGH
{
    meta:
        description  = "OTP relay: intercepts received OTP/SMS and forwards to attacker C2"
        author       = "MobileGuard AI"
        severity     = "HIGH"
        action       = "ESCALATE"
        false_pos    = "Low — OTP interception + HTTP relay is definitive"

    strings:
        // Intercept incoming SMS
        $sms_received      = "android.provider.Telephony.SMS_RECEIVED" ascii
        $sms_read_perm     = "READ_SMS" ascii
        $get_body          = "getMessageBody" ascii
        $get_sender        = "getOriginatingAddress" ascii

        // OTP / financial keyword matching in SMS body
        $otp_kw1           = "OTP" ascii
        $otp_kw2           = "one time password" ascii nocase
        $otp_kw3           = "verification code" ascii nocase
        $otp_kw4           = "transaction" ascii nocase
        $otp_kw5           = "debit" ascii nocase
        $otp_kw6           = "credit" ascii nocase

        // Relay to attacker (HTTP POST with SMS content)
        $http_post1        = "HttpURLConnection" ascii
        $http_post2        = "OkHttpClient" ascii
        $post_method       = "POST" ascii
        $json_body         = "JSONObject" ascii

        // Indian bank SMS sender IDs commonly spoofed/targeted
        $target_sbi        = "SBIINB" ascii
        $target_hdfc       = "HDFCBK" ascii
        $target_icici      = "ICICIB" ascii
        $target_boi        = "BOIIND" ascii
        $target_axis       = "AXISBK" ascii

    condition:
        // Must intercept incoming SMS
        ($sms_read_perm or $get_body or $sms_received)
        and ($get_body or $get_sender)

        // Must match financial/OTP content
        and (2 of ($otp_kw1, $otp_kw2, $otp_kw3, $otp_kw4, $otp_kw5, $otp_kw6))

        // Must relay to remote server
        and (1 of ($http_post1, $http_post2))
        and ($post_method and $json_body)

        and (
            $target_sbi
            or $target_hdfc
            or $target_icici
            or $target_boi
            or $target_axis
        )
}


// ─────────────────────────────────────────────────────────────────
// TIER 4: MEDIUM — Suspicious SMS behaviour, analyst triage
// ─────────────────────────────────────────────────────────────────
rule SMS_FRAUD_SUSPICIOUS
{
    meta:
        description  = "Suspicious SMS capability — requires analyst review to rule out legitimate use"
        author       = "MobileGuard AI"
        severity     = "MEDIUM"
        action       = "MONITOR"
        false_pos    = "Moderate — 2FA apps and OTP managers may trigger this"

    strings:
        $sms_send          = "sendTextMessage" ascii
        $sms_receive       = "RECEIVE_SMS" ascii
        $sms_read          = "READ_SMS" ascii
        $get_body          = "getMessageBody" ascii
        $contacts_perm     = "READ_CONTACTS" ascii
        $http_conn         = "HttpURLConnection" ascii

    condition:
        // Sending + reading + forwarding — without any of the above
        ($sms_send and $sms_read and $get_body and $http_conn)
        and $contacts_perm
        and $sms_receive
        and not SMS_FRAUD_WORM_CRITICAL
        and not SMS_FRAUD_PREMIUM_HIGH
        and not SMS_FRAUD_OTP_RELAY_HIGH
}
