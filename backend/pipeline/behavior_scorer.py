def score_behavior(features):

    score = 0

    score += features.sms_send_attempts * 20

    score += min(
        len(features.network_domains_contacted) * 5,
        25
    )

    if features.accessibility_service_abused:
        score += 25

    if features.device_admin_requested:
        score += 20
        
    if features.camera_accessed:
        score += 10

    if features.microphone_accessed:
        score += 10

    if features.location_accessed:
        score += 10

    if features.clipboard_hijack_detected:
        score += 15

    if features.silent_install_attempted:
        score += 20
    
    if features.overlay_detected:
        score += 20

    return min(score, 100)