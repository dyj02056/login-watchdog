import os

FAILURE_THRESHOLD = int(os.environ.get("FAILURE_THRESHOLD", 5))
DETECTION_WINDOW_SECONDS = int(os.environ.get("DETECTION_WINDOW_SECONDS", 60))
LOCKOUT_DURATION_SECONDS = int(os.environ.get("LOCKOUT_DURATION_SECONDS", 300))
TRUST_FORWARDED_FOR = os.environ.get("TRUST_FORWARDED_FOR", "false").lower() == "true"
