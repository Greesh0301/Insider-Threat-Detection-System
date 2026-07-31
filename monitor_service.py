import threading
import time
from usb_monitor import monitor_usb
from detector import run_detector


def detector_loop():
    while True:
        try:
            run_detector()
        except Exception as e:
            print("Detector Error:", e)

        # Run every 30 seconds
        time.sleep(30)


def start_services():

    # USB Monitor
    usb_thread = threading.Thread(
        target=monitor_usb,
        daemon=True
    )

    # Threat Detector
    detector_thread = threading.Thread(
        target=detector_loop,
        daemon=True
    )

    # Start Services
    usb_thread.start()
    detector_thread.start()

    print("===================================")
    print(" Insider Threat Services Started")
    print(" USB Monitor Running")
    print(" File Monitor will start after user login")
    print(" Threat Detector Running")
    print("===================================")