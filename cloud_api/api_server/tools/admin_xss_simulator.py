# This script is an XSS payload simulator for admin support interface testing.
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

def run_admin_simulator():
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Admin XSS simulator running...", flush=True)
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(options=options)
    try:
        driver.get("http://localhost:5000/admin/support")
        time.sleep(5)
    finally:
        driver.quit()

if __name__ == "__main__":
    run_admin_simulator()