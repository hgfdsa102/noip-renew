#!/usr/bin/env python3
# Copyright 2017 loblab
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os
import re
import subprocess
import sys
import time
from datetime import date
from datetime import datetime, timezone
from datetime import timedelta
from functools import wraps
from traceback import format_exc

from pyotp import *
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from slack_sdk import WebClient

VERSION = "2.0.3"
DOCKER = False


class SingletonType(type):
    def __call__(cls, *args, **kwargs):
        try:
            return cls.__instance
        except AttributeError:
            cls.__instance = super(SingletonType, cls).__call__(*args, **kwargs)
            return cls.__instance


class SlackDebugLog(metaclass=SingletonType):
    def __init__(self, time: bool = True, slack_token: str = "", slack_channel: str = ""):
        self.token = slack_token
        self.channel = slack_channel
        self.client = WebClient(token=self.token)

        self.address = None
        self.hostname = None

        self.time = time

    def _formatter(self, message: str, is_code: bool = True) -> str:
        utc_now = datetime.now(timezone.utc)
        kst = utc_now + timedelta(hours=9)
        timestamp = kst.strftime("%Y-%m-%d %H:%M:%S")

        format = []
        if self.time:
            format.append(f"[{timestamp}]")

        if is_code:
            return "".join(format) + f"\n```{message}```"
        else:
            return "".join(format) + f"\n{message}"

    def logging(self, raise_exception: bool = True, alter_return: Any = None):
        def wrapper(func):
            @wraps(func)
            def decorator(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if raise_exception:
                        self.client.chat_postMessage(
                            channel=self.channel,
                            text=self._formatter(f"{format_exc()}"),
                        )
                        raise e
                    else:
                        self.client.chat_postMessage(
                            channel=self.channel,
                            text=self._formatter(
                                f"{format_exc()} > alter_return: {alter_return}"
                            ),
                        )
                        if callable(alter_return):
                            return alter_return()
                        else:
                            return alter_return

            return decorator

        return wrapper

    def retry(self, count: int = 2, delay: int = 10):
        def wrapper(func):
            @wraps(func)
            def decorator(*args, **kwargs):
                for try_count in range(count):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        self.client.chat_postMessage(
                            channel=self.channel,
                            text=self._formatter(
                                f"{format_exc()} > try_count: {try_count}"
                            ),
                        )
                        if try_count == count - 1:
                            raise e
                    time.sleep(delay)

            return decorator

        return wrapper

    def message(self, message: str = "", display_name: bool = False):
        def wrapper(func):
            @wraps(func)
            def decorator(*args, **kwargs):
                function_name = ""
                if display_name:
                    function_name = func.__name__
                self.client.chat_postMessage(
                    channel=self.channel,
                    text=self._formatter(f"{function_name}{message}"),
                )
                return func(*args, **kwargs)

            return decorator

        return wrapper

    def info(self, message: str = ""):
        self.client.chat_postMessage(
            channel=self.channel,
            text=self._formatter(f"{message}"),
        )


slack_token = str(os.environ.get('SLACK_TOKEN', ''))
slack_channel = str(os.environ.get('SLACK_CHANNEL', ''))
if slack_token and slack_channel:
    LOG = SlackDebugLog(time=True, slack_token=slack_token, slack_channel=slack_channel)
else:
    sys.exit("slack env not exist")


class Logger:
    def __init__(self, level):
        self.level = 0 if level is None else level

    def log(self, msg, level=None):
        self.time_string_formatter = time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(time.time()))
        self.level = self.level if level is None else level
        if self.level > 0:
            print(f"[{self.time_string_formatter}] - {msg}")


class Robot:
    USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0"
    LOGIN_URL = "https://www.noip.com/login"
    HOST_URL = "https://my.noip.com/dynamic-dns"

    def __init__(self, username, password, totp_secret, debug, docker):
        self.debug = debug
        self.docker = docker
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.browser = self.init_browser()
        self.logger = Logger(debug)

    @staticmethod
    def init_browser():
        options = webdriver.ChromeOptions()
        # added for Raspbian Buster 4.0+ versions. Check https://www.raspberrypi.org/forums/viewtopic.php?t=258019 for reference.
        options.add_argument("lang=en-US")
        options.add_argument("accept-language=ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7")
        options.add_argument("disable-features=VizDisplayCompositor")
        options.add_argument("headless")
        options.add_argument("no-sandbox")  # need when run in docker
        options.add_argument("window-size=1200x800")
        options.add_argument(f"user-agent={Robot.USER_AGENT}")
        options.add_argument("disable-gpu")
        if 'https_proxy' in os.environ:
            options.add_argument("proxy-server=" + os.environ['https_proxy'])
        browser = webdriver.Chrome(options=options)
        browser.set_page_load_timeout(90)  # Extended timeout for Raspberry Pi.
        return browser

    @LOG.logging()
    def login(self):
        self.logger.log(f"Opening {Robot.LOGIN_URL}...")
        LOG.info(f"Opening {Robot.LOGIN_URL}...")
        self.browser.get(Robot.LOGIN_URL)

        try:
            elem = WebDriverWait(self.browser, 10).until(EC.presence_of_element_located((By.ID, "content")))
        except:
            raise Exception("Login page could not be loaded")

        if self.debug > 1:
            # self.browser.save_screenshot("debug1.png")
            pass

        self.logger.log("Logging in...")
        LOG.info("Logging in...")

        ele_usr = elem.find_element(By.NAME, "username")
        ele_pwd = elem.find_element(By.NAME, "password")

        ele_usr.send_keys(self.username)

        # If running on docker, password is not base64 encoded
        if self.docker:
            ele_pwd.send_keys(self.password)
        else:
            ele_pwd.send_keys(base64.b64decode(self.password).decode('utf-8'))
        ele_pwd.send_keys(Keys.ENTER)

        try:
            elem = WebDriverWait(self.browser, 10).until(EC.presence_of_element_located((By.ID, "verificationCode")))
        except:
            raise Exception("2FA verify page could not load")

        if self.debug > 1:
            # self.browser.save_screenshot("debug-otp.png")
            pass

        self.logger.log("Sending OTP...")
        LOG.info("Sending OTP...")

        ele_challenge = elem.find_element(By.NAME, "challenge_code")
        self.browser.execute_script("arguments[0].focus();", ele_challenge)
        ActionChains(self.browser).send_keys(TOTP(self.totp_secret).now()).perform()
        ActionChains(self.browser).send_keys(Keys.ENTER).perform()

        # After Loggin browser loads my.noip.com page - give him some time to load
        # 'noip-cart' element is near the end of html, so html have been loaded
        try:
            elem = WebDriverWait(self.browser, 10).until(EC.presence_of_element_located((By.ID, "noip-cart")))
        except:
            raise Exception("my.noip.com page could not load")

        if self.debug > 1:
            # self.browser.save_screenshot("debug2.png")
            pass

    @LOG.logging()
    def update_hosts(self):
        count = 0

        self.open_hosts_page()
        self.browser.implicitly_wait(5)
        iteration = 1
        next_renewal = []

        hosts = self.get_hosts()
        for host in hosts:
            host_link = self.get_host_link(host, iteration)  # This is for if we wanted to modify our Host IP.
            host_name = host_link.text
            expiration_days = self.get_host_expiration_days(host, iteration)
            if expiration_days <= 7:
                host_button = self.get_host_button(host, iteration)  # This is the button to confirm our free host
                self.update_host(host_button, host_name)
                expiration_days = self.get_host_expiration_days(host, iteration)
                next_renewal.append(expiration_days)
                self.logger.log(f"{host_name} expires in {str(expiration_days)} days")
                LOG.info(f"{host_name} expires in {str(expiration_days)} days")
                count += 1
            else:
                next_renewal.append(expiration_days)
                self.logger.log(f"{host_name} expires in {str(expiration_days)} days")
                LOG.info(f"{host_name} expires in {str(expiration_days)} days")
            iteration += 1
        # self.browser.save_screenshot("results.png")
        self.logger.log(f"Confirmed hosts: {count}", 2)
        LOG.info(f"Confirmed hosts: {count}")
        nr = min(next_renewal) - 6
        today = date.today() + timedelta(days=nr)
        day = str(today.day)
        month = str(today.month)
        if not self.docker:
            try:
                subprocess.call(['/usr/local/bin/noip-renew-skd.sh', day, month, "True"])
            except (FileNotFoundError, PermissionError):
                self.logger.log(f"noip-renew-skd.sh missing or not executable, skipping crontab configuration")
                LOG.info(f"noip-renew-skd.sh missing or not executable, skipping crontab configuration")
        return True

    @LOG.logging()
    def open_hosts_page(self):
        self.logger.log(f"Opening {Robot.HOST_URL}...")
        LOG.info(f"Opening {Robot.HOST_URL}...")
        try:
            self.browser.get(Robot.HOST_URL)
        except TimeoutException as e:
            # self.browser.save_screenshot("timeout.png")
            self.logger.log(f"Timeout: {str(e)}")
            LOG.info(f"Timeout: {str(e)}")

    @LOG.logging()
    def update_host(self, host_button, host_name):
        self.logger.log(f"Updating {host_name}")
        host_button.click()
        self.browser.implicitly_wait(3)
        intervention = False
        try:
            if self.browser.find_elements(By.XPATH, "//h2[@class='big']")[0].text == "Upgrade Now":
                intervention = True
        except:
            pass

        if intervention:
            raise Exception("Manual intervention required. Upgrade text detected.")

        # self.browser.save_screenshot(f"{host_name}_success.png")

    @staticmethod
    @LOG.logging()
    def get_host_expiration_days(host, iteration):
        try:
            host_remaining_days = host.find_element(By.XPATH, ".//a[contains(@class,'no-link-style')]")
        except:
            return 0
        if host_remaining_days.get_attribute("data-original-title") is not None:
            regex_match = re.search("\\d+", host_remaining_days.get_attribute("data-original-title"))
        else:
            regex_match = re.search("\\d+", host_remaining_days.text)
        if regex_match is None:
            raise Exception("Expiration days label does not match the expected pattern in iteration: {iteration}")
        expiration_days = int(regex_match.group(0))
        return expiration_days

    @staticmethod
    @LOG.logging()
    def get_host_link(host, iteration):
        return host.find_element(By.XPATH, ".//a[@class='link-info cursor-pointer notranslate']")

    @staticmethod
    @LOG.logging()
    def get_host_button(host, iteration):
        return host.find_element(By.XPATH, "//td[6]/button[contains(@class, 'btn-success')]")

    @LOG.logging()
    def get_hosts(self):
        host_tds = self.browser.find_elements(By.XPATH, "//td[@data-title=\"Host\"]")
        if len(host_tds) == 0:
            raise Exception("No hosts or host table rows not found")
        return host_tds

    @LOG.logging()
    def run(self):
        rc = 0
        self.logger.log(f"No-IP renew script version {VERSION}")
        self.logger.log(f"Debug level: {self.debug}")
        LOG.info(f"No-IP renew script version {VERSION}")
        LOG.info(f"Debug level: {self.debug}")

        try:
            self.login()
            if not self.update_hosts():
                rc = 3
        except Exception as e:
            self.logger.log(str(e))
            LOG.info(str(e))
            # self.browser.save_screenshot("exception.png")
            if not self.docker:
                try:
                    subprocess.call(['/usr/local/bin/noip-renew-skd.sh', "*", "*", "False"])
                except (FileNotFoundError, PermissionError):
                    self.logger.log(f"noip-renew-skd.sh missing or not executable, skipping crontab configuration")
                    LOG.info(f"noip-renew-skd.sh missing or not executable, skipping crontab configuration")
            rc = 2
        finally:
            self.browser.quit()
        return rc


def main(argv=None):
    # check if we're running on docker
    DOCKER = os.environ.get("CONTAINER", "").lower() in ("yes", "y", "on", "true", "1")
    if DOCKER:
        print("Running inside docker container")
        noip_username = os.environ.get('NOIP_USERNAME', '')
        noip_password = os.environ.get('NOIP_PASSWORD', '')
        noip_totp = os.environ.get('NOIP_2FA_SECRET_KEY', '')
        debug = int(os.environ.get('NOIP_DEBUG', 1))
        if not any([noip_username, noip_password, noip_totp]):
            sys.exit(
                'You are using docker, you need to specify the required parameters as environment varialbes, check the documentation.')

    else:
        noip_username, noip_password, noip_totp, debug = get_args_values(argv)

    return (Robot(noip_username, noip_password, noip_totp, debug, DOCKER)).run()


def get_args_values(argv):
    if argv is None:
        argv = sys.argv
    if len(argv) < 4:
        print(
            f"Usage: {argv[0]} <noip_username> <noip_base64encoded_password> <2FA_secret_key> [<debug-level>] ")
        sys.exit(1)

    noip_username = argv[1]
    noip_password = argv[2]
    noip_totp = argv[3]
    debug = 1
    if len(argv) > 3:
        debug = int(argv[4])
    return noip_username, noip_password, noip_totp, debug


if __name__ == "__main__":
    sys.exit(main())
