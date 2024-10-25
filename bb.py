import os
import time
import random
import string
import base64
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
from anticaptchaofficial.recaptchav2proxyless import *
from git import Repo

creds = Credentials.from_authorized_user_file('token.json')

def generate_random_name(length=10):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for i in range(length))

def generate_gmail_plus_email(base_email="cac1md8@qmaul.com"):
    random_string = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    email_parts = base_email.split('@')
    return f"{email_parts[0]}+{random_string}@{email_parts[1]}"

def get_verification_link(creds):
    service = build('gmail', 'v1', credentials=creds)
    results = service.users().messages().list(userId='me', q='from:Atlassian subject:"Verify your email for Atlassian"').execute()
    messages = results.get('messages', [])

    if not messages:
        print("No verification email found.")
        return None

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        if 'payload' in msg_data and 'parts' in msg_data['payload']:
            for part in msg_data['payload']['parts']:
                if part['mimeType'] == 'text/html':
                    data = part['body']['data']
                    decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
                    start_index = decoded_data.find('https://id.atlassian.com/signup/welcome?token=')
                    end_index = decoded_data.find('"', start_index)
                    verification_link = decoded_data[start_index:end_index]
                    return verification_link
    return None

def solve_recaptcha(api_key, site_key, url):
    solver = recaptchaV2Proxyless()
    solver.set_verbose(1)
    solver.set_key(api_key)
    solver.set_website_url(url)
    solver.set_website_key(site_key)
    token = solver.solve_and_return_solution()
    if token != 0:
        print("reCAPTCHA solved: ", token)
        return token
    else:
        print("Failed to solve reCAPTCHA: ", solver.error_code)
        return None

def save_email_and_push_to_github(email):
    file_path = "email.txt"
    
    # Append the email to email.txt
    with open(file_path, "a") as f:
        f.write(f"{email}\n")

    # Commit and push changes to GitHub
    repo = Repo(".")
    repo.index.add([file_path])
    repo.index.commit(f"Add successful email: {email}")
    
    # Use GITHUB_TOKEN from environment to push
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN not found. Please set it in the environment variables.")
        return

    remote_url = f"https://{token}@github.com/USERNAME/REPOSITORY.git"  # Replace USERNAME/REPOSITORY
    repo.remotes.origin.set_url(remote_url)
    
    try:
        repo.remotes.origin.push()
        print(f"Email saved and pushed: {email}")
    except Exception as e:
        print(f"Failed to push to GitHub: {e}")

chrome_options = Options()
chrome_options.add_argument("--remote-allow-origins=*")

api_key = "YOUR-ANTI-CAPTCHA-API-KEY"

def run_signup_task():
    email = generate_gmail_plus_email()
    print(f"Generated email: {email}")
    
    driver = webdriver.Chrome(options=chrome_options)
    driver.set_window_size(1200, 1000)

    driver.get('https://id.atlassian.com/signup')
    time.sleep(10)

    email_input = driver.find_element(By.ID, 'email')
    email_input.send_keys(email)
    time.sleep(3)
    email_input.send_keys(Keys.ENTER)
    time.sleep(5)

    try:
        recaptcha_site_key = driver.find_element(By.CLASS_NAME, 'g-recaptcha').get_attribute('data-sitekey')
        if recaptcha_site_key:
            print(f"Solving reCAPTCHA for {email}...")
            recaptcha_token = solve_recaptcha(api_key, recaptcha_site_key, driver.current_url)
            if recaptcha_token:
                driver.execute_script(f'document.getElementById("g-recaptcha-response").innerHTML="{recaptcha_token}";')
                time.sleep(5)
        else:
            print("No reCAPTCHA found.")
    except NoSuchElementException:
        print("No reCAPTCHA element found on the page.")

    sign_up_successful = False
    while not sign_up_successful:
        try:
            current_url = driver.current_url
            if current_url.startswith("https://id.atlassian.com/signup/verify-email/otp"):
                print("Successfully signed up, verification email has been sent.")
                sign_up_successful = True
                break
            else:
                try:
                    submit_button = driver.find_element(By.ID, 'signup-submit')
                    submit_button.click()
                    time.sleep(10)
                except NoSuchElementException:
                    print("No Sign up button found, skipping...")
                    break
        except Exception as e:
            print(f"An error occurred: {e}")
            break

    if sign_up_successful:
        driver.get('https://id.atlassian.com/login')
        time.sleep(5)

        try:
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, 'username'))
            )
            username_input = driver.find_element(By.ID, 'username')
            username_input.send_keys(email)
            username_input.send_keys(Keys.ENTER)
            time.sleep(5)
        except TimeoutException:
            print("Timeout waiting for username input")
            driver.quit()
            return

        verification_link = get_verification_link(creds)
        if verification_link:
            print(f"Verification link found: {verification_link}")
            driver.get(verification_link)
            time.sleep(10)

            display_name_input = driver.find_element(By.ID, 'displayName-uid2')
            display_name_input.send_keys(generate_random_name())
            time.sleep(3)

            password_input = driver.find_element(By.ID, 'password-uid3')
            password_input.send_keys('giatuye123')
            password_input.send_keys(Keys.ENTER)
            time.sleep(15)

            current_url = driver.current_url
            if current_url.startswith("https://home.atlassian.com/?utm_source=identity"):
                print(f"BERHASIL: {email}")
                save_email_and_push_to_github(email)
            else:
                print(f"Gagal login untuk {email}, cek secara manual.")
        else:
            print("No verification link was found. Please check your email.")

    driver.quit()

run_signup_task()
