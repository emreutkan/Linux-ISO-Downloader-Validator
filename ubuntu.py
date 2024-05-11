import os
import requests
from bs4 import BeautifulSoup
import re
import requests
from tqdm import tqdm
import hashlib
import subprocess

UBUNTU_KEY_URL = 'https://ubuntu.com/tutorials/how-to-verify-ubuntu#4-retrieve-the-correct-signature-key'



def verify_ISO(directory):
    def calculate_sha256(filename, directory):
        hash_sha256 = hashlib.sha256()
        file_path = os.path.join(directory, filename)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def verify_sha256(directory):
        iso_files = [f for f in os.listdir(directory) if f.endswith('.iso')]
        sha256_file_path = os.path.join(directory, 'SHA256SUMS')

        # Read the SHA256SUMS file to get the correct hashes
        hashes = {}
        with open(sha256_file_path, 'r') as file:
            for line in file:
                parts = line.split()  # This splits on any whitespace, getting all elements
                if len(parts) < 2:
                    continue  # Skip lines that do not have at least two parts
                hash_val = parts[0]
                filename = ' '.join(parts[1:])  # Join the remaining parts back into a filename
                hashes[filename] = hash_val

        # Verify each ISO file
        for iso in iso_files:
            calculated_hash = calculate_sha256(iso, directory)
            expected_hash = hashes.get(iso, None)
            if expected_hash and calculated_hash == expected_hash:
                print(f"Verification successful for {iso}: {calculated_hash}")
                return True
            else:
                print(
                    f"Verification failed for {iso}: {calculated_hash} does not match {expected_hash if expected_hash else 'No expected hash found'}")
                return False
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    cookies = {
        'consent': 'true'  # This might need adjustment based on the actual cookies required by the site
    }
    signature_verification = False
    iso_signature_match = verify_sha256(directory)
    try:
        response = requests.get(UBUNTU_KEY_URL, headers=headers, cookies=cookies)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Attempt to find the <code> tag directly within <pre> tags
        code_tags = soup.find_all('code', class_='lang-plaintext')
        for code in code_tags:
            if "gpg --keyid-format long --keyserver" in code.text:
                gpg_public_key_command = code.text.strip()
                print(f"Found GPG command: {gpg_public_key_command}")
                try:
                    result = subprocess.run(gpg_public_key_command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
                    print("Command output:", result.stdout)
                    try:
                        print("Verifying the ISO...")
                        command = f"gpg --keyid-format long --verify SHA256SUMS.gpg SHA256SUMS"
                        process = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE, cwd=directory)
                        stdout = process.stdout + process.stderr
                        print(stdout + '\n')
                        if "Good signature" in stdout:
                            print(f"Signature verification successful")
                            if iso_signature_match:
                                print('\n')
                                print("The ISO file matches the expected hash values and the signature verification succeeded.")
                                print("The ISO file is authentic and can be trusted.")
                            else:
                                print('\n')
                                print("The ISO file does not match the expected hash values.")
                                print("The ISO file may have been tampered with or corrupted.")
                        else:
                            if iso_signature_match:
                                print('\n')
                                print("The ISO file matches the expected hash values, but the signature verification failed.")
                                print("there might be a problem with GPG Keys or the signature file.")
                                print("Or the ISO file and the signature file are not from the same source.")
                    except subprocess.CalledProcessError as e:
                        print("Error executing command:", e.stderr)
                except subprocess.CalledProcessError as e:
                    print("Error executing command:", e.stderr)
        print("GPG command not found in the expected format.")
    except requests.RequestException as e:
        print(f"Failed to fetch the GPG command due to: {e}")

def fetch_ubuntu_releases():
    url = 'https://releases.ubuntu.com/'
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to fetch the page")
        return []
    soup = BeautifulSoup(response.text, 'html.parser')
    entries = soup.find_all('a', href=True)
    version_pattern = re.compile(r'^\d{2}\.\d+')

    releases = []
    for entry in entries:
        text = entry.text.strip()
        if version_pattern.match(text):
            date_element = entry.find_next_sibling(string=True)
            date_description = date_element.strip() if date_element else "No date found"
            releases.append((text, date_description))
    return releases

def print_releases(releases):
    print("Directory          Date Modified           Description")
    print("-" * 80)
    for release in releases:
        dir_name, date_description = release
        print(f"{dir_name.replace('/', ''):18} {date_description:20}")

import requests
from tqdm import tqdm
import os

def download_file(url, directory, filename):
    response = requests.get(url, stream=True)  # Enable streaming
    if response.status_code == 200:
        total_length = int(response.headers.get('content-length', 0))  # Get content length
        progress_bar = tqdm(total=total_length, unit='B', unit_scale=True, desc=f"Downloading {filename}")

        with open(os.path.join(directory, filename), 'wb') as file:
            for chunk in response.iter_content(chunk_size=1024):  # Use a reasonable chunk size
                if chunk:
                    file.write(chunk)
                    progress_bar.update(len(chunk))  # Update the progress bar
        progress_bar.close()
        if total_length != 0 and progress_bar.n != total_length:
            print("ERROR, something went wrong")
    else:
        print(f"Failed to download {filename}")





# At the end of the `main()` function after the downloads complete:
def main():
    releases = fetch_ubuntu_releases()
    print_releases(releases)

    user_input = input("\nEnter a version (e.g., '24.04'): ")
    user_url = f'https://releases.ubuntu.com/{user_input}/'
    print(f"Navigate to: {user_url}")

    # Create directory
    directory_name = f"ubuntu{user_input.replace('.', '')}"
    os.makedirs(directory_name, exist_ok=True)
    print(f"Directory created: {directory_name}")

    files_to_download = ['SHA256SUMS', 'SHA256SUMS.gpg', f'ubuntu-{user_input}-desktop-amd64.iso']
    for filename in files_to_download:
        file_url = f"https://releases.ubuntu.com/{user_input}/{filename}"
        try:
            download_file(file_url, directory_name, filename)
        except Exception as e:
            print(f"Failed to download {filename}: {str(e)}")
    verify_ISO(directory_name)



if __name__ == "__main__":
    main()
