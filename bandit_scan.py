import json
import time
import datetime
import tempfile
import xmlrpc.client
import requests
import shutil
import os
import zipfile
import tarfile
import subprocess

BASE_URL = "https://pypi.org/pypi"
INTERVAL_SECONDS = 5
# INITIAL_INTERVAL_SECONDS = INTERVAL_SECONDS
INITIAL_INTERVAL_SECONDS = 1 * 60 * 60
PACKAGES_SCANNED = list()


def log_line(line):
    print(line)
    with open("out.log", "a", encoding="utf-8") as f:
        f.write(line)

def main():
    last_run = datetime.datetime.now() - datetime.timedelta(seconds=INITIAL_INTERVAL_SECONDS)
    while True:
        # The RPC has a habit of listing a package multiple times, so only do each one once
        client = xmlrpc.client.ServerProxy(BASE_URL)
        recentchanges = client.changelog(int(last_run.timestamp()))
        last_run = datetime.datetime.now()
        for entry in recentchanges:
            # Get The download URL
            package_name = entry[0]
            package_ver = entry[1]
            package_key = f"{package_name}{package_ver}".lower()
            if package_key in PACKAGES_SCANNED:
                continue
            else:
                PACKAGES_SCANNED.append(package_key)
            if package_ver is None:
                log_line(f"Found new package: '{package_name}'")
                release_url = f"{BASE_URL}/{package_name}/json"
            else:
                log_line(
                    f"Found updated package: '{package_name}' Version '{package_ver}'"
                )
                release_url = f"{BASE_URL}/{package_name}/{package_ver}/json"
            req_release = requests.get(release_url)
            if not req_release.ok:
                # log_line(f"Failed to get URL {req_release.url}")
                continue
            rel_data = json.loads(req_release.text)
            # Grab the URL of the release, doesn't matter if its the .whl or .tar.gz
            if package_ver is None:
                package_ver = rel_data["info"]["version"]
            package_url = rel_data["releases"][package_ver][0]["url"]
            req_package = requests.get(package_url, stream=True)
            if not req_package.ok:
                log_line(f"Failed to get URL {package_url}")
                continue
            # Write the data to disk
            with tempfile.TemporaryDirectory() as tmpdirname:
                package_filename = os.path.join(tmpdirname,
                                                package_url.split("/")[-1])
                with open(package_filename, "wb") as fp:
                    shutil.copyfileobj(req_package.raw, fp)
                # Extract file
                out_folder = os.path.join(tmpdirname, "out")
                if package_filename.endswith(".tar.gz"):
                    with tarfile.open(package_filename, "r:gz") as ft:
                        def is_within_directory(directory, target):
                            
                            abs_directory = os.path.abspath(directory)
                            abs_target = os.path.abspath(target)
                        
                            prefix = os.path.commonprefix([abs_directory, abs_target])
                            
                            return prefix == abs_directory
                        
                        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                        
                            for member in tar.getmembers():
                                member_path = os.path.join(path, member.name)
                                if not is_within_directory(path, member_path):
                                    raise Exception("Attempted Path Traversal in Tar File")
                        
                            tar.extractall(path, members, numeric_owner=numeric_owner) 
                            
                        
                        safe_extract(ft, path=out_folder)
                elif package_filename.endswith(".whl") or package_url.endswith(
                        ".zip"):
                    with zipfile.ZipFile(package_filename, "r") as fz:
                        fz.extractall(out_folder)
                else:
                    log_line(f"Can't extract file: {package_url}")
                    continue

                # Now Run bandit over it
                out_json = os.path.join(tmpdirname, "out.json")
                tests = [
                    "B102",   # exec_used
                    "B104",   # hardcoded_bind_all_interfaces
                    "B307",   # exec
                    "B501",   # request_with_no_cert_validation
                    "B601",   # paramiko_calls
                    "B602",   # subprocess_popen_with_shell_equals_true
                    "B603",   # subprocess_without_shell_equals_true
                    "B604",   # any_other_function_with_shell_equals_true
                    "B605",   # start_process_with_a_shell
                    "B606",   # start_process_with_no_shell
                    "B607"   # start_process_with_partial_path
                ]
                test_string = ",".join(tests)
                subprocess.run(
                    f"bandit -t {test_string} -r -f json -o {out_json} {out_folder}",
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
                with open(out_json, "r") as f:
                    bandit_out = json.load(f)
                if len(bandit_out["results"]) != 0:
                    log_line(f"[****] FOUND EVAL IN: {release_url}")
                    for result in bandit_out["results"]:
                        filename = result["filename"].replace(out_folder, "")[1:]
                        issue = result["issue_text"]
                        log_line(f"{filename}: {issue}")
                        log_line(result["code"])
                    log_line("----------------------------")
        else:
            pass
            log_line("No new entries, sleeping...")
        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
