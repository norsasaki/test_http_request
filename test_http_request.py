# -*- coding: utf-8 -*-
import sys
import shutil
import os
import pathlib
import re
import time
from functools import reduce
import subprocess
import multiprocessing
import requests
import yaml
import logging
import logging.handlers
from tabulate import tabulate
from dictknife import deepmerge

# define global variables
_filename = os.path.basename(__file__)
filename = os.path.splitext(_filename)[0]
subdir = f"{filename}"
config_file = str(pathlib.Path(f"./{subdir}/{filename}.yaml"))
data_file = str(pathlib.Path(f"./{subdir}/uri_list.txt"))
work_dir = str(pathlib.Path(f"./{subdir}/tmp"))

# define logger
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
rh = logging.handlers.RotatingFileHandler(
        f'{filename}.log', 
        encoding='utf-8',
        maxBytes=1024000,
        backupCount=2
    )
log.addHandler(rh)


def construct_curl(config, path):

    # initialize config
    default = {
        "cmd": f"curl -sS -k ",
        "proto": "https",
        "domain": "www.google.com",
        "user-agent": "Mozilla/5.0 from test_request",
        "header": [],
        "write_out": ["http_code", "time_total"],
        "cookie": []
    }
    default.update(config)

    options = []
    options.append(["--output-dir", work_dir])
    options.append(["--output", os.getpid()])

    # make cookie
    cookie = reduce(lambda a, b: a + f"{b[0]}={b[1]};", default['cookie'], "")
    options.append(["--cookie", cookie])

    # user-agent
    options.append(["--user-agent", default['user-agent']])

    # make write_out
    write_out_options = [
         "content_type", "errormsg", "exitcode", "filename_effective", "ftp_entry_path", "http_code", "http_connect", "http_version", "local_ip", "local_port", "method", "num_connects", "num_headers", "num_redirects", "onerror", "proxy_ssl_verify_result", "redirect_url", "referer", "remote_ip", "remote_port", "response_code", "scheme", "size_download", "size_header", "size_request", "size_upload", "speed_download", "speed_upload", "ssl_verify_result", "stderr", "stdout", "time_appconnect", "time_connect", "time_namelookup", "time_pretransfer", "time_redirect", "time_starttransfer", "time_total", "url", "url_effective", "urlnum"
    ]
    write_out = "\\n" + reduce(lambda a, b: a + b + "# %{" + b + "}\\n", filter(lambda x: x in write_out_options, default["result"]), "")
    options.append(["--write-out", write_out])

    # construct request header
    for header in default['header']:
        options.append(["--header", f"{header[0]}: {header[1]}"])

    # construct uri
    if re.match("\S+://", path):
        uri = path
    else:
        uri = f"{default['proto']}://{default['domain']}{path}"
    options.append(["--dump-header -", uri])

    # make command
    return  reduce(lambda a, b: f'{a} {b[0]} "{b[1]}"', options, default['cmd'])


def curl(command):
    log.debug(command)
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if not result.returncode == 0:
        log.error(result.stderr)
        
    res_header = {}
    res_command = {}
    html = None
    for line in result.stdout.split("\n"):
        match = re.findall(r'^(HTTP\S+).+(\d\d\d)\s*$', line)
        if len(match) != 0:
            continue

        match = re.findall(r'^(\S+): (.+)$', line)
        if len(match) != 0:
            for array in match:
                res_header[array[0]] = array[1]
            continue

        match = re.findall(r'^(\S+)# (.+)$', line)
        if len(match) != 0:
            for array in match:
                res_command[array[0]] = array[1]
            continue

    if "content-type" in res_header.keys() and re.match("text/html", res_header["content-type"]):
        with open(str(pathlib.Path(f"./{subdir}/tmp/{os.getpid()}")), "r", encoding="utf-8") as f:
            html = f.read()

    return {
        "res_header": res_header,
        "res_command": res_command,
        "html": html
    }


# define worker
def worker(uri, config, result_list):

    command = construct_curl(config, uri)
    result = curl(command)

    log.debug(f"PID: {os.getpid()}")
    log.debug("res_header\n" + yaml.dump(result["res_header"]))
    log.debug("res_command\n" + yaml.dump(result["res_command"]))

    output = []
    for key in config["result"]:
        if key in result["res_header"]:
            output.append(result["res_header"][key])
            continue

        if key in result["res_command"]:
            output.append(result["res_command"][key])
            continue

        match = re.findall(r'^m(.)(.+)\1$', key)
        if len(match) != 0 and result["html"] is not None:
            regexp = match[0][1]
            match = re.findall(regexp, result["html"], re.IGNORECASE)
            if match:
                output.append(match[0])
            else:
                output.append("")
            continue

        # append blank if key doesn't match all condition
        output.append("N/A")

    
    time.sleep(config["config"]["wait"])
    return result_list.append(output)


if __name__ == "__main__":
    if not os.path.exists(subdir): 
        os.mkdir(subdir)
    if os.path.exists(work_dir): 
        shutil.rmtree(work_dir)
    if not os.path.exists(work_dir): 
        os.mkdir(work_dir)

    with open(config_file, "r", encoding="utf-8") as file:
        config = {
            "config": {"logLevel": 1, "process": 8, "wait": 0.5}
        }
        config = deepmerge(config, yaml.safe_load(file))

    with open(data_file, "r", encoding="utf-8") as f:
        uris = f.read().split("\n")
        uris = list(filter(lambda a: not re.match("^$|^#", a), uris))

    while len(uris) != 0:
        with multiprocessing.Manager() as manager:
            # list which is pushed to worker result
            result_list = manager.list()

            # process list
            process = []

            for i in range(config["config"]["process"]):
                if len(uris) == 0:
                    break

                process.append(multiprocessing.Process(target=worker, args=(uris.pop(0), config, result_list)))
                process[i].start()

            for p in process:
                p.join()

            print(tabulate(result_list, headers=config["result"]))


