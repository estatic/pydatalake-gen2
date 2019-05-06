import logging
import threading
from collections import OrderedDict, defaultdict
from random import seed

import requests
import hmac
from datetime import datetime
import hashlib
import base64
import os
from urllib.parse import urlparse
from urllib.parse import quote

from requests import Request
from requests.auth import AuthBase

from functools import lru_cache, _make_key

LEASE_ACTIONS = ["acquire", "break", "change", "renew", "release"]
LOGGER = logging.getLogger("pydatalake.gen2")
LOGGER.setLevel(logging.DEBUG)

sleep_length = 5
seed(123)
arg_range = 3
num_tasks = 5

def threadsafe_lru(func):
    func = lru_cache()(func)
    lock_dict = defaultdict(threading.Lock)

    def _thread_lru(*args, **kwargs):
        key = _make_key(args, kwargs, typed=False)
        with lock_dict[key]:
            return func(*args, **kwargs)

    return _thread_lru


class SharedKeyAuth(AuthBase):
    """Attaches HTTP Shared Key Authentication to the given Request object."""

    def __init__(self, account, account_key):
        self.account = account
        self.account_key = account_key

    def __call__(self, r: Request):
        print(f"Requesting... {r.url}")

        required_headers = {}
        for key, val in r.headers.items():
            if key in ["Content-Length", "Content-Type"] or key.startswith("x-ms"):
                required_headers[key] = val
        r.headers = OrderedDict(required_headers)
        r.headers["x-ms-date"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        r.headers["x-ms-version"] = "2018-11-09"

        parsed_url = urlparse(r.url)
        qparams = parsed_url.query.split("&")
        params = {}
        for param in qparams:
            key = param[:param.index("=")]
            val = param[param.index("=")+1:]
            params[key] = val
        params = "\n".join([f"{quote(key.lower())}:{val}"
                            for key, val in sorted(params.items(), key=lambda x: x[0])])

        canonicalized_headers = [f"{key.lower()}:{val}"
                                 for key, val in sorted(r.headers.items(),
                                                        key=lambda x: x[0]) if key.startswith("x-ms")]

        canonicalized_headers = "\n".join(canonicalized_headers)

        length = r.headers.get("Content-Length", "0")
        if length == "0":
            length = ""

        content_type = r.headers.get("Content-Type", "")

        inputvalue = f"{r.method}\n" \
                     "\n" \
                     "\n" \
                     f"{length}\n" \
                     "\n" \
                     f"{content_type}\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     f"{canonicalized_headers}\n" \
                     f"/{self.account}{parsed_url.path}\n{params}"

        print(inputvalue)
        dig = hmac.new(
            base64.b64decode(self.account_key),
            msg=inputvalue.encode("utf-8"), digestmod=hashlib.sha256
        ).digest()
        signature = base64.b64encode(dig).decode()
        r.headers["Authorization"] = f"SharedKey {self.account}:{signature}"

        return r


class BasicClient:

    def __init__(self, storage_account, shared_key, dns_suffix=None, account=None):
        self.storage_account = storage_account
        if dns_suffix is None:
            self.dns_suffix = "dfs.core.windows.net"
        else:
            self.dns_suffix = dns_suffix

        if account is None:
            self.account = storage_account
        else:
            self.account = account
        self.shared_key = shared_key

    def make_request(self, method, url, headers=None, data=None):
        response = requests.request(method, url, headers=headers, auth=SharedKeyAuth(self.account, self.shared_key),
                                    data=data)
        return response


class FileSystemClient(BasicClient):
    def __init__(self, storage_account, shared_key, dns_suffix=None, account=None):
        super().__init__(storage_account, shared_key, dns_suffix, account)

    def create_filesystem(self, file_path: str, timeout: int = None, properties: dict = None):
        if file_path.startswith("/"):
            file_path = file_path[1:]
        headers = {}
        if properties:
            headers["x-ms-properties"] = ", ".join([f"{key}={val}" for key, val in properties.items()])
        if timeout is None:
            timeout = 60
        response = self.make_request("PUT",
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{file_path}?resource=filesystem&timeout={timeout}",
                                     headers=headers)
        if response.status_code == 201:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def delete_filesystem(self, file_path: str, timeout: int = None):
        if file_path.startswith("/"):
            file_path = file_path[1:]

        params = ["resource=filesystem"]

        if timeout:
            params.append(f"timeout={timeout}")
        query = "&".join(params)

        response = self.make_request("DELETE",
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{file_path}?{query}",
                                     headers={})
        if response.status_code == 202:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def list_filesystem(self, prefix: str = None, continuation: str = None, max_results: int = None,
                        timeout: str = None):
        params = ["resource=account"]
        if prefix:
            params.append(f"prefix={prefix}")
        if timeout:
            params.append(f"timeout={timeout}")
        if continuation:
            params.append(f"continuation={continuation}")
        if max_results:
            params.append(f"maxResults={max_results}")
        query = "&".join(params)
        headers = {}
        response = self.make_request("GET",
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"?{query}",
                                     headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def get_properties_filesystem(self, path: str, timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        if timeout is None:
            timeout = 60

        response = self.make_request("HEAD",
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{path}?resource=filesystem&timeout={timeout}",
                                     headers={})
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def set_properties_filesystem(self, path: str, properties: dict, timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        if timeout is None:
            timeout = 60
        headers = {}
        if properties:
            headers["x-ms-properties"] = ", ".join([f"{key}={val}" for key, val in properties.items()])

        response = self.make_request("PATCH",
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{path}?resource=filesystem&timeout={timeout}",
                                     headers=headers)
        if response.status_code == 200:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")


class PathClient(BasicClient):
    def create_path(self, filesystem, path, resource: str = None, continuation: str = None, mode: str = None,
                    timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        if resource is None:
            resource = "file"
        if mode is None:
            mode = "posix"

        params = []
        if timeout:
            params.append(f"timeout={timeout}")
        if continuation:
            params.append(f"continuation={continuation}")
        if mode:
            params.append(f"mode={mode}")
        if resource:
            params.append(f"resource={resource}")
        query = "&".join(params)

        response = self.make_request("PUT", f"https://{self.storage_account}.{self.dns_suffix}/"
                                            f"{filesystem}/{path}"
                                            f"?{query}")
        if response.status_code == 201:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def rename_file(self, source_path: str, destination_path: str, timeout: int = None, content_length: int = None):
        if destination_path.startswith("/"):
            destination_path = destination_path[1:]
        if not source_path.startswith("/"):
            source_path = f"/{source_path}"

        params = []
        if timeout:
            params.append(f"timeout={timeout}")
        params.append("mode=posix")

        query = "&".join(params)

        root, filename = os.path.split(source_path)
        filesystem, *directories = root[1:].split("/")

        if directories is None:
            directories = []

        if content_length is None:
            paths = self.list_path(filesystem, directory='/'.join(directories), recursive=False)
            paths = [p for p in paths["paths"] if p["name"].endswith(filename) and source_path.endswith(p["name"])]

            if len(paths) == 0:
                raise Exception("File not found")

            content_length = paths[0]["contentLength"]

        headers = {"x-ms-rename-source": source_path, "Content-Length": content_length,
                   "Content-Type": "application/octet-stream", "x-ms-content-type": "application/octet-stream"}

        response = self.make_request("PUT", f"https://{self.storage_account}.{self.dns_suffix}/"
                                            f"{destination_path}"
                                            f"?{query}", headers=headers)
        if response.status_code == 201:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def delete_path(self, filesystem, path, resource, recursive=False, continuation: str = None, timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        if resource is None:
            resource = "file"
        params = []
        if timeout:
            params.append(f"timeout={timeout}")
        if continuation:
            params.append(f"continuation={continuation}")
        if recursive:
            params.append(f"recursive=true")
        else:
            params.append(f"recursive=false")
        if resource:
            params.append(f"resource={resource}")
        query = "&".join(params)

        response = self.make_request("DELETE", f"https://{self.storage_account}.{self.dns_suffix}/"
                                               f"{filesystem}/{path}"
                                               f"?{query}")
        if response.status_code == 200:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def get_properties_path(self, filesystem, path, action: str = None, upn: bool = False, timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        params = []
        if action is None:
            params.append("action=getStatus")
        else:
            params.append(f"action={action}")
        if timeout:
            params.append(f"timeout={timeout}")
        if upn:
            params.append(f"upn=true")
        else:
            params.append(f"upn=false")
        query = "&".join(params)

        response = self.make_request("HEAD", f"https://{self.storage_account}.{self.dns_suffix}/"
                                             f"{filesystem}/{path}"
                                             f"?{query}")
        if response.status_code == 200:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def lease_path(self, filesystem, path, action, lease_id: str = None, duration: int = None, timeout: int = None):
        if action not in LEASE_ACTIONS:
            raise Exception("Action variable is not valid")

        if path.startswith("/"):
            path = path[1:]

        params = []

        if timeout:
            params.append(f"timeout={timeout}")
        query = "&".join(params)

        headers = {"x-ms-lease-action": action}
        if action in ["renew", "change", "release"]:
            assert lease_id
            headers["x-ms-lease-id"] = lease_id

        if action == "acquire":
            assert lease_id
            assert duration
            headers["x-ms-proposed-lease-id"] = lease_id
            headers["x-ms-lease-duration"] = str(duration)

        response = self.make_request("POST", f"https://{self.storage_account}.{self.dns_suffix}/"
                                             f"{filesystem}/{path}"
                                             f"?{query}", headers)
        if response.status_code == 200:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    @threadsafe_lru
    def list_path(self, filesystem, directory: str = None, recursive: bool = True, continuation: str = None,
                  max_results: int = 5000, upn: bool = None, timeout: int = None, options: dict = None):
        if filesystem.startswith("/"):
            filesystem = filesystem[1:]

        params = []
        if timeout:
            params.append(f"timeout={timeout}")
        if continuation:
            params.append(f"continuation={quote(continuation)}")
        if directory:
            params.append(f"directory={directory}")
        if max_results:
            params.append(f"maxResults={max_results}")

        if recursive:
            params.append(f"recursive=true")
        else:
            params.append(f"recursive=false")
        if upn is not None:
            if upn:
                params.append(f"upn=true")
            else:
                params.append(f"upn=false")

        params.append("resource=filesystem")
        query = "&".join(params)

        response = self.make_request("GET", f"https://{self.storage_account}.{self.dns_suffix}/"
                                            f"{filesystem}"
                                            f"?{query}", headers=options)
        if response.status_code == 200:
            paths = response.json()
            if response.headers.get("x-ms-continuation", None) is not None:
                paths["continuation"] = response.headers.get("x-ms-continuation")
            if response.headers.get("x-ms-request-id", None) is not None:
                paths["request-id"] = response.headers.get("x-ms-request-id")
            return paths
        elif response.status_code == 404:
            return {"paths": []}
        else:
            raise Exception(f"{response.status_code}: {response.text}\n{directory}")

    def read_path(self, filesystem: str, path: str, timeout: int = None):
        if path.startswith("/"):
            path = path[1:]

        params = []
        if timeout:
            params.append(f"timeout={timeout}")

        query = "&".join(params)

        response = self.make_request("GET", f"https://{self.storage_account}.{self.dns_suffix}/"
                                            f"{filesystem}/{path}"
                                            f"?{query}")
        if response.status_code == 200:
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")

    def update_path(self, filesystem: str, path: str, action: str, data = None, position: int = 0,
                    retain_uncommitted_data: bool = None, timeout: int = None, lease_id: str = None, close: bool = None):
        if action not in ["append", "flush", "setProperties", "setAccessControl"]:
            raise Exception("Action is not valid")
        if path.startswith("/"):
            path = path[1:]

        params = []
        if timeout:
            params.append(f"timeout={timeout}")
        if action:
            params.append(f"action={action}")
        if position is not None:
            params.append(f"position={position}")
        if close:
            params.append(f"close={close}")
        if action == "flush":
            if retain_uncommitted_data:
                params.append(f"retainUncommittedData=true")
            else:
                params.append(f"retainUncommittedData=false")

        query = "&".join(params)

        headers = {}
        if action == "flush":
            headers["Content-Length"] = str(0)
        if action == "append":
            headers["Content-Length"] = str(len(data))
        if lease_id:
            headers["x-ms-lease-id"] = lease_id

        response = self.make_request("PATCH", f"https://{self.storage_account}.{self.dns_suffix}/"
                                              f"{filesystem}/{path}"
                                              f"?{query}", headers=headers, data=data)
        if response.status_code in (200, 202):
            return response.headers
        else:
            raise Exception(f"{response.status_code}: {response.text}")


class DataLakeGen2Client(FileSystemClient, PathClient):
    pass
