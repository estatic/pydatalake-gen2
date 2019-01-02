import requests
import uuid
import hmac
from datetime import datetime
import hashlib
import base64
from urllib.parse import urlparse


class BasicClient:

    def __init__(self, storage_account, shared_key, dns_suffix=None, account=None):
        self.storage_account = storage_account
        if dns_suffix is None:
            self.dns_suffix = 'dfs.core.windows.net'
        else:
            self.dns_suffix = dns_suffix

        if account is None:
            self.account = storage_account
        else:
            self.account = account
        self.shared_key = shared_key

    def make_request(self, method, url, headers):
        headers['x-ms-client-request-id'] = str(uuid.uuid4())
        headers["x-ms-date"] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers["x-ms-version"] = "2015-02-21"
        parsed_url = urlparse(url)
        sign = self.__create_sign(parsed_url, method, headers)
        headers['Authorization'] = f"SharedKey {self.account}:{sign}"
        response = requests.request(method,
                                    url,
                                    headers=headers)
        return response

    def __create_sign(self, input: str, method: str, headers: dict):
        inputvalue = f"{method}\n" \
                     f"\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     "\n" \
                     f"x-ms-client-request-id:{headers['x-ms-client-request-id']}\n" \
                     f"x-ms-date:{headers['x-ms-date']}\n" \
                     f"x-ms-version:{headers['x-ms-version']}\n" \
                     f"{input}"
        dig = hmac.new(inputvalue.encode('utf-8'), msg=self.shared_key.encode('utf-8'),
                       digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()


class FileSystemClient(BasicClient):
    def __init__(self, storage_account, shared_key, dns_suffix=None, account=None):
        super().__init__(storage_account, shared_key, dns_suffix, account)

    def create_filesystem(self, file_path: str, timeout: int = None, properties: dict = None):
        if file_path.startswith('/'):
            file_path = file_path[1:]
        headers = {}
        if properties:
            headers['x-ms-properties'] = ', '.join([f"{key}={val}" for key, val in properties.items()])
        if timeout is None:
            timeout = 60
        response = self.make_request('PUT',
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{file_path}?resource=filesystem&timeout={timeout}",
                                     headers=headers)
        if response.status_code == 201:
            return response.headers()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")

    def delete_filesystem(self, file_path: str, timeout: int = None):
        if file_path.startswith('/'):
            file_path = file_path[1:]
        response = self.make_request('DELETE',
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{file_path}?resource=filesystem&timeout={timeout}",
                                     headers={})
        if response.status_code == 202:
            return response.headers()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")

    def list_filesystem(self, prefix: str = None, continuation: str = None, max_results: int = None,
                        timeout: str = None):
        params = []
        params.append('resource=account')
        if prefix:
            params.append(f'prefix={prefix}')
        if timeout:
            params.append(f'timeout={timeout}')
        if continuation:
            params.append(f'continuation={continuation}')
        if max_results:
            params.append(f'maxResults={max_results}')
        query = '&'.join(params)
        headers = {}
        response = self.make_request('GET',
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"?{query}",
                                     headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")

    def get_properties_filesystem(self, path: str, timeout: int = None):
        if path.startswith('/'):
            path = path[1:]

        if timeout is None:
            timeout = 60

        response = self.make_request('HEAD',
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{path}?resource=filesystem&timeout={timeout}",
                                     headers={})
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")

    def set_properties_filesystem(self, path: str, properties: dict, timeout: int = None):
        if path.startswith('/'):
            path = path[1:]

        if timeout is None:
            timeout = 60
        headers = {}
        if properties:
            headers['x-ms-properties'] = ', '.join([f"{key}={val}" for key, val in properties.items()])

        response = self.make_request('PATCH',
                                     f"https://{self.storage_account}.{self.dns_suffix}/"
                                     f"{path}?resource=filesystem&timeout={timeout}",
                                     headers=headers)
        if response.status_code == 200:
            return response.headers()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")


class PathClient(BasicClient):
    def create_path(self, filesystem, path, resource, continuation: str, mode: str, timeout: int = None):
        if path.startswith('/'):
            path = path[1:]

        if resource is None:
            resource = 'file'
        params = []
        if timeout:
            params.append(f'timeout={timeout}')
        if continuation:
            params.append(f'continuation={continuation}')
        if mode:
            params.append(f'mode={mode}')
        if resource:
            params.append(f'resource={resource}')
        query = '&'.join(params)

        response = self.make_request('PUT', f"https://{self.storage_account}.{self.dns_suffix}/"
                                            f"{filesystem}/{path}"
                                            f"?{query}")
        if response.status_code == 200:
            return response.headers()
        else:
            raise Exception(f"{response.status_code}: {response.text()}")


class DataLakeGen2Client(FileSystemClient, PathClient):
    pass
