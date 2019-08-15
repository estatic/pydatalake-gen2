# Python client for Azure Data Lake Gen2 REST API

It's simple implementation of Data Lake Gen2 REST api. Some of methods still not works properly.

## Installation

```bash
pip3 install pydatalake-gen2
```

## Usage

```python
from azure.datalake.gen2.client import DataLakeGen2Client

client = DataLakeGen2Client(ACCOUNT_NAME, STORAGE_KEY)

# Create fylesystem (aka container)
headers = client.create_filesystem('/testfilesystem')

# List available filesystems (containers)
filesystems = client.list_filesystem()

# Get files from container
files = client.list_path('testfilesystem', directory="/optional/folder")

# Create directory
path = client.create_path('testfolder', 'testfolder2', resource='directory')

# Rename (move) file
files = client.rename_file('/testfolder/file1.txt', '/testfolder2/file2.txt')
```

This is really early version of client. So, please fell free to contribute!