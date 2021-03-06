import os
import unittest
from azure.datalake.gen2.client import DataLakeGen2Client

ACCOUNT_NAME = os.environ.get('ACCOUNT_NAME', '')
STORAGE_KEY = os.environ.get('STORAGE_KEY', '')


class TestGen2FileSystem(unittest.TestCase):
    client = DataLakeGen2Client(ACCOUNT_NAME, STORAGE_KEY)

    def test_create_filesystem(self):
        headers = self.client.create_filesystem('/testfilesystem')
        self.assertIsNotNone(headers['ETag'])

    def test_delete_filesystem(self):
        headers = self.client.delete_filesystem('/testfilesystem')
        self.assertIsNotNone(headers)

    def test_list_filesystem(self):
        filesystems = self.client.list_filesystem()
        self.assertIsNotNone(filesystems)

    @unittest.skip(reason="Need to fix sources")
    def test_list_filesystem_with_prefix(self):
        filesystems = self.client.list_filesystem(prefix='testfolder')
        self.assertIsNotNone(filesystems)

    def test_list_path_with_prefix(self):
        files = self.client.list_path('input', max_results=1000)
        files = self.client.list_path('input', max_results=1000, continuation=files['continuation'])
        self.assertIsNotNone(files)

    def test_rename_file(self):
        self.client.create_path('testfolder', 'testfolder2', resource='directory')
        files = self.client.rename_file('/testfolder/file1.txt', '/testfolder2/file2.txt')
        self.assertIsNotNone(files)

    def test_update_path_append(self):
        response = self.client.update_path('test1', 'test/test_file', 'append', 'test', timeout=60, position=0)
        self.assertIsNotNone(response)

    def test_full_upload_file(self):
        response = self.client.upload_filepath_to_path('nonecorebi', '/some_binary_file.xlsx',
                                                       '/path/to/some_binary_file.xlsx')

    def test_fully_upload_data(self):
        with open('some_file', 'rb') as f:
            response = self.client.upload_file_to_path('nonecorebi', '/some_binary_file.xlsx', f)

    def test_update_path_flush(self):
        response = self.client.update_path('test1', 'test/test_file', 'flush', position=0)
        self.assertIsNotNone(response)

    def test_read_file(self):
        response = self.client.read_path('test1', 'test/test_file')
        self.assertIsNotNone(response)

if __name__ == '__main__':
    unittest.main()
