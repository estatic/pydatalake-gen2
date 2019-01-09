import unittest
from azure.datalake.gen2.client import DataLakeGen2Client

ACCOUNT_NAME = ''
STORAGE_KEY = ''

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
        files = self.client.list_path('testfolder')
        self.assertIsNotNone(files)

    def test_rename_file(self):
        path = self.client.create_path('testfolder', 'testfolder2', resource='directory')
        files = self.client.rename_file('/testfolder/file1.txt', '/testfolder2/file2.txt')
        self.assertIsNotNone(files)


if __name__ == '__main__':
    unittest.main()