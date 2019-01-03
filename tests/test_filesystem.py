import unittest
from azure.datalake.gen2.client import DataLakeGen2Client


class TestGen2FileSystem(unittest.TestCase):
    client = DataLakeGen2Client('',
                                '')

    def test_create_filesystem(self):

        headers = self.client.create_filesystem('/testfilesystem')
        self.assertIsNotNone(headers['ETag'])

    def test_delete_filesystem(self):
        headers = self.client.delete_filesystem('/testfilesystem')
        self.assertIsNotNone(headers)

    def test_list_filesystem(self):
        filesystems = self.client.list_filesystem()
        self.assertIsNotNone(filesystems)


if __name__ == '__main__':
    unittest.main()