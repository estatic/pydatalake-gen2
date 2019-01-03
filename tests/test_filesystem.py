import unittest
from azure.datalake.gen2.client import DataLakeGen2Client


class TestGen2FileSystem(unittest.TestCase):

    def test_list_filesystem(self):
        client = DataLakeGen2Client('', '')
        client.create_filesystem('/testfilesystem')



if __name__ == '__main__':
    unittest.main()