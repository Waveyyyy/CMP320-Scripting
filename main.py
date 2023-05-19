#!/usr/bin/env python3

import argparse
import r2pipe
import hashlib
import inspect


class Analyse():

    def __init__(self):
        pass

    def arg_parser(self):
        '''Handles argument parsing using the argparse module'''
        parser = argparse.ArgumentParser(
            description="Initial malware triage automation")
        parser.add_argument("sample", help="The file to analyse")
        parser.add_argument("-y", "--yes", action='store_true',
                            help="Answer yes to any y/n prompts")
        parser.add_argument("-a",
                            "--algorithm", help="Which hash algorithm to use",
                            choices=["MD5", "SHA1", "SHA224",
                                     "SHA256", "SHA384", "SHA512"])

        self.args = parser.parse_args()

    def get_file_hash(self):
        '''Retrieves the hash of the sample'''
        algorithm = hashlib.md5()
        match self.args.algorithm:
            case "MD5":
                algorithm = hashlib.md5()
            case "SHA1":
                algorithm = hashlib.sha1()
            case "SHA224":
                algorithm = hashlib.sha224()
            case "SHA256":
                algorithm = hashlib.sha256()
            case "SHA384":
                algorithm = hashlib.sha256()
            case "SHA512":
                algorithm = hashlib.sha256()

        # check if the calling function was virus_total
        # virus total only accepts MD5,SHA1 or SHA256 hashes
        if "virus_total".equals(inspect.stack()[1].function):
            algorithm = hashlib.sha256()

        # read the whole sample into data
        # if the sample is larger than the system has RAM this may cause issues
        with open(self.args.sample, "rb") as sample:
            data = sample.read()

        # update the hash object with the content read from the sample file
        algorithm.update(data)

        # return the hex representation of the file hash
        return algorithm.hexdigest()

    def run(self):
        '''Execution flow starts here'''
        self.arg_parser()


if __name__ == "__main__":
    analyse = Analyse()
    analyse.run()
