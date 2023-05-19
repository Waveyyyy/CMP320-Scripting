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
        parser.add_argument(
            "--offline", help="Will not use external services")
        parser.add_argument("-a",
                            "--algorithm", help="Which hash algorithm to use",
                            choices=["MD5", "SHA1", "SHA224",
                                     "SHA256", "SHA384", "SHA512"])

        self.args = parser.parse_args()

    def get_file_hash(self):
        '''Retrieves the hash of the sample'''
        # by default the algorithm is sha256()
        algorithm = hashlib.sha256()
        # choose the algorithm based off of the algorithm argument
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
                algorithm = hashlib.sha384()
            case "SHA512":
                algorithm = hashlib.sha512()

        # check if the calling function was virus_total
        # virus total only accepts MD5,SHA1 or SHA256 hashes
        if "virus_total" == inspect.stack()[1].function:
            algorithm = hashlib.sha256()

        # read the whole sample into data
        # if the sample is larger than the system has RAM this may cause issues
        with open(self.args.sample, "rb") as sample:
            data = sample.read()

        # update the hash object with the content read from the sample file
        algorithm.update(data)

        # return the hex representation of the file hash
        return algorithm.hexdigest()

    def virus_total(self):
        # get sha256 hash of the sample
        sample_hash = self.get_file_hash()
        # use vt api or bs3/selenium/requests lib to perform this
        # parse data (most likely to use vt api for this)
        # store useful responses somehow
        return sample_hash

    def run(self):
        '''Execution flow starts here'''
        self.arg_parser()
        print(f'run: {self.get_file_hash()}')
        print(f'virus_total: {self.virus_total()}')


if __name__ == "__main__":
    analyse = Analyse()
    analyse.run()
