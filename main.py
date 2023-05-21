#!/usr/bin/env python3

import argparse
import r2pipe
import hashlib
import inspect
import requests
import json
import time


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
        parser.add_argument("--offline",
                            help="Will not use external services")
        parser.add_argument("-a", "--algorithm",
                            help="Which hash algorithm to use",
                            choices=["MD5", "SHA1", "SHA224",
                                     "SHA256", "SHA384", "SHA512"])
        parser.add_argument("-k", "--api-key",
                            help="Virus Total API key ")

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
        '''Submits file hash to virus total for analysis'''
        # get sha256 hash of the sample
        sample_hash = self.get_file_hash()
        # use vt api to get a file report
        url = f'https://www.virustotal.com/api/v3/files/{sample_hash}'
        headers = {'X-ApiKey': self.args.api_key,
                   'accept': 'application/json'}
        response = requests.get(url, headers=headers)
        file_info = response.text
        # parse the response data and output it
        self.parsing(file_info)

    def parsing(self, data):
        '''Parses data into output formats which match the calling function'''
        # print_data will contain the formatted output
        print_data = "Invalid call to parsing"
        # match based on calling function
        match inspect.stack()[1].function:
            case "virus_total":
                # title of this section
                print_data = 'Virus Total'.center(80, "=") + '\n'

                # check if the sample is on virus Total
                # there is nothing to parse otherwise
                try:
                    json_data = json.loads(data)["data"]["attributes"]
                except KeyError:
                    print_data += 'No data returend from Virus Total API\n'
                    print(print_data)
                    return

                # display the size in megabytes
                column_one = 'Size = ' + \
                    str(json_data["size"] / 1_000_000) + 'MB\n'

                # sample date information
                column_one += 'Date Created: ' + \
                    time.ctime(json_data["creation_date"]) + '\n'
                column_one += 'First seen in the wild: ' + \
                    time.ctime(json_data["first_seen_itw_date"]) + '\n'

                # time between creation and first seen in the wild
                days_since = (json_data["first_seen_itw_date"]
                              - json_data["creation_date"]) / (24 * 60 * 60)
                years = str(days_since // 365.25)
                days = str(days_since % 365.25)
                column_one += f'Difference:  {years} years and {days} days\n'

                # format the type tags on separate lines
                column_one += 'Type(s):\n'
                for tag in json_data["type_tags"]:
                    column_one += (' ' * 2) + tag + '\n'

                # signature information
                column_one += 'Signature Info:\n'
                for info in json_data["signature_info"].values():
                    column_one += (' ' * 2) + f'{info}\n'

                # threat label & category
                threat_class = json_data["popular_threat_classification"]
                column_one += 'Threat Label: ' \
                    + threat_class["suggested_threat_label"] + '\n'
                column_one += 'Threat Category: \n'
                for category in threat_class["popular_threat_category"]:
                    column_one += (' ' * 2) + category["value"] + '\n'

                # threat name(s)
                column_one += 'Threat Name: \n'
                for threat_name in threat_class["popular_threat_name"]:
                    column_one += (' ' * 2) + threat_name["value"] + '\n'

                # tags
                column_one += 'Tags: \n'
                for tag in json_data["tags"]:
                    column_one += (' ' * 2) + f'{tag}\n'

                # packers
                column_one += 'Packers: \n'
                for detection, packer in json_data["packers"].items():
                    column_one += (' ' * 2) + f'{detection}: {packer}\n'

                # resource details
                pe_details = json_data["pe_info"]
                column_one += 'Resource Details: \n'
                for resource in pe_details["resource_details"]:
                    for key, value in resource.items():
                        column_one += (' ' * 2) + f'{key}: {value}\n'
                    column_one += '\n'

                # names of samples submitted with matching hash
                # in a separte column
                column_two = 'Name(s):\n'
                for name in json_data["names"]:
                    column_two += (' ' * 2) + name + '\n'

                # find the max amount of lines between the columns
                c1_len = column_one.splitlines().__len__()
                c2_len = column_two.splitlines().__len__()
                max_len = max((c1_len, c2_len))

                # make the column with less lines match by
                # adding newlines
                if c1_len < max_len:
                    for i in range(c2_len - c1_len):
                        column_one += '\n'
                elif c2_len < max_len:
                    for i in range(c1_len - c2_len):
                        column_two += '\n'

                # longest string in column one, used for formatting columns
                max_len = max(len(line) for line in column_one.splitlines())
                for c1, c2 in zip(column_one.splitlines(), column_two.splitlines()):
                    print_data += f'{c1:{max_len+2}}{c2}\n'

        print(print_data)

    def run(self):
        '''Execution flow starts here'''
        self.arg_parser()
        print(f'run: {self.get_file_hash()}')
        print(f'virus_total: {self.virus_total()}')


if __name__ == "__main__":
    analyse = Analyse()
    analyse.run()
