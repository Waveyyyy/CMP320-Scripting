#!/usr/bin/env python3

import argparse
import r2pipe
import hashlib
import inspect
import requests
import json
import time
import re
import jsonpickle
import itertools


class Analyse():

    def __init__(self):
        self.r2_obj = None

    def arg_parser(self):
        '''Handles argument parsing using the argparse module'''
        parser = argparse.ArgumentParser(
            description="Initial malware triage automation")
        parser.add_argument("sample", help="The file to analyse")
        parser.add_argument("-y", "--yes", action='store_true',
                            help="Answer yes to any y/n prompts")
        parser.add_argument("--offline", action='store_true',
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

    def radare_2(self):
        if self.args.sample:
            self.r2_obj = r2pipe.open(self.args.sample)
            self.r2_obj.cmd("aaa")

    def strings(self):
        result = self.r2_obj.cmd('iz')
        self.parsing(result)

    def headers(self):
        result = self.r2_obj.cmd('iH')
        self.parsing(result)

    def imports(self):
        result = self.r2_obj.cmd('ii')
        self.parsing(result)

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
                try:
                    column_one = 'Size = ' + \
                        str(json_data["size"] / 1_000_000) + 'MB\n'
                except KeyError:
                    pass

                # sample date information
                try:
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
                except KeyError:
                    pass

                # format the type tags on separate lines
                try:
                    column_one += 'Type(s):\n'
                    for tag in json_data["type_tags"]:
                        column_one += (' ' * 2) + tag + '\n'
                except KeyError:
                    pass

                # signature information
                try:
                    column_one += 'Signature Info:\n'
                    for info in json_data["signature_info"].values():
                        column_one += (' ' * 2) + f'{info}\n'
                except KeyError:
                    pass

                # threat label & category
                try:
                    threat_class = json_data["popular_threat_classification"]
                    column_one += 'Threat Label: ' \
                        + threat_class["suggested_threat_label"] + '\n'
                    column_one += 'Threat Category: \n'
                    for category in threat_class["popular_threat_category"]:
                        column_one += (' ' * 2) + category["value"] + '\n'
                except KeyError:
                    pass

                # threat name(s)
                try:
                    column_one += 'Threat Name: \n'
                    for threat_name in threat_class["popular_threat_name"]:
                        column_one += (' ' * 2) + threat_name["value"] + '\n'
                except KeyError:
                    pass

                # tags
                try:
                    column_one += 'Tags: \n'
                    for tag in json_data["tags"]:
                        column_one += (' ' * 2) + f'{tag}\n'
                except KeyError:
                    pass

                # packers
                try:
                    column_one += 'Packers: \n'
                    for detection, packer in json_data["packers"].items():
                        column_one += (' ' * 2) + f'{detection}: {packer}\n'
                except KeyError:
                    pass

                # resource details
                try:
                    pe_details = json_data["pe_info"]
                    column_one += 'Resource Details: \n'
                    for resource in pe_details["resource_details"]:
                        for key, value in resource.items():
                            column_one += (' ' * 2) + f'{key}: {value}\n'
                        column_one += '\n'
                except KeyError:
                    pass

                # names of samples submitted with matching hash
                # in a separte column
                try:
                    column_two = 'Name(s):\n'
                    for name in json_data["names"]:
                        column_two += (' ' * 2) + name + '\n'
                except KeyError:
                    pass

                # longest string in column one, used for formatting columns
                max_len = max(len(line) for line in column_one.splitlines())
                for c1, c2 in itertools.zip_longest(column_one.splitlines(),
                                                    column_two.splitlines(), fillvalue=''):
                    print_data += f'{c1:{max_len+2}}{c2}\n'
            case "strings":
                # title of this section
                print_data = "Strings".center(80, '=') + '\n'
                string_data = ""
                # print all lines bar the first 3, they are not related
                # to the strings of the files
                for line in data.splitlines()[3:]:
                    # 7th column contains the string
                    # anything after is still part of the string and has been
                    # separated into new columns due to spaces
                    if line.split().__len__() > 8:
                        string_data += f'{" ".join(line.split()[7:])}\n'
                    else:
                        string_data += f'{str(line.split()[7])}\n'
                # sort lines so the longest ones are at the top
                string_data = sorted(
                    string_data.splitlines(), key=len, reverse=True)
                for line in string_data:
                    print_data += f'{line}\n'
            case "headers":
                # title of this section
                print_data = "Header Info".center(80, "=") + '\n'
                # regex which gets the header and the data between it and the
                # next one
                matches = re.findall(
                    r'([A-Z_]+)\n((?:\s{2,}.+\n)+)', data, flags=re.MULTILINE)
                matches_dict = {}
                # loop over each match
                for match in matches:
                    match_name = match[0]
                    match_data = match[1].split('\n')
                    match_dict = {}
                    # loop over the values under each heading
                    for item in match_data:
                        pair = item.strip().split(':')
                        # check if the value pair has more than 2 entries
                        if len(pair) == 2:
                            key, value = pair
                            # construct the new dict with the values under
                            # the current heading
                            match_dict[key.strip()] = value.strip()
                        elif len(pair) > 2:
                            key = pair[0].strip()
                            value = ':'.join(pair[1:]).strip()
                            match_dict[key] = value
                        # add the dict to the dict which contains the other
                        # headings and values
                        matches_dict[match_name] = match_dict
                # transform the data into json format and load it to be used
                jdata = json.loads(jsonpickle.encode(matches_dict, indent=4))
                half_way = len(jdata.keys()) // 2
                column_one = {}
                column_two = {}
                # separate the data "evenly" into two columns
                for i, (key, value) in enumerate(jdata.items()):
                    if i < half_way:
                        column_one[key] = value
                    else:
                        column_two[key] = value

                max_len = max((len(key) + len(value))
                              for key, value in column_one.items())
                for (key1, value1), (key2, value2) in zip(column_one.items(), column_two.items()):
                    # print section heading
                    print_data += f'{key1:{max_len}}{key2}\n'
                    for (v_key1, v_value1), (v_key2, v_value2) in zip(value1.items(), value2.items()):
                        # print the values of each section
                        if not (v_key1 and v_value1):
                            print_data += f'{v_key1}{v_value1:{max_len}}{v_key2}: {v_value2}\n'
                        elif not (v_key2 and v_value2):
                            print_data += f'{v_key1}: {v_value1:{max_len}}{v_key2}{v_value2}\n'
                        else:
                            print_data += f'{v_key1}: {v_value1:{max_len}}{v_key2}: {v_value2}\n'
                    # end with another newline for ease of reading
                    print_data += '\n'
            case "imports":
                # title of this section
                print_data = "Function Imports".center(80, "=") + '\n'
                # get a list containing a list with the dll and the function
                imports = [line.strip().split()[4:]
                           for line in data.strip().splitlines()[3:]]
                import_dict = {}
                # loop over the dll and function list in the imports list
                for pair in imports:
                    dll = pair[0]
                    function = pair[1]
                    # add unique dlls to the import_dict
                    if dll not in import_dict:
                        import_dict[dll] = []
                    # add functions to their related dll key
                    import_dict[dll].append(function)

                half_way = len(import_dict.keys()) // 2
                column_one = {}
                column_two = {}
                # split import_dict into two columns
                for i, (key, value) in enumerate(import_dict.items()):
                    if i < half_way:
                        column_one[key] = value
                    else:
                        column_two[key] = value

                max_len = max((len(key) + len(value))
                              for key, value in column_one.items())
                for (dll_1, functions_1), (dll_2, functions_2) in zip(column_one.items(), column_two.items()):
                    print_data += f'{dll_1:{max_len}}  {dll_2}\n'
                    for functions_1, functions_2 in zip(functions_1, functions_2):
                        print_data += f'  {functions_1:{max_len}}  {functions_2}\n'
                    print_data += '\n'

        print(print_data)

    def run(self):
        '''Execution flow starts here'''
        self.arg_parser()
        if not self.args.offline:
            self.virus_total()
        self.radare_2()
        self.strings()
        self.headers()


if __name__ == "__main__":
    analyse = Analyse()
    analyse.run()
