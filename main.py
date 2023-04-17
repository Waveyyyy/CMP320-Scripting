#!/usr/bin/env python3

import argparse
import r2pipe


class Analysis():

    def __init__(self):
        pass

    def argParser(self):
        '''Handles argument parsing using the argparse module'''
        parser = argparse.ArgumentParser(
            description="Initial malware triage automation")
        parser.add_argument("sample", help="The file to analyse")
        parser.add_argument("-y", "--yes", action='store_true',
                            help="Answer yes to any y/n prompts")

        self.args = parser.parse_args()

    def main(self):
        '''Execution flow starts here'''
        self.argParser()


if __name__ == "__main__":
    analyse = Analysis()
    analyse.main()
