#!/usr/bin/env python
"""
Selectively dump AWS IAM security information.

Copyright (c) 2017, Adam Lanier
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import sys
from argparse import ArgumentParser, FileType

import boto3


class ReportWrapper(object):
    __state = {}

    def __init__(self):
        """
        Save/restore state upon initialization.
        """
        self.__dict__ = self.__state
        self.iam = boto3.client('iam')

    def get_report(self, filter=None):
        """
        Get potentially filtered IAM report and handle IsTruncated flag.
        Yield report pieces as necessary.
        """
        not_complete = True
        marker = None

        while not_complete:
            if marker is None:
                report = self.iam.get_account_authorization_details(Filter=filter)
                yield report
            else:
                report = self.iam.get_account_authorization_details(Filter=filter, Marker=marker)
                yield report
            try:
                marker = report['Marker']
            except KeyError:
                not_complete = False

    def get_user(self, user):
        """
        Support function to flesh out the detail for users.
        """
        return self.iam.get_user(UserName=user)


if __name__ == '__main__':
    parser = ArgumentParser(description=__doc__)
    service_group = parser.add_argument_group('Services', 'AWS services to dump')
    service_group.add_argument('-u', '--user',
                               action='store_true',
                               default=False,
                               help="Dump all user data")
    service_group.add_argument('-g', '--group',
                               action='store_true',
                               default=False,
                               help="Dump all group data")
    service_group.add_argument('-r', '--role',
                               action='store_true',
                               default=False,
                               help="Dump all role data")
    service_group.add_argument('-p', '--policy',
                               action='store_true',
                               default=False,
                               help="Dump all policy data")
    service_group.add_argument('-a', '--all',
                               action='store_true',
                               default=False,
                               help="Dump all data")

    output_group = parser.add_argument_group('Output', 'Output destination')
    output_group.add_argument('-f', '--file', help='Default is stdout',
                              type=FileType('wb'),
                              default=sys.stdout)
    args = parser.parse_args()
    report = ReportWrapper()

    if args.user or args.all:
        args.file.write("--- Users ---\n")
        for r in report.get_report(filter=['User']):
            for user in r['UserDetailList']:
                profile = report.get_user(user['UserName'])
                args.file.write("* Username:       {}\n".format(user['UserName']))
                args.file.write("  Created:        {}\n".format(profile['User']['CreateDate']))
                try:
                    args.file.write("  Last Logged In: {}\n".format(profile['User']['PasswordLastUsed']))
                except KeyError:
                    args.file.write("  Last Logged In: {}\n".format('Never'))
                args.file.write("Policies:\n")
                try:
                    for policy in user['UserPolicyList']:
                        args.file.write("\t{PolicyName}\n".format(**policy))
                except KeyError:
                    pass
                args.file.write("Groups:\n")
                try:
                    for group in user['GroupList']:
                        args.file.write("\t{}\n".format(group))
                except KeyError:
                    pass
                args.file.write("Managed Policies:\n")
                try:
                    for attached_policy in user['AttachedManagedPolicies']:
                        args.file.write("\t{PolicyName}\n".format(**attached_policy))
                except KeyError:
                    pass
                args.file.write('\n')

    if args.group or args.all:
        args.file.write("\n--- Groups ---\n")
        for r in report.get_report(filter=['Group']):
            for group in r['GroupDetailList']:
                args.file.write("* GroupName: {}\n".format(group['GroupName']))
                args.file.write("Group Policies:\n")
                try:
                    for policy in group['GroupPolicyList']:
                        args.file.write("\t{PolicyName}\n".format(**policy))
                except KeyError:
                    pass
                args.file.write("Attached Managed Policies:\n")
                try:
                    for attached_policy in group['AttachedManagedPolicies']:
                        args.file.write("\t{PolicyName}\n".format(**attached_policy))
                except KeyError:
                    pass
                args.file.write('\n')

    if args.role or args.all:
        args.file.write("\n--- Roles ---\n")
        for r in report.get_report(filter=['Role']):
            for role in r['RoleDetailList']:
                args.file.write("* {}\n".format(role['RoleName']))
                args.file.write("Instance Profiles:\n")
                try:
                    for instance_profile in role['InstanceProfileList']:
                        args.file.write("\tProfile Name: {}:\n".format(instance_profile['InstanceProfileName']))
                        for instance_role in instance_profile['Roles']:
                            args.file.write("\t\tRole: {RoleName}\n".format(**instance_role))
                except KeyError:
                    pass
                args.file.write("Role Policies:\n")
                try:
                    for policy in role['RolePolicyList']:
                        args.file.write("\t{PolicyName}\n".format(**policy))
                except KeyError:
                    pass
                args.file.write("Managed Policies:\n")
                try:
                    for attached_policy in role['AttachedManagedPolicies']:
                        args.file.write("\t{PolicyName}\n".format(**attached_policy))
                except KeyError:
                    pass
                args.file.write('\n')

    if args.policy or args.all:
        args.file.write("\n --- AWS Managed Policies ---\n")
        for r in report.get_report(filter=['AWSManagedPolicy']):
            for policy in r['Policies']:
                args.file.write("* {}\n".format(policy['PolicyName']))
                args.file.write("\tAttachment Count: {AttachmentCount}\n".format(**policy))
                args.file.write("\tIsAttachable:     {IsAttachable}\n".format(**policy))
                try:
                    for version in policy['PolicyVersionList']:
                        args.file.write("\t{Document}\n".format(version['Document']))
                except KeyError:
                    pass
                args.file.write('\n')

        args.file.write("\n --- Local Managed Policies ---\n")
        for r in report.get_report(filter=['LocalManagedPolicy']):
            for policy in r['Policies']:
                args.file.write("* {}\n".format(policy['PolicyName']))
                args.file.write("\tAttachment Count: {AttachmentCount}\n".format(**policy))
                args.file.write("\tIsAttachable:     {IsAttachable}\n".format(**policy))
                try:
                    for version in policy['PolicyVersionList']:
                        args.file.write("\t{Document}\n".format(version['Document']))
                except KeyError:
                    pass
                args.file.write('\n')
