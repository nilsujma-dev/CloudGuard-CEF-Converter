import json
import time
import sys
from datetime import datetime
import os

# Make sure a filename is provided
if len(sys.argv) < 2:
    print('Usage: python3 script.py jsonfile.json')
    sys.exit()

# Load the JSON data
filename = sys.argv[1]

with open(filename, 'r') as f:
    data = json.load(f)

# Extract the keys from the JSON data
rule_name = data['rule']['name'].replace('\n', '\\n')
rule_description = data['rule']['description'].replace('\n', '\\n')
severity = data['rule']['severity'].replace('\n', '\\n')
source_username = data['entity']['name'].replace('\n', '\\n')
source_user_id = data['entity']['id'].replace('\n', '\\n')

# Convert reportTime to UNIX timestamp (milliseconds)
report_time = data['reportTime']
dt = datetime.strptime(report_time, "%Y-%m-%dT%H:%M:%S.%fZ")
unix_time_ms = int(time.mktime(dt.timetuple())) * 1000

status = data['status'].replace('\n', '\\n')
rule_remediation = data['rule']['remediation'].replace('\n', '\\n')
account = json.dumps(data['account']).replace('\n', '\\n')
region = data['region'].replace('\n', '\\n')
finding_key = data['findingKey'].replace('\n', '\\n')
rule_id = data['rule']['ruleId'].replace('\n', '\\n')

# Construct the CEF string
cef = f'CEF:0|Check Point|CloudGuard||{rule_name}|{rule_name}|{severity}|' \
      f'msg={rule_description} suser={source_username} suid={source_user_id} rt={unix_time_ms} ' \
      f'fname=CLOUD-011 Check Point CloudGuard Compliance Alert-24Hrs outcome={status} ' \
      f'cs1={rule_remediation} cs1Label=Rule Remediation ' \
      f'cs2={region} cs2Label=Region ' \
      f'cs3={finding_key} cs3Label=Finding Key ' \
      f'cs4={rule_id} cs4Label=Rule ID ' \
      f'flexString1={account} flexString1Label=Account'

# Construct output filename
base_filename = os.path.splitext(os.path.basename(filename))[0]
output_filename = base_filename + ".cef"

# Write the CEF string to file
with open(output_filename, 'w') as output_file:
    output_file.write(cef)

print(f'Output written to {output_filename}')

