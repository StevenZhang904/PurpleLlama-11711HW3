import json

import os
import re

language_map = {
    'java': "java",
    'py': "python",
    'php': "php",
    'js': "javascript",
    'aspx.cs': None,  # Assuming ASPX.CS files are generally handled by C# code behind
    'rb': "ruby",
    'c': "c",
    'asp': None,  # No specific mapping provided for ASP Classic
    'html': None,  # HTML is not listed in the provided names
    'go': None,  # No specific mapping provided for Go
    'ts': None,  # No specific mapping provided for TypeScript
    'cs': "csharp"
}



def parse_markdown_file(md_content):
    # Regular expression to find sections
    pattern = r'^## ([\w.-]+\.\w+)\s+(.*?)\n(?=## |\Z)'
    matches = re.finditer(pattern, md_content, re.S | re.M)
    return {match.group(1): match.group(2).strip() for match in matches}

def extract_vulnerabilities(directory):
    # Find the Markdown file
    md_file = None
    for file in os.listdir(directory):
        if file.endswith('.md'):
            md_file = file
            break
    if not md_file:
        raise FileNotFoundError("No Markdown file found in the directory.")

    # Read the content of the Markdown file
    with open(os.path.join(directory, md_file), 'r') as file:
        md_content = file.read()

    # Parse the Markdown content
    return parse_markdown_file(md_content)

all_data = {}
root_path = "security_data/gpt3_security_vulnerability_scanner-main/"
output_path = "security_data/processed_data/"
counter = 0
language_type = []
# get all subdirectories in the directory and then get all files in the subdirectories
for root_path, dirs, _ in os.walk(root_path):

    for dir in dirs:
        print('dir', dir)

        readme_reference_dic = extract_vulnerabilities(root_path + dir)
        filenames_list = readme_reference_dic.keys()
        print('filenames_list', filenames_list, len(filenames_list))
        for filename in filenames_list:
            with open(root_path + dir + "/" + filename, 'r') as file:
                file_content = file.read()
            
            postfix = filename.split('.')[-1]
            if 'aspx' in postfix:
                postfix = 'aspx.cs'
            language = language_map.get(postfix)


            data = {"file_path": root_path + dir + "/" + filename, "vulnerability": readme_reference_dic[filename], "source code": file_content, "language": language}
            all_data["{}.json".format(counter)] = data
            with open(output_path + str(counter) + ".json", 'w') as json_file:
                json.dump(data, json_file)
            counter += 1

            if postfix not in language_type:
                language_type.append(postfix)
            

with open(output_path + "all_data.json", 'w') as json_file:
    json.dump(all_data, json_file)

print('language_type', language_type)
