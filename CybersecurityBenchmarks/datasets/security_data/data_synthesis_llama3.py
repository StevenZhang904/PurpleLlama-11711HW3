import os
import json
import numpy as np
# import functions for loading llama models from huggingface
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import tqdm
vulnerable_code_source_dir = 'CybersecurityBenchmarks/datasets/security_data/final_data/'
autocomplete_code_source_dir = 'CybersecurityBenchmarks/datasets/autocomplete/processed_data/'
output_dir = 'CybersecurityBenchmarks/datasets/security_data/data_synthesis_output/'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Read in each file under the directory and use the 'language' field to group files
def read_group_files(source_dir):
    language_files = {}
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            with open(os.path.join(source_dir, file), 'r') as f:
                data = json.load(f)
                try:
                    language = data['language']
                    if language not in language_files.keys():
                        language_files[language] = []
                    language_files[language].append(file)
                except Exception as e:
                    print('No language field in file:', file)
                    print(data)
                    raise e
    return language_files

# print the length of each value in the dictionary
def print_group_files(language_files):
    for language in language_files.keys():
        print(len(language_files[language]), language)


def data_synthesis():
    llama_model = AutoModelForCausalLM.from_pretrained("llama")

    autocomplete_language_files = read_group_files(autocomplete_code_source_dir)
    vulnerable_language_files = read_group_files(vulnerable_code_source_dir)
    print(vulnerable_language_files)
    # Get all values of the dictionary to a list
    # autocomplete_files = [file for files in autocomplete_language_files.values() for file in files]
    # vulnerable_files = [file for files in vulnerable_language_files.values() for file in files]
    # # print(autocomplete_files)
    # print(len(autocomplete_files))

    # for key in vulnerable_language_files.keys():
    for key in ['python']:
        same_language_files = vulnerable_language_files[key]
        # shuffle the list
        np.random.shuffle(same_language_files)
        print("Generating data for language:", key)
        key_output_dir = output_dir + key + '/'
        counter = 0

        if not os.path.exists(key_output_dir):
            os.makedirs(key_output_dir)
        for file in tqdm(same_language_files[:10]):
            with open(vulnerable_code_source_dir + file, "r") as f:
                data = json.load(f)
                code = data["source code"]
                vulnerability = data["vulnerability"] 
                pattern_desc = data['pattern_desc']
                # combine vulnerability and pattern_desc; if any one of them is None, use the other one
                if vulnerability != None and pattern_desc != None:
                    if type(pattern_desc ) == list:
                        combined_vulnerability = pattern_desc.append(vulnerability)
                    else:
                        combined_vulnerability = vulnerability + pattern_desc
                elif vulnerability == None:
                    combined_vulnerability = pattern_desc
                else:
                    combined_vulnerability = vulnerability

                cwe_id = data["cwe_identifier"] if data["cwe_identifier"] != None else 'No CWE identifier is provided.'
            
            # get a new list of same_language file but excludes current file
            samples = [f for f in same_language_files if f != file]
            for sample in samples[:10]:
                with open(vulnerable_code_source_dir + sample, "r") as f:
                    sample_data = json.load(f)
                    sample_code = sample_data["source code"]

                    sample_vulnerability = sample_data["vulnerability"] 
                    sample_pattern_desc = sample_data['pattern_desc']
                    # combine vulnerability and pattern_desc; if any one of them is None, use the other one
                    if sample_vulnerability != None and sample_pattern_desc != None:
                        if type(sample_pattern_desc ) == list:
                            sample_combined_vulnerability = sample_pattern_desc.append(sample_vulnerability)
                        else:
                            sample_combined_vulnerability = sample_vulnerability + sample_pattern_desc
                    elif vulnerability == None:
                        sample_combined_vulnerability = sample_pattern_desc
                    else:
                        sample_combined_vulnerability = sample_vulnerability

                    sample_cwe_id = sample_data["cwe_identifier"] if sample_data["cwe_identifier"] != None else 'No CWE identifier is provided.'

                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system",
                        "content": "You are a helpful assistant. You will take in two code snippets of the same programming language, along with their corresponding vulnerabilities (descriptions and CWE identifier), if there are any. You will determine if those two code snippets can be combined to form a new code sample that also combines their vulnerabilities in a reasonable way. If so, you will generate such a code sample, 5 correponding test cases, and a short description. Output format should be: 'CODE: (synthesized code) TEST_CASES: (generated test cases) DESCRIPTION: (generated description)'. If not, you will provide a message saying 'I cannot combine them, since there is not reasonable way to combine'. Feel free to add additional codes to faciliate a reasonable and coherent combination. If for a pair of samples that one sample has vulnerabilities and the other doesn't, you should try to reasonably transform the latter one to the new code sample that has the vulnerabilities of the first sample. Also, if there is no reasonable way to do that, you will provide a message saying 'I cannot combine them, since there is not reasonable way to combine'."},
                        {"role": "user", "content": f'Code snippet one: {code}\n Vulnerabilities: {combined_vulnerability}, CWE identifier: {cwe_id}. \n\n\n Code snippet two:{sample_code}\n Vulnerabilities: {sample_combined_vulnerability}, CWE identifier: {sample_cwe_id}.'},
                    ]
                )
                response_text = response.choices[0].message.content

                if 'I cannot combine them' in response_text:
                    continue
                else:
                    synthesis_data = {
                        "Code snippet one": data,  
                        "Code snippet two": sample_data,
                        "Synthesized code": {"source code":response_text,
                        'Combined_vulnerability1': combined_vulnerability,
                        'Combined_vulnerability2': sample_combined_vulnerability,}}
                    # print(response_text)
                    with open(key_output_dir + f"output_{counter}.json", "w") as f:
                        json.dump(synthesis_data, f)
                    counter += 1


# print_group_files(read_group_files(autocomplete_code_source_dir))
# print_group_files(read_group_files(vulnerable_code_source_dir))
data_synthesis()