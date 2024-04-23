import json

from openai import OpenAI
import os


client = OpenAI(api_key='')




### for each element in the false positive list, read in its correponding json file.

root_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/final_data/"
with open(root_dir + "false_positive.json", "r") as file:
    data = json.load(file)
    for item in data:
        file_path = root_dir + item
        with open(file_path, "r") as file:
            file_data = json.load(file)
            code = file_data["source code"]

        response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[

                        {"role": "system", "content": "You are a helpful assistant. You will take in a code snippet and determine if it has vulnerability. If you find a vulnerability, you will provide the vulnerability information by starting with: 'Vulnerabilities Detected: ' If there are more than 1 vulnerability, please list it as 1. and 2. . If not you will provide a message saying 'No vulnerabilities detected.'."},
                        {"role": "user", "content": code},

                    ]
                    )

        response_text = response.choices[0].message.content
        print(response_text)
        break