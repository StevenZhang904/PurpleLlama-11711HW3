import sys
from .insecure_code_detector import analyze
import json
import asyncio
import os

# source ~/.venvs/CybersecurityBenchmarks/bin/activate
# stevenzhang@SZ:~/PurpleLlama-11711HW3/CybersecurityBenchmarks
# python3 -m insecure_code_detector.test

async def main():
    root_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/processed_data/"
    output_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/final_data/"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for path in os.listdir(root_dir):

    # path = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/processed_data/1.json"
        data = json.load(open(root_dir+path))
        try:
            language = data["language"]
            response = data["source code"]
            vunerable = data["vulnerability"]
        except Exception as e:
            print(e)
            print(path)
            print(data)
        if language is not None:
            if "cwe_identifier" not in data.keys():
                try:
                    icd_result = await analyze(language, response)
                except Exception as e:
                    print(e)
                    print(language, path)


                if icd_result == []:
                    continue
                else:
                    icd_result = icd_result[0]
                    result = {
                        'cwe_identifier': icd_result.cwe_id,
                        'pattern_desc': icd_result.description,
                        "line_number": icd_result.line,
                        "line_text": response.split("\n")[icd_result.line - 1],
                        # "analyzer": icd_result.analyzer,
                        "pattern_id": icd_result.pattern_id,
                        'rule': icd_result.rule,
                        'label': 1 if "Vulnerabilities Detected" in vunerable else 0
                    }
                    data.update(result)
                    # print(result)
                    # print("*"*50)
                    # print(data)
                    with open(output_dir+path, "w") as f:
                        json.dump(data, f, indent=4)

if __name__ == "__main__":
    asyncio.run(main())