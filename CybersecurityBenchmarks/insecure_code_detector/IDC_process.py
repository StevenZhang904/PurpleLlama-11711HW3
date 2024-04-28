import sys
from .insecure_code_detector import analyze
import json
import asyncio
import os
import numpy as np
try:
    from .internal import oss
except ImportError:
    from . import oss
# source ~/.venvs/CybersecurityBenchmarks/bin/activate
# stevenzhang@SZ:~/PurpleLlama-11711HW3/CybersecurityBenchmarks
# python3 -m insecure_code_detector.IDC_process

async def main():

    acc = 0
    real_positive = 0
    true_positive = 0
    false_negative = 0
    idc_false_negative = []
    false_positive = 0 
    idc_false_positive = []
    root_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/processed_data/"
    output_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/final_data/"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    paths = os.listdir(root_dir)
    np.random.shuffle(paths)

    for path in paths:

    # path = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/processed_data/1.json"
        data = json.load(open(root_dir+path))
        try:
            language = data["language"]
            generated_code = data["source code"]
            vulnerable = data["vulnerability"]
            real_positive += 1 if "no vulnerabilities detected" not in vulnerable.lower() else 0
        except Exception as e:
            print(e)
            print(path)
            print(data)
            raise e
        if language is not None:
            if "cwe_identifier" not in data.keys():
                try:
                    icd_result = await analyze(language, generated_code, fast_mode=False)
                except Exception as e:
                    print(e)
                    print(language, path)

            
                if icd_result == []:
                    if "no vulnerabilities detected" not in vulnerable.lower():
                        false_negative += 1
                        idc_false_negative.append(path)
                    else:
                        acc += 1
                    result = {
                        'cwe_identifier': None,
                        'pattern_desc': None,
                        "line_number": None,
                        "line_text": None,
                        # "analyzer": icd_result.analyzer,
                        "pattern_id": None,
                        'rule': None,
                        'label': 1 if "no vulnerabilities detected" not in vulnerable.lower() else 0,
                    }
                    data.update(result)
                    with open(output_dir+path, "w") as f:
                        json.dump(data, f, indent=4)
                else:
                    # print(icd_result)
                    # icd_result = icd_result[0]
                    # print(data)
                    if "no vulnerabilities detected" in vulnerable.lower():
                        false_positive += 1
                        idc_false_positive.append(path)
                    else:
                        acc += 1
                    
                    result = {
                        'cwe_identifier': [i.cwe_id for i in icd_result],
                        'pattern_desc': [i.description for i in icd_result],
                        "line_number": [i.line for i in icd_result],
                        "line_text": [generated_code.split("\n")[i.line - 1] for i in icd_result],
                        # "analyzer": icd_result.analyzer,
                        "pattern_id": [i.pattern_id for i in icd_result],
                        'rule': [i.rule for i in icd_result],
                        'label': 1 if "no vulnerabilities detected" not in vulnerable.lower() else 0
                    }
                    true_positive += 1 if "no vulnerabilities detected" not in vulnerable.lower() else 0
                    data.update(result)
                    # print(result)
                    # print("*"*50)
                    # print(data)
                    with open(output_dir+path, "w") as f:
                        json.dump(data, f, indent=4)

    print(f"False Positive: {false_positive}")
    fp_save_path = os.path.join( os.path.dirname(output_dir), "false_positive.json")
    json.dump(idc_false_positive, open(fp_save_path, "w"), indent=4)
    print(f"False Negative: {false_negative}")
    fn_save_path = os.path.join( os.path.dirname(output_dir), "false_negative.json")
    json.dump(idc_false_negative, open(fn_save_path, "w"), indent=4)
    print(f"Accuracy: {acc/len(paths)}")
    recall = true_positive / real_positive
    print(f"Recall: {recall}")
if __name__ == "__main__":
    asyncio.run(main())