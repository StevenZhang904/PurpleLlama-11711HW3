import sys
from .insecure_code_detector import analyze
import json
import asyncio
import os
import evaluate
# source ~/.venvs/CybersecurityBenchmarks/bin/activate
# stevenzhang@SZ:~/PurpleLlama-11711HW3/CybersecurityBenchmarks
# python3 -m insecure_code_detector.synthesis_code_eval


### TODO: add line number detection feature to detect if the model can find the line number of the vulnerability in the synthesized code and also CWE identifiers
async def evaluate_processed_data(root_dir):
    acc = 0
    real_positive = 0
    true_positive = 0
    false_negative = 0
    idc_false_negative = []
    false_positive = 0 
    idc_false_positive = []
    BLEU_metric = evaluate.load("bleu")
    Rouge_metric = evaluate.load("rouge")
    bertscore = evaluate.load("bertscore")

    vulnerabilities = []
    pattern_descs = []

    for file in os.listdir(root_dir):
        data = json.load(open(os.path.join(root_dir, file)))
        generated_code = data["source code"]
        language = data["language"]
        vulnerability = data["vulnerability"]
        pattern_desc = data["pattern_desc"]

        real_positive += 1 if "no vulnerabilities detected" not in vulnerability.lower() else 0

        icd_result = await analyze(language, generated_code, fast_mode=False)

        if icd_result == []:
            if "no vulnerabilities detected" not in vulnerability.lower():
                false_negative += 1
                idc_false_negative.append(file)
            else:
                acc += 1
        else:
            if "no vulnerabilities detected" in vulnerability.lower():
                false_positive += 1
                idc_false_positive.append(file)
            else:
                acc += 1

            true_positive += 1 if "no vulnerabilities detected" not in vulnerability.lower() else 0

        if type(pattern_desc) == list:
            pattern_desc = ' '.join(pattern_desc)

        if pattern_desc == None:
            pattern_desc = "no vulnerabilities detected"

        vulnerabilities.append([vulnerability])
        pattern_descs.append(pattern_desc)

    bleu_score = BLEU_metric.compute(predictions=pattern_descs, references=vulnerabilities)
    rouge_score = Rouge_metric.compute(predictions=pattern_descs, references=vulnerabilities)
    bert_score = bertscore.compute(predictions=pattern_descs, references=vulnerabilities, lang="en")
    print("For the processed data that are used for code synthesis:")
    print(f"BLEU Score: {bleu_score}")
    print(f"Rouge Score: {rouge_score}")
    # The precision field of BertScore is a list, find the average of the list
    bert_score_precision = sum(bert_score["precision"]) / len(bert_score["precision"])
    bert_score_recall = sum(bert_score["recall"]) / len(bert_score["recall"])
    bert_score_f1 = sum(bert_score["f1"]) / len(bert_score["f1"])
    print(f"Bert Score Precision: {bert_score_precision}")
    print(f"Bert Score Recall: {bert_score_recall}")
    print(f"Bert Score F1: {bert_score_f1}")

    print("Total number of samples: ", len(os.listdir(root_dir)))
    print(f"False Positive: {false_positive}")

    print(f"False Negative: {false_negative}")

    print(f"Accuracy: {acc/len(root_dir)}")
    recall = true_positive / real_positive
    print(f"Recall: {recall}")


async def main():
    acc = 0
    real_positive = 0
    true_positive = 0
    false_negative = 0
    idc_false_negative = []
    false_positive = 0 
    idc_false_positive = []
    cwe_acc = 0
    line_number_acc = 0

    synthesized_root_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/data_synthesis_output/python/"
    output_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/Synthesized_eval_results/"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    sample_root_dir = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/final_data/"
    await evaluate_processed_data(sample_root_dir)
    BLEU_metric = evaluate.load("bleu")
    Rouge_metric = evaluate.load("rouge")
    bertscore = evaluate.load("bertscore")

    icd_generated_vulnerability_descriptions = []
    llm_generated_vulnerability_descriptions = []
    real_vulnerability_descriptions = []
    for path in os.listdir(synthesized_root_dir):

    # path = "/home/stevenzhang/PurpleLlama-11711HW3/CybersecurityBenchmarks/datasets/security_data/processed_data/1.json"
        data = json.load(open(synthesized_root_dir+path))
        try:
            language = 'python'
            Synthesized_output = data["Synthesized code"]['source code']
            vulnerable1 = data['Code snippet one']["vulnerability"]
            vulnerable2 = data['Code snippet two']["vulnerability"]
            line_number1 = data['Code snippet one']["line_number"]
            line_number2 = data['Code snippet two']["line_number"]

            cwe_identifier1 = data['Code snippet one']["cwe_identifier"]
            cwe_identifier2 = data['Code snippet two']["cwe_identifier"]
            if vulnerable1 == None:
                vulnerable1 = "no vulnerabilities detected"
            if vulnerable2 == None:
                vulnerable2 = "no vulnerabilities detected"         
            # Slice Synthesized_output to get the generated code by finding string between 'CODE' to 'TEST_CASES'
            if 'I cannot combine them' in Synthesized_output:
                continue
            generated_code = Synthesized_output[Synthesized_output.find('CODE:')+5:Synthesized_output.find('TEST_CASES')]
            llm_generated_vulnerability_description = Synthesized_output[Synthesized_output.find('DESCRIPTION:')+12:]

            icd_result = await analyze(language, generated_code, fast_mode=False)
            idc_generated_cwe_ids = [i.cwe_id for i in icd_result]

            idc_generated_vulnerability = [i.description for i in icd_result]
            # join the list to a string
            idc_generated_vulnerability = ' '.join(idc_generated_vulnerability)

            real_vulnerability_descriptions.append([vulnerable1, vulnerable2])

            icd_generated_vulnerability_descriptions.append(idc_generated_vulnerability)

            llm_generated_vulnerability_descriptions.append(llm_generated_vulnerability_description)

            real_positive += 1 if "no vulnerabilities detected" not in vulnerable1.lower() or "no vulnerabilities detected" not in vulnerable2.lower() else 0


            ### Each match only adds 0.5, since there is two vulnerabilities from two base samples
            for cwe_identifier in [cwe_identifier1,cwe_identifier2]:
                if len(idc_generated_cwe_ids) == 0:
                    if cwe_identifier is None:
                        cwe_acc += 0.5
                elif len(idc_generated_cwe_ids) > 0:
                    if cwe_identifier in idc_generated_cwe_ids:
                        cwe_acc += 0.5

        except Exception as e:
            print(e)
            print(path)
            print(data)
            raise e
        
        if icd_result == []:
            if 'no vulnerabilities detected' in vulnerable1.lower() and 'no vulnerabilities detected' in vulnerable2.lower():
                acc += 1
            else:
                false_negative += 1
                idc_false_negative.append(path)

        else:
            
            if 'no vulnerabilities detected' not in vulnerable1.lower() or 'no vulnerabilities detected' not in vulnerable2.lower():
                acc += 1
            elif 'no vulnerabilities detected' in vulnerable1.lower() and 'no vulnerabilities detected' in vulnerable2.lower():
                false_positive += 1
                idc_false_positive.append(path)
            else:
                raise Exception("Corner case not handled!")

            true_positive += 1 if "no vulnerabilities detected" not in vulnerable1.lower() or "no vulnerabilities detected" not in vulnerable2.lower() else 0


    idc_bleu_score = BLEU_metric.compute(predictions=icd_generated_vulnerability_descriptions, references=real_vulnerability_descriptions)
    idc_rouge_score = Rouge_metric.compute(predictions=icd_generated_vulnerability_descriptions, references=real_vulnerability_descriptions)
    idc_bert_score = bertscore.compute(predictions=icd_generated_vulnerability_descriptions, references=real_vulnerability_descriptions, lang="en")
    print()
    print('For the idc results, which is the pattern descriptions:')
    print(f"BLEU Score: {idc_bleu_score}")
    print(f"Rouge Score: {idc_rouge_score}")
    bert_score_precision = sum(idc_bert_score["precision"]) / len(idc_bert_score["precision"])
    bert_score_recall = sum(idc_bert_score["recall"]) / len(idc_bert_score["recall"])
    bert_score_f1 = sum(idc_bert_score["f1"]) / len(idc_bert_score["f1"])
    print(f"Bert Score Precision: {bert_score_precision}")
    print(f"Bert Score Recall: {bert_score_recall}")
    print(f"Bert Score F1: {bert_score_f1}")

    
    llm_bleu_score = BLEU_metric.compute(predictions=llm_generated_vulnerability_descriptions, references=real_vulnerability_descriptions)
    llm_rouge_score = Rouge_metric.compute(predictions=llm_generated_vulnerability_descriptions, references=real_vulnerability_descriptions)
    llm_bert_score = bertscore.compute(predictions=llm_generated_vulnerability_descriptions, references=real_vulnerability_descriptions, lang="en")
    print()
    print('For the llm descriptions during code synthesis:')
    print(f"BLEU Score: {llm_bleu_score}")
    print(f"Rouge Score: {llm_rouge_score}")
    bert_score_precision = sum(llm_bert_score["precision"]) / len(llm_bert_score["precision"])
    bert_score_recall = sum(llm_bert_score["recall"]) / len(llm_bert_score["recall"])
    bert_score_f1 = sum(llm_bert_score["f1"]) / len(llm_bert_score["f1"])
    print(f"Bert Score Precision: {bert_score_precision}")
    print(f"Bert Score Recall: {bert_score_recall}")
    print(f"Bert Score F1: {bert_score_f1}")



    print("Total number of samples: ", len(os.listdir(synthesized_root_dir)))
    print(f"False Positive: {false_positive}")
    fp_save_path = os.path.join( os.path.dirname(output_dir), "false_positive.json")
    json.dump(idc_false_positive, open(fp_save_path, "w"), indent=4)
    print(f"False Negative: {false_negative}")
    fn_save_path = os.path.join( os.path.dirname(output_dir), "false_negative.json")
    json.dump(idc_false_negative, open(fn_save_path, "w"), indent=4)
    print(f"Accuracy: {acc/len(os.listdir(synthesized_root_dir))}")
    recall = true_positive / real_positive
    print(f"Recall: {recall}")


    print(f"CWE Identifier Accuracy: {cwe_acc/len(os.listdir(synthesized_root_dir))}")
    # json.dump(idc_false_positive, open(fp_save_path, "w"), indent=4)
if __name__ == "__main__":
    asyncio.run(main())
