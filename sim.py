

import sys
import json
import time
import random
import tlsh
import networkx as nx
from tqdm import tqdm
import concurrent.futures

#Process command line argument
arg_num = len(sys.argv)
if arg_num < 2:
    print("Not enough arguments")
    sys.exit()
elif arg_num > 2:
    print("Too many arguments")
    sys.exit()
else:
    upper_threshold = int(sys.argv[1])


#log the current time
start_time = time.time()

#Define some grobal variable.
lower_threshold = 40
cloud_detection_rate = 0.95

#Scan a traget against dominating set and return the minimum score.
def scan(target, set):
    score_list = list()
    for x in set:
        score_list.append(tlsh.diff(target, x))
    return min(score_list)

#The thread target function.
#Arguments:
#pos: position for progress bar
#lower_threshold: lower threshold for TLSH simularity
#upper_threshold: upper threshold for TLSH simularity
#Return value:
#1. How many times a file is detected as malware localy
#2. How many times a hash is uploaded to the cloud
#3. The total smaple size
def simulation(pos, lower_threshold, upper_threshold):
    #Open the file comtaining malware sample
    malware_sample_file = open('data/TLSH_malware.txt', 'r')
    malware_full_list = malware_sample_file.readlines()
    malware_sample_file.close()

    #Create a progress bar
    single_len = int(0.1*len(malware_full_list)) + len(malware_full_list)
    total_len = single_len * 3
    pbar = tqdm(total=total_len, position=pos)

    #Setup counters
    local_detected_counter = 0
    upload_counter = 0

    #Loop 3 times
    for _ in range(3):
        #Randomly select 10% from the full malware list
        sample_list = random.sample(malware_full_list, int(0.1*len(malware_full_list)))
        sample_graph = nx.Graph() #Create empty graph
        sample_graph.add_nodes_from(sample_list) #Add all hash value as nodes

        for x in sample_list:
            for y in sample_list:

                score = tlsh.diff(x,y)
                if score <= upper_threshold:
                    sample_graph.add_edge(x,y)
            pbar.update(1)

        #Generate dominating set
        dominating_set = nx.dominating_set(sample_graph)

        #Loop malware sample and record result.
        for target in malware_full_list:
            score = scan(target, dominating_set)
            if score <= lower_threshold:
                local_detected_counter += 1
            elif score > lower_threshold and score <= upper_threshold:
                upload_counter += 1
            else:
                continue
            pbar.update(1)
    pbar.close()
    return [local_detected_counter, upload_counter, len(malware_full_list)*3]


# Create a list of arguments for the simulation function
args_list = [(i, lower_threshold, upper_threshold) for i in range(5)]

# Create a ThreadPoolExecutor with 5 threads
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    # Submit each simulation function to the executor
    futures = [executor.submit(simulation, *args) for args in args_list]

# Collect the return values from each future in a list
results = [future.result() for future in futures]

#Log the finish time and calculate process time
finish_time = time.time()
process_time = finish_time - start_time
print(f"\n\n\nTotal process time: {process_time}\n")

#Process data to calculate detection rate.
detection_rate_sum = 0
for result in results:
    detection_rate_sum += (result[0] + result[1] * cloud_detection_rate) / result[2]
detection_rate = detection_rate_sum / 5


#Create a report. Save is as json file
report = {"Time": process_time, "upper_threshold": upper_threshold, "detection_rate": detection_rate, "Raw data": results}
report_name = f"./report_{upper_threshold}.json"
with open(report_name, 'w') as report_file:
    json.dump(report, report_file)
print("Report saved at "+ report_name)
