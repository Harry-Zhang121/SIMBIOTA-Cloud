import random
import tlsh
import networkx as nx

file = open('data/TLSH_malware.txt', 'r')
full_list = file.readlines()
file.close()


sample_list = random.sample(full_list, 2000)
print(sample_list[0])

for x in sample_list:

    score = tlsh.diffxlen(sample_list[0], x)
    if score <= 60:
        print(score)