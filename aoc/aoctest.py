input_data  = open("/home/pheonix/Desktop/DEV_bkup/Hybrid-Encryption/aoc2.txt","r").read()
f = 0
n = len(input_data)

for i in range(n - 1):
    diff = abs(input_data[i + 1] - input_data[i])
    if diff < 1 or diff > 3:



# if all(report[i] < report[i + 1] for i in range(n - 1)):
#         f = 0
# if all(report[i] > report[i + 1] for i in range(n - 1)):
#         f = 1