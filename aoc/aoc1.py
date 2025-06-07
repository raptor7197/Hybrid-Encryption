# def split_numbers():
#     with open("text.txt", 'r') as file:
#         # Read the file and split its content into individual numbers
#         numbers = file.read().split()
    
#     # Convert the numbers to integers
#     numbers = [int(num) for num in numbers]
    
#     # Split into two arrays (example: even and odd)
#     # array1 = [num for num in numbers if num % 2 == 0]  # Even numbers
#     # array2 = [num for num in numbers if num % 2 != 0]  # Odd numbers

#     array1 = [numbers[i] for i in range(len(numbers)) if i % 2 == 0]  # Even index
#     array2 = [numbers[i] for i in range(len(numbers)) if i % 2 != 0]  # Odd index

    
#     return array1, array2   

# file_path = 'test.txt'

# array1, array2 = split_numbers( )
# print("Array 1 (Even Numbers):", sorted(array1))
# print("Array 2 (Odd Numbers):", sorted(array2))


# differences = [abs(a - b) for a, b in zip(array1, array2)]
# print(differences)
# k  = sum(differences)
# print(sum(differences))  # Output: 1

# import sys
# from pprint import pprint
# data=[[],[]]
# with open(sys.argv[1]) as f:
#   for line in f.read().splitlines():
#     for i,val in enumerate(line.split()):
#       data[i].append(int(val))
# data[0].sort()
# data[1].sort()
# pprint(sum([abs(data[0][j]-data[1][j]) for j in range(len(data[0]))]))
# pprint(sum([data[0][j]*data[1].count(data[0][j]) for j in range(len(data[0]))]))




data  = open("/home/pheonix/Desktop/DEV_bkup/Hybrid-Encryption/text.txt","r").read()
data = data.split()

arr1 = data[::2]
arr2 = data[1::2]


arr1 = list(map(int,arr1))
arr2 = list(map(int,arr2))

arr1.sort()
arr2.sort()

final=[]

for i in range (len(arr1)):
    final.append(abs(arr1[i]-arr2[i]))
print(sum(final))

# ---------------------------------------------
count = []
for num in arr1:
    count.append(arr2.count(num))

s = 0

for k in range(len(arr1)):
    s = s+(count[k]*arr1[k])

print(s)

