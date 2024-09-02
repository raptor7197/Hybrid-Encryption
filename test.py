#!/usr/bin/env python3
import string 
import random

def main():
    k = "Hello Worldhehe"
    result = ""
    for char in k:
        if char.isalpha():
            result += random.choice(string.ascii_letters)
        else:
            result += char
        print(result)

if __name__ == "__main__":
    main()