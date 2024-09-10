


from cryptography.fernet import Fernet 
  
  
key = Fernet.generate_key() 
print(key)
print("-------------------------------------------------\n")
f = Fernet(key) 

message = input("enter the message : \n")
# token = f.encrypt(b"welcome to geeksforgeeks") 
token = f.encrypt(b'message')

print("-------------------------------------------------\n")

  
print(token) 
  
d = f.decrypt(token) 
  
print(d.decode()) 
