import pandas as pd
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

users_data = [
    {"users": "admin", "password": hash_password("1234"), "role": "admin", "avatar": "uploads/default.png"},
    {"users": "user1", "password": hash_password("4321"), "role": "user", "avatar": "uploads/default.png"}
]

df = pd.DataFrame(users_data, columns=["users", "password", "role", "avatar"])
df.to_csv("users.csv", index=False)
print("Файл users.csv успешно создан")