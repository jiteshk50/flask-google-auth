import secrets

# Generate a random secret key
security_password_salt = secrets.token_hex(32)

# Write the secret key to a .env file
with open(".env", "w") as env_file:
    env_file.write(f"SECURITY_PASSWORD_SALT={security_password_salt}\n")

print("security_password_salt key generated and stored in .env file.")
