import secrets

# Generate a random secret key
secret_key = secrets.token_hex(32)

# Write the secret key to a .env file
with open(".env", "w") as env_file:
    env_file.write(f"SECRET_KEY={secret_key}\n")

print("Secret key generated and stored in .env file.")
