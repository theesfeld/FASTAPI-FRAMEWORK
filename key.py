import secrets
import bcrypt

# manually make a key
# youll need this


def generate_hashed_api_key():
    raw_api_key = secrets.token_urlsafe(32)
    hashed_api_key = bcrypt.hashpw(raw_api_key.encode(), bcrypt.gensalt())
    return raw_api_key, hashed_api_key.decode()


if __name__ == "__main__":
    raw_key, hashed_key = generate_hashed_api_key()
    print(f"Raw API Key (store this safely and use for authentication): {raw_key}")
    print(f"Hashed API Key (store this in the database): {hashed_key}")
