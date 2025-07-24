import os
import libsql_client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

TURSO_URL = os.getenv("TURSO_DATABASE_URL")
TURSO_TOKEN = os.getenv("TURSO_AUTH_TOKEN")

print(f"Attempting to connect to: {TURSO_URL}")

if not TURSO_URL or not TURSO_TOKEN:
    print("Error: Database URL or Auth Token is missing from your .env file.")
else:
    try:
        with libsql_client.create_client_sync(
            url=TURSO_URL,
            auth_token=TURSO_TOKEN
        ) as client:
            result = client.execute("SELECT 1")
            print("\n✅ --- Success! --- ✅")
            print("Successfully connected to Turso and executed a query.")
            print("Result:", result.rows[0][0])
    except Exception as e:
        print("\n❌ --- Connection Failed! --- ❌")
        print("The test script failed with the following error:")
        print(e)