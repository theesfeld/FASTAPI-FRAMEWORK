A framework to fast-track API server creation with FastAPI.

Includes API key management/access
Postgres logging and key storage
* Redis Cache

Make sure to create a `.env` file per the comment in main.py


use key.py from the command line to create your originating API key, store the hashed in the DB that was created after first run, and use the raw key in your requests.
