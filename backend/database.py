import os
from pathlib import Path
import mysql.connector
import mysql.connector.pooling
from dotenv import load_dotenv

# Load environment variables: check backend/.env first, then root .env
_current_dir = Path(__file__).resolve().parent
_root_dir = _current_dir.parent

if (_current_dir / ".env").exists():
    load_dotenv(_current_dir / ".env")
if (_root_dir / ".env").exists():
    load_dotenv(_root_dir / ".env")
load_dotenv()

# MySQL database configuration (explicitly configured for UTC)
DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "time_zone": "+00:00"
}

# Thread-safe MySQL connection pool
_pool = None


def init_pool(pool_name="netsentry_pool", pool_size=5):
    global _pool
    if _pool is None:
        try:
            _pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name=pool_name,
                pool_size=pool_size,
                pool_reset_session=True,
                **DB_CONFIG
            )
        except mysql.connector.Error as error:
            print(f"[DATABASE POOL INIT ERROR] {error}")
            _pool = None
    return _pool


def get_db_connection():
    global _pool

    if _pool is None:
        init_pool()

    if _pool is not None:
        try:
            return _pool.get_connection()
        except mysql.connector.Error as pool_err:
            print(f"[DATABASE POOL WARNING] Fallback to direct connection: {pool_err}")

    # Fallback direct connection
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except mysql.connector.Error as error:
        print(f"[DATABASE ERROR] {error}")

    return None
