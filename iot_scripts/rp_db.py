import os
import mysql.connector 
from dotenv import load_dotenv     # configure .env BEFORE running script

def add_pcap_data(filepath : str) -> None:
    '''
    Reads CSV file and adds each row into database
    '''

    # Connect
    load_dotenv('.env')

    db = mysql.connector.connect(
        host = os.getenv("DB_HOST"),
        user = os.getenv("DB_USER"),
        passwd = os.getenv("DB_PASS"),
        database = os.getenv("DB_NAME")
    )

    # Read file data
    with open(filepath, 'r') as f:
        lines = f.readlines()

    # Add each row to database
    cursor = db.cursor()
    for l in lines[1:]:
        try:
            cursor.execute(f"INSERT INTO pcap ({lines[0].strip()}) VALUES ({l.strip()})")
        except Exception as e:
            print(e)

    # Close connection
    cursor.close()
    db.close()
    print(f"Successfully stored data from {filepath} in SQL server")