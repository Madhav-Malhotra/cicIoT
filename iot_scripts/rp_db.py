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

    cursor = db.cursor()

    # Read file data
    with open(filepath, 'r') as f:
        lines = f.readlines()
   
    columns = lines[0].strip()
    num_cols = len(columns.split(','))
    values = [ tuple(l.strip().split(',')) for l in lines[1:] ] 
    
    # Add rows to database
    insert_query = f"INSERT INTO pcap ({columns}) VALUES ({ '%s, ' * (num_cols - 1) + '%s' })"
    try:
        cursor.executemany(insert_query, values)
        db.commit()
        print(f"Successfully stored data from {filepath} in SQL server")
    except Exception as e:
        print("ERROR:", e)

    # Close connection
    cursor.close()
    db.close()