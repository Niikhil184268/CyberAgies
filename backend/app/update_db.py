import sqlite3

DB_PATH = "database/cyberagis.db"

connection = sqlite3.connect(DB_PATH)
cursor = connection.cursor()

cursor.execute("""
    ALTER TABLE findings
    ADD COLUMN remediation TEXT
""")

connection.commit()
connection.close()

print("Database updated successfully")