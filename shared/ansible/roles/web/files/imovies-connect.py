import mysql.connector

mydb = mysql.connector.connect(
    host="db",
    user="admin",
    password="admin",
    database="imovies"
)

mycursor = mydb.cursor()

mycursor.execute("SELECT * FROM users")
myresult = mycursor.fetchall()

for x in myresult:
    print(x)
