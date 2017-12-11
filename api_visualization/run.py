from flask import Flask
from flask import render_template
import sqlite3

app = Flask(__name__, static_url_path='/static')

con = sqlite3.connect("C://api_visualization//data.db")
cursor = con.cursor()
cursor.execute('select name from sqlite_master where type="table"')
table_name = cursor.fetchall()
value_list = {}
name_list = {}
number_list = {}

for i in table_name:
    cursor.execute("select * from "+i[0])
    value = cursor.fetchall()
    name_list[i[0]] = []
    number_list[i[0]] = []
    for j in value:
        name_list[i[0]].append(j[1])
        number_list[i[0]].append(j[2])
        
con.close()
#print(name_list)
#print(number_list)

@app.route('/')
def main():
    return render_template('index.html',dllnames=table_name, values=value_list,names=name_list , numbers=number_list )

if __name__ == '__main__':
    app.run()
