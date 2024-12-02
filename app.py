from flask import Flask, render_template, jsonify
from db_handler import db, init_db, add_vulnerability, get_all_vulnerabilities
import requests
import re
import os
import asyncio

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# API kEY AND INFO for Puya's account!
base_url = "https://www.cvedetails.com/api/v1/vulnerability/search"
headers = {
    "Authorization": "Bearer f8741cc811e00fdd3805c4275db0e71e75f474b7.eyJzdWIiOjgzNzcsImlhdCI6MTczMjg1MzgxOCwiZXhwIjoxNzM1NjAzMjAwLCJraWQiOjEsImMiOiJNcEdPZWdsSmFURXB2QUE0UnRYWG9zS0MwWWJWb0N5Tkg5QklvTmxRR3hpY2VmRHpqaloxWk42blRDSkRHMzFRaDREYUR0dmMifQ==",
    "accept": "application/json"
}

init_db(app)


#def fetch_data_cvsdetails():
#    fetch_data_cvsdetails_tech(2012 ,1 , 6)
#    fetch_data_cvsdetails_tech(2012 , 7 , 12)

def fetch_data_cvsdetails():
    for year in range(2012, 2013):
        fetch_data_cvsdetails_tech(year, 1, 6)
        fetch_data_cvsdetails_tech(year, 7, 12)


def fetch_data_cvsdetails_tech(year, start_month, end_month):
    with app.app_context():
        print("here2")
        #for page in range(1, 3):  # Loop for up to 5 pages
        #url = f"{base_url}?outputFormat=json&publishDateStart={start_year}-0{start_month}-01&publishDateEnd={end_year}-0{end_month}-01&pageNumber={1}&resultsPerPage=50"
        url = f"{base_url}?outputFormat=json&publishDateStart={year}-{'0' + str(start_month) if start_month < 10 else str(start_month)}-01&publishDateEnd={year}-{'0' + str(end_month) if end_month < 10 else str(end_month)}-01&pageNumber={1}&resultsPerPage=50"
        print(url)  # Debugging: print the URL being requested
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('results', [])
            for item in data:
                add_vulnerability(item)



def reset_database():
    with app.app_context():
        db.drop_all() 
        db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/fetch', methods=['GET'])
def fetch_data():
    records = get_all_vulnerabilities()
    data = [record.data for record in records]
    return jsonify(data)

@app.route('/count', methods=['GET'])
def count_records():
    records = get_all_vulnerabilities()
    return jsonify({"count": len(records)})


@app.route('/fetch-data', methods=['POST'])
def fetch_data_from_api():
    try:
        fetch_data_cvsdetails()
        return jsonify({"message": "Data fetched successfully!"}), 200
    except Exception as e:
        return jsonify({"message": f"Error fetching data: {e}"}), 500

 
if __name__ == "__main__":
    with app.app_context():
        reset_database()
    app.run(debug=True)