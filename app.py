from flask import Flask, render_template, jsonify
from db_handler import db, init_db, add_vulnerability, get_all_vulnerabilities
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np
from machinelearning import run_linear_regression



import matplotlib.pyplot as plt
from io import BytesIO
import base64



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




# Fetching Data from NVD
def fetch_data_nvd(year, start_month, end_month):
    with app.app_context():
        print("In fetch_data_nvd:")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-{'0' + str(start_month) if start_month < 10 else str(start_month)}-01T00:00:00Z&pubEndDate={year}-{'0' + str(end_month) if end_month < 10 else str(end_month)}-01T00:00:00Z"
        print(url)  # Debugging: print the URL being requested
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('vulnerabilities', [])
            for item in data:
                print(item)
                add_vulnerability(item)
        else:
            print(f"Failed to fetch data from NVD API: {response.status_code} - {response.text}")



#Fetching Data from OSV
def fetch_data_osv(year, start_month, end_month):
    with app.app_context():
        print("In fetch_data_osv:")
        url = f"https://api.osv.dev/v1/query?start={year}-{'0' + str(start_month) if start_month < 10 else str(start_month)}-01&end={year}-{'0' + str(end_month) if end_month < 10 else str(end_month)}-01"
        print(url)  # Debugging: print the URL being requested
        response = requests.post(url, headers=headers, json={})
        if response.status_code == 200:
            data = response.json().get('results', [])
            for item in data:
                print(item)
                add_vulnerability(item)
        else:
            print(f"Failed to fetch data from OSV API: {response.status_code} - {response.text}")





#Fetching Data from MITRE
def fetch_data_mitre(year, start_month, end_month):
    with app.app_context():
        print("In fetch_data_mitre:")
        url = f"https://mitre.example.org/api/vulnerabilities?startDate={year}-{'0' + str(start_month) if start_month < 10 else str(start_month)}-01&endDate={year}-{'0' + str(end_month) if end_month < 10 else str(end_month)}-01"
        print(url)  # Debugging: print the URL being requested
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('vulnerabilities', [])
            for item in data:
                print(item)
                add_vulnerability(item)
        else:
            print(f"Failed to fetch data from MITRE API: {response.status_code} - {response.text}")



def calculate_statistics():
    records = get_all_vulnerabilities()
    data = [float(record.data.get('maxCvssBaseScore', 0)) for record in records if record.data.get('maxCvssBaseScore')]
    if not data:
        return {
            "mean": 0,
            "std_dev": 0,
            "max": 0,
            "min": 0
        }
    return {
        "mean": round(np.mean(data), 2),
        "std_dev": round(np.std(data), 2),
        "max": max(data),
        "min": min(data)
    }



def format_vulnerability_data(vulnerabilities):
    formatted_data = []
    for vuln in vulnerabilities:
        record = vuln.data 
        assigner = "CVE DETAILS" if record.get("assigner") == "cve@mitre.org" else record.get("assigner", "Unknown")
    
        vulnerability_type = []
        for key, label in {
            "isOverflow": "Overflow",
            "isMemoryCorruption": "MemoryCorruption",
            "isSqlInjection": "SqlInjection",
            "isXss": "Xss",
            "isDirectoryTraversal": "DirectoryTraversal",
            "isFileInclusion": "FileInclusion",
            "isCsrf": "Csrf",
            "isXxe": "Xxe",
            "isSsrf": "Ssrf",
            "isOpenRedirect": "OpenRedirect",
            "isInputValidation": "InputValidation",
            "isCodeExecution": "CodeExecution",
            "isBypassSomething": "BypassSomething",
            "isGainPrivilege": "GainPrivilege",
            "isDenialOfService": "DenialOfService",
            "isInformationLeak": "InformationLeak",
            "isUsedForRansomware": "UsedForRansomware",
        }.items():
            if record.get(key) == "1":
                vulnerability_type.append(label)

        if not vulnerability_type:
            vulnerability_type.append("UnKnown")

        formatted_data.append({
            "assigner": assigner,
            "cveId": record.get("cveId"),
            "cveYear": record.get("cveYear"),
            "publishDate": record.get("publishDate"),
            "cvssScore": record.get("maxCvssBaseScore"),
            "exploitabilityScore": record.get("maxCvssExploitabilityScore"),
            "impactScore": record.get("maxCvssImpactScore"),
            "vulnerabilityType": ", ".join(vulnerability_type),
            "description" : record.get("summary"), 
        })
    return formatted_data







def fetch_page_data(url):
    """
    Fetches data from a single page and handles rate limiting.
    """
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('results', [])
            print(response.status_code )
            return data
        elif response.status_code == 429:  # Handle rate limiting
            retry_after = int(response.headers.get('Retry-After', 50))
            print(f"Rate limit reached. Retrying after {retry_after} seconds...")
            time.sleep(retry_after)
            return fetch_page_data(url)  # Retry
        else:
            print(f"Error fetching URL {url}: {response.status_code}")
            return []
    except Exception as e:
        print(f"Exception occurred for URL {url}: {e}")
        return []




def fetch_data_cvsdetails_tech(year, start_month, end_month):
    with app.app_context():
        max_pages = 2
        results_per_page = 50
        urls = [
            f"{base_url}?outputFormat=json&publishDateStart={year}-{'0' + str(start_month) if start_month < 10 else str(start_month)}-01&publishDateEnd={year}-{'0' + str(end_month) if end_month < 10 else str(end_month)}-01&pageNumber={page}&resultsPerPage={results_per_page}"
            for page in range(1, max_pages + 1)
        ]

        all_data = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_url = {executor.submit(fetch_page_data, url): url for url in urls}
            for future in as_completed(future_to_url):
                try:
                    data = future.result()
                    if data:
                        for item in data:
                            try:
                                add_vulnerability(item)
                            except Exception as e:
                                print(f"Error adding vulnerability: {e}")
                        all_data.extend(data)
                except Exception as e:
                    print(f"Error processing future: {e}")
        
        print(f"Fetched {len(all_data)} vulnerabilities for {year}-{start_month} to {year}-{end_month}.")
        return all_data








def reset_database():
    with app.app_context():
        db.drop_all() 
        db.create_all()


#my routers:
@app.route('/')
def index():
    stats = calculate_statistics()
    return render_template('index.html', stats=stats)


@app.route('/get-stats', methods=['GET'])
def get_stats():
    stats = calculate_statistics()  
    return jsonify(stats) 


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
        for year in range(2012, 2024):
            fetch_data_cvsdetails_tech(year, 4, 7)
            #fetch_data_cvsdetails_tech(year, 7, 12)
        return jsonify({"message": "Data fetched successfully!"}), 200
    except Exception as e:
        return jsonify({"message": f"Error fetching data: {e}"}), 500

 
@app.route('/tables')
def tables():
    vulnerabilities = get_all_vulnerabilities()
    formatted_data = format_vulnerability_data(vulnerabilities)
    return render_template('tables.html', vulnerabilities=formatted_data)


@app.route('/charts')
def charts():
    return render_template('charts.html')


#@app.route('/Mlearning', methods=['GET'])
#def Mlearning():
#    try:
#        vulnerabilities = get_all_vulnerabilities()
#        predictions = run_linear_regression(vulnerabilities)
#        return render_template('mlearning.html', predictions=predictions)
#    except Exception as e:
#        return render_template('mlearning.html', error=str(e))




@app.route('/Mlearning', methods=['GET'])
def Mlearning():
    try:
        vulnerabilities = get_all_vulnerabilities()
        predictions = run_linear_regression(vulnerabilities)


        plt.figure(figsize=(8, 4))
        plt.plot(list(predictions.keys()), list(predictions.values()), marker='o', color='blue')
        plt.title("Predicted Vulnerabilities")
        plt.xlabel("Year")
        plt.ylabel("Number of Vulnerabilities")

        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode('utf8')
        plt.close()

        return render_template('mlearning.html', predictions=predictions, plot_url=plot_url)
    except Exception as e:
        return render_template('mlearning.html', error=str(e))





@app.route('/shutdown', methods=['POST'])
def shutdown():
    """
    Shuts down the Flask application.
    """
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()  # Shut down the server
    return jsonify({"message": "Server is shutting down..."}), 200

#Donut_Chart
@app.route('/charts-data', methods=['GET'])
def get_charts_data():
    records = get_all_vulnerabilities()
    vulnerability_counts = {
        "Overflow": 0,
        "MemoryCorruption": 0,
        "SqlInjection": 0,
        "Xss": 0,
        "DirectoryTraversal": 0,
        "FileInclusion": 0,
        "Csrf": 0,
        "Xxe": 0,
        "Ssrf": 0,
        "OpenRedirect": 0,
        "InputValidation": 0,
        "CodeExecution": 0,
        "BypassSomething": 0,
        "GainPrivilege": 0,
        "DenialOfService": 0,
        "InformationLeak": 0,
        "UsedForRansomware": 0,
    }

    for record in records:
        data = record.data
        for key, label in {
            "isOverflow": "Overflow",
            "isMemoryCorruption": "MemoryCorruption",
            "isSqlInjection": "SqlInjection",
            "isXss": "Xss",
            "isDirectoryTraversal": "DirectoryTraversal",
            "isFileInclusion": "FileInclusion",
            "isCsrf": "Csrf",
            "isXxe": "Xxe",
            "isSsrf": "Ssrf",
            "isOpenRedirect": "OpenRedirect",
            "isInputValidation": "InputValidation",
            "isCodeExecution": "CodeExecution",
            "isBypassSomething": "BypassSomething",
            "isGainPrivilege": "GainPrivilege",
            "isDenialOfService": "DenialOfService",
            "isInformationLeak": "InformationLeak",
            "isUsedForRansomware": "UsedForRansomware",
        }.items():
            if data.get(key) == "1": 
                vulnerability_counts[label] += 1

    return jsonify(vulnerability_counts)


@app.route('/bar-chart-data', methods=['GET'])
def calculate_severity():
    records = get_all_vulnerabilities() 
    severity_by_year = {}

    for record in records:
        year = record.data.get('cveYear')
        severity = record.data.get('maxCvssBaseScore')

        if year and severity:
            severity = float(severity)
            if year not in severity_by_year:
                severity_by_year[year] = {'total_severity': 0, 'count': 0}
            
            severity_by_year[year]['total_severity'] += severity
            severity_by_year[year]['count'] += 1


    avg_severity_by_year = {
        year: round(data['total_severity'] / data['count'], 2)
        for year, data in severity_by_year.items()
    }

    return jsonify(avg_severity_by_year)


@app.route('/area-chart-data', methods=['GET'])
def get_area_chart_data():
    records = get_all_vulnerabilities() 
    vulnerabilities_by_exploitability = {}

    for record in records:
        exploitability = record.data.get('maxCvssExploitabilityScore')
        if exploitability:
            exploitability = round(float(exploitability), 1)  # رند کردن به نزدیک‌ترین اعشار
            vulnerabilities_by_exploitability[exploitability] = vulnerabilities_by_exploitability.get(exploitability, 0) + 1

    sorted_vulnerabilities = dict(sorted(vulnerabilities_by_exploitability.items()))
    return jsonify(sorted_vulnerabilities)


if __name__ == "__main__":
    with app.app_context():
        reset_database()
    app.run(debug=True)