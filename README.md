# Open-Source Vulnerability Intelligence Application (AVSA_APP)

## Project Overview
This project is designed to collect, analyze, and visualize software vulnerability data from multiple trusted sources, including **NVD**, **CVE**, **OSV**, and **MITRE**. The data is retrieved using specialized APIs for each repository, cleaned, standardized, and stored in a centralized database. The system provides actionable insights through interactive dashboards and predictive analytics to support security experts in identifying and addressing critical vulnerabilities.

![Screenshot 2024-12-03 030321](https://github.com/user-attachments/assets/d612ff8f-3c4b-4b43-bf1a-baab9ebb3f24)

## Features and Capabilities

1. **Data Collection and Integration**
   - Fetching data using APIs:
     - **CVE**: Utilizing `cve-search/api` for detailed vulnerability entries.
     - **NVD**: Fetching data via `nvd.nist.gov/api` for severity scores and metadata.
     - **OSV**: Accessing `osv.dev/api` for open-source vulnerability insights.
     - **MITRE**: Retrieving curated vulnerability summaries through `mitre.org/cve-api`.

2. **Data Management**
   - Cleaning and standardizing collected vulnerability data.
   - Centralized storage in a relational database for efficient querying and analysis.

3. **User-Friendly Interface**
   - Interactive and responsive design for seamless usage on various devices.
   - Organized tables with:
     - **Search and Filter Functionality**: Query vulnerabilities based on attributes like severity, CVSS scores, and type.
     - **Pagination**: Simplified navigation through large datasets.

4. **Data Visualization**
   - Intuitive charts to identify trends and patterns:
     - **Pie Charts**: Classification based on vulnerability types.
     - **Bar Charts**: Average severity of vulnerabilities by year.
     - **Area Charts**: Vulnerability count trends over time.

5. **Statistical Analysis**
   - Calculations including mean, standard deviation, and severity score distribution.
   - Comprehensive insights for cybersecurity teams.

6. **Machine Learning for Predictive Analytics**
   - Linear regression-based models to predict the number of vulnerabilities for future years using historical data.
   - Visualized predictions to aid in proactive risk management.

7. **Actionable Insights**
   - Detailed analysis by vulnerability type, year, and severity.
   - Empowering cybersecurity professionals to prioritize critical risks.

---

## Technical Stack

- **Backend**: Python (Flask framework)
- **Frontend**: HTML, CSS, JavaScript (with Chart.js for visualizations)
- **Database**: SQLite
- **APIs**: CVE, NVD, OSV, MITRE
- **Machine Learning**: Scikit-learn for regression-based predictions
- **Hosting**: Ready for deployment on cloud platforms like AWS or Azure

---

## Goals and Benefits

- **Empower Security Teams**: Deliver actionable insights for prioritizing vulnerabilities and mitigating risks effectively.
- **Enhance Software Resilience**: Identify trends such as the prevalence of bug types like buffer overflows or SQL injection.
- **Improve Decision-Making**: Provide visual and statistical clarity to support data-driven security decisions.

---

This project aims to bridge the gap between raw vulnerability data and actionable intelligence, fostering a secure software ecosystem for organizations of all sizes.
