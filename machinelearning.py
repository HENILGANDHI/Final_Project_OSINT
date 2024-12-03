import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
import numpy as np

def run_linear_regression(vulnerabilities):
    data = pd.DataFrame([record.data for record in vulnerabilities])
    
    # Ensure cveYear is numeric
    data['cveYear'] = pd.to_numeric(data['cveYear'], errors='coerce')  
    data.dropna(subset=['cveYear'], inplace=True) 
    data['cveYear'] = data['cveYear'].astype(int) 

    numeric_columns = ['maxCvssBaseScore', 'configCount', 'weaknessCount']
    for col in numeric_columns:
        data[col] = pd.to_numeric(data[col], errors='coerce')  
    data.fillna(0, inplace=True)  

    year_counts = data['cveYear'].value_counts().sort_index()
    df = pd.DataFrame({'cveYear': year_counts.index, 'vulnerabilityCount': year_counts.values})
    
    df['maxCvssBaseScore'] = data.groupby('cveYear')['maxCvssBaseScore'].mean().values
    df['configCount'] = data.groupby('cveYear')['configCount'].sum().values
    df['weaknessCount'] = data.groupby('cveYear')['weaknessCount'].sum().values
    
    df = df[df['vulnerabilityCount'] > 0]
    
    df['yearFromStart'] = df['cveYear'] - df['cveYear'].min()
    
    # Separate features and target
    X = df[['yearFromStart', 'maxCvssBaseScore', 'configCount', 'weaknessCount']]
    y = df['vulnerabilityCount']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Standardize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Use Gradient Boosting Regressor
    model = GradientBoostingRegressor(n_estimators=200, learning_rate=0.1, max_depth=3, random_state=42)
    model.fit(X_train_scaled, y_train)    
    future_years = pd.DataFrame({
        'cveYear': [2025, 2026, 2027, 2028],
        'yearFromStart': [year - df['cveYear'].min() for year in [2025, 2026, 2027, 2028]],
    })

    future_years['maxCvssBaseScore'] = np.polyval(
        np.polyfit(df['yearFromStart'], df['maxCvssBaseScore'], 1),
        future_years['yearFromStart']
    )
    future_years['configCount'] = np.polyval(
        np.polyfit(df['yearFromStart'], df['configCount'], 1),
        future_years['yearFromStart']
    )
    future_years['weaknessCount'] = np.polyval(
        np.polyfit(df['yearFromStart'], df['weaknessCount'], 1),
        future_years['yearFromStart']
    )
    
    future_years_scaled = scaler.transform(future_years[['yearFromStart', 'maxCvssBaseScore', 'configCount', 'weaknessCount']])
    predictions = model.predict(future_years_scaled)
    
    base_predictions = [max(0, int(pred)) for pred in predictions]
    adjusted_predictions = []
    for i, pred in enumerate(base_predictions):
        growth_factor = 1 + (0.5 * ((i*2) + 1))  
        adjusted_predictions.append(int(pred * growth_factor))
    
    for i in range(1, len(adjusted_predictions)):
        adjusted_predictions[i] = max(adjusted_predictions[i], adjusted_predictions[i - 1] + 5)
    
    return {year: pred for year, pred in zip(future_years['cveYear'], adjusted_predictions)}
