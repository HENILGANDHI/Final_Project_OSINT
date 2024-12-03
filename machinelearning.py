import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
import numpy as np

def run_linear_regression(vulnerabilities):
    
    data = pd.DataFrame([record.data for record in vulnerabilities])
    
    # Ensure cveYear is numeric
    data['cveYear'] = pd.to_numeric(data['cveYear'], errors='coerce')  # Convert to numeric, invalid values become NaN
    data.dropna(subset=['cveYear'], inplace=True)  # Drop rows where cveYear is NaN
    data['cveYear'] = data['cveYear'].astype(int)  # Convert to integers

    # Convert other numeric columns
    numeric_columns = ['maxCvssBaseScore', 'configCount', 'weaknessCount']
    for col in numeric_columns:
        data[col] = pd.to_numeric(data[col], errors='coerce')  # Convert to numeric
    data.fillna(0, inplace=True)  # Replace NaN values with 0

    # Count vulnerabilities by year
    year_counts = data['cveYear'].value_counts().sort_index()
    df = pd.DataFrame({'cveYear': year_counts.index, 'vulnerabilityCount': year_counts.values})
    
    # Add additional features
    df['maxCvssBaseScore'] = data.groupby('cveYear')['maxCvssBaseScore'].mean().values
    df['configCount'] = data.groupby('cveYear')['configCount'].sum().values
    df['weaknessCount'] = data.groupby('cveYear')['weaknessCount'].sum().values
    
    # Remove outliers and ensure positive counts
    df = df[df['vulnerabilityCount'] > 0]
    
    # Use year as an ordinal feature
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
    
    # Predict for future years
    future_years = pd.DataFrame({
        'cveYear': [2025, 2026, 2027, 2028],
        'yearFromStart': [year - df['cveYear'].min() for year in [2025, 2026, 2027, 2028]],
        'maxCvssBaseScore': df['maxCvssBaseScore'].mean(),
        'configCount': df['configCount'].mean(),
        'weaknessCount': df['weaknessCount'].mean()
    })
    future_years_scaled = scaler.transform(future_years[['yearFromStart', 'maxCvssBaseScore', 'configCount', 'weaknessCount']])
    predictions = model.predict(future_years_scaled)
    
    # Ensure predictions are non-negative
    predictions = [max(0, int(pred)) for pred in predictions]
    
    return {year: pred for year, pred in zip(future_years['cveYear'], predictions)}
