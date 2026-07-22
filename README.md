# 🛡️ DNSGuard AI

> Machine Learning-powered DNS Threat Detection System

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-black)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

# 🌐 Live Demo

https://dnsguard-ai-1.onrender.com

---

# 📌 Project Overview

DNSGuard AI is a Machine Learning-based web application that analyzes DNS-related information to identify whether a domain is safe or potentially associated with suspicious DNS activity.

The system combines feature engineering, machine learning, and an interactive web dashboard to help users better understand DNS behavior.

---

# 🚀 Features

- DNS Threat Prediction
- Interactive Dashboard
- Machine Learning Model Comparison
- Prediction History
- Batch Analysis
- Feature Engineering
- Responsive User Interface
- Live Web Deployment

---

# 📸 Screenshots

## 🏠 Home Page

![Home](assets/home.png)

## 🔍 Prediction Result

![Prediction](assets/prediction.png)

## 📊 Dashboard

![Dashboard](assets/dashboard.png)

## 📜 History

![History](assets/history.png)

## 🤖 Model Information

![Model](assets/model_info.png)

---

# 🛠️ Tech Stack

## Frontend

- HTML5
- CSS3
- JavaScript

## Backend

- Flask
- Python

## Machine Learning

- Scikit-Learn
- Pandas
- NumPy

## Deployment

- Render

## Version Control

- Git
- GitHub

---

# 📂 Dataset

The project uses a custom dataset containing DNS-related features.

Features include:

- Domain Length
- Subdomain Length
- Number of Labels
- Longest Label
- Shannon Entropy
- Randomness Score
- Character Diversity
- Digit Ratio
- Character Distribution
- Base64 Detection
- Base32 Detection
- Hex Detection
- Query Type
- TTL
- Response Time
- TXT Record
- NXDOMAIN
- Domain Age
- SSL Presence
- Reputation Score

Target:

- Safe
- Potential DNS Security Threat

---

# 🤖 Machine Learning Models

| Model | Accuracy |
|-------|-----------|
| Logistic Regression | 99.90% |
| Random Forest | 99.85% |
| Decision Tree | 99.75% |

Final model used:

**Logistic Regression**

---

# 📂 Folder Structure

```text
DNSGuard-AI
│
├── assets/
├── datasets/
├── models/
├── notebook/
├── static/
├── templates/
├── app.py
├── dns_utils.py
├── feature_engineering.py
├── enrichment.py
├── explain.py
├── database.py
├── model_insights.py
├── requirements.txt
├── README.md
```

---

# ⚙️ Installation

Clone Repository

```bash
git clone https://github.com/mahakjain06/DNSGuard---AI.git
```

Move into project

```bash
cd DNSGuard---AI
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run application

```bash
python app.py
```

Open browser

```
http://127.0.0.1:5000
```

---

# 🎯 Future Improvements

- Explainable AI (SHAP)
- Live WHOIS Lookup
- Threat Risk Meter
- PDF Report Generation
- Real-Time DNS Monitoring
- Threat Timeline
- API Support

---

# 👩‍💻 Author

**Mahak Jain**

B.Tech Computer Science (AI & ML)

GitHub:
https://github.com/mahakjain06

---

⭐ If you found this project useful, consider giving it a Star!