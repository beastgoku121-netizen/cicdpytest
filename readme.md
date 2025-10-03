# 📄 CI/CD Pipeline Test Report – Flask ToDo App

## 🏷️ Project Details
- **Project Name**: Flask ToDo Application with CI/CD  
- **Author/Tester**: Deepanshu Agarwal
- **Date**: 03/oct/2025
- **Repository Link**: https://github.com/beastgoku121-netizen/cicdpytest.git

---

## 🎯 Objective
The objective of this project was to:
- Build a simple Flask ToDo application.  
- Write unit tests using `pytest`.  
- Integrate automated testing into a CI/CD pipeline using GitHub Actions.  
- Ensure that code quality, formatting, and coverage are enforced automatically.  

---

## ⚙️ CI/CD Workflow Overview
The pipeline is triggered on:
- Pushes to the `main` branch  
- Pull requests targeting `main`  

### **Pipeline Steps**
1. Checkout repository  
2. Setup Python environment (v3.11)  
3. Install dependencies from `requirements.txt`  
4. Run quality checks (flake8, black, mypy)  
5. For a security check we should also have use a safety type of extenstion of python
5. Run unit tests with `pytest`  
6. Generate test coverage (XML + HTML)  
7. Upload coverage reports as artifacts  

---

## 🧪 Testing Strategy

### **Unit Testing**
- Each ToDo route (add, update, delete, list tasks) tested with pytest.  
- Edge cases included (invalid inputs, empty task names).  
- Fixtures used for setting up test data.  

### **Integration Testing**
- Tested API endpoints using Flask test client.  
- Verified correct responses for valid and invalid requests.  



## 📊 Results & Observations

### ✅ Successful Pipeline Run
- All tests passed  
- Linting and formatting checks successful  
- Coverage report generated  

**Screenshot:**  
*(Insert pipeline green screenshot here)*  

---

### ❌ Failure Case (Sample)
- Introduced a failing test (`assert 2+2 == 5`)  
- Pipeline failed at test stage, merge blocked  

**Screenshot:**  
*(Insert pipeline red screenshot here)*  

---

### 📈 Coverage Report
- Coverage achieved: **XX%**  
- Coverage artifacts uploaded in GitHub Actions  
- HTML report available for download  

**Screenshot:**  
*(Insert coverage screenshot here)*  

---

## 📝 Issues & Fixes
- Example: Git user email not set → Fixed with `git config`.  
- Example: Dependency version mismatch → Updated `requirements.txt`.  
- Example: Wrong PYTHONPATH → Fixed by setting `$GITHUB_ENV`.  

---

## 🚀 Future Improvements
- Add authentication (user login/signup).  
- Use PostgreSQL instead of SQLite.  
- Add deployment step (Docker + Heroku/AWS).  
- Add performance/load testing.  

---

## ✅ Conclusion
This project successfully demonstrated:  
- Writing and running unit tests with pytest.  
- Automating quality checks and coverage in CI/CD pipeline.  
- Blocking bad code merges (red pipeline) and enforcing code quality.  

The CI/CD pipeline ensures **reliable, consistent, and automated testing** for every code change.  

---



fail status badge:    [![Flask CI/CD Pipeline](https://github.com/beastgoku121-netizen/cicdpytest/actions/workflows/ci.yml/badge.svg)](https://github.com/beastgoku121-netizen/cicdpytest/actions/workflows/ci.yml)




pass status badge :  [![Flask CI/CD Pipeline](https://github.com/beastgoku121-netizen/cicdpytest/actions/workflows/ci.yml/badge.svg)](https://github.com/beastgoku121-netizen/cicdpytest/actions/workflows/ci.yml)







