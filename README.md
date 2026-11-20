# BAITWATCH — Phishing Defense Simulator

> Every inbox is a battlefield.

A safe phishing-simulation and security-awareness training platform with an AI email-risk classifier.
Every simulated link points only to `safe-training-domain.local`, and every phishing drill is labelled `[SIMULATION]`.

## Features

- **Mixed Bait Inbox**: phishing lures shuffled in with legitimate mail. Open, report or mark safe, and your defense score changes.
- **Shuffled Intel Quizzes**: 4 random questions from a bank of 10, with a review and explanations.
- **AI Threat Scanner**: a TF-IDF + Logistic Regression model scores the phishing risk of a draft drill.
- **Command Center**: stats, drill deployment, an agent leaderboard and a live interaction log.
- **Adaptive Training**: modules assigned based on each agent's clicks and score.

## Tech stack

- **Backend:** Python, FastAPI, Uvicorn, Pydantic, SQLAlchemy, SQLite (`baitwatch.db`)
- **AI:** scikit-learn `Pipeline(TfidfVectorizer, LogisticRegression)`
- **Frontend:** React 18 (UMD) + Babel Standalone, no build step (`App.jsx`, `style.css`)

## Run

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Open http://127.0.0.1:8000 (API docs at `/docs`). The database is created and seeded on first start.
Use **Reset simulation** in the Command Center (or `POST /api/admin/reset`) to restore the seed data.

## Scoring

| Action | Phishing email | Legitimate email |
|---|---|---|
| Open Link | −20, bait taken | no change |
| Report Threat | +10, threat reported | −5 (false alarm) |
| Mark Safe | −15 (missed threat) | +5 |
| Quiz bonus | `round(correct / total × 15, 1)` | |

Scores stay between 10 and 100.
