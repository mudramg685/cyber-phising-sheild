"""
BAITWATCH — Phishing Defense Simulator (backend)
=================================================

A SAFE phishing-simulation and security-awareness training platform.

  * FastAPI + Uvicorn web server
  * SQLAlchemy ORM on a local SQLite file (baitwatch.db)
  * scikit-learn TF-IDF + Logistic Regression email-risk classifier
  * Serves the React 18 single-page app (App.jsx + style.css) at "/"
    using React UMD + Babel Standalone (no build step)

Safety guarantees
-----------------
  * Every simulated link must point to safe-training-domain.local — the API
    rejects any other host, so a drill can never send people to a real site.
  * Every phishing drill subject is prefixed with [SIMULATION].
  * "Open Link" in the UI never navigates anywhere; it only records the
    interaction for scoring.

Run:  python main.py   ->   http://127.0.0.1:8000
"""

from __future__ import annotations

import os
import random
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Literal, Optional
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field, field_validator
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import Session, declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "baitwatch.db")

SAFE_DOMAIN = "safe-training-domain.local"
DEFAULT_URL = f"https://{SAFE_DOMAIN}/verify"
SIM_PREFIX = "[SIMULATION]"

SCORE_MIN, SCORE_MAX = 10.0, 100.0
QUIZ_MAX_BONUS = 15


def utcnow() -> datetime:
    """Timezone-aware 'now' (SQLite stores it naive; we re-attach UTC on output)."""
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime]) -> Optional[str]:
    """Serialise a datetime as ISO-8601 UTC so the browser can localise it."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def clamp_score(value: float) -> float:
    """Defense scores always stay between 10 and 100."""
    return round(max(SCORE_MIN, min(SCORE_MAX, value)), 1)


# ---------------------------------------------------------------------------
# Database setup (SQLAlchemy ORM + SQLite)
# ---------------------------------------------------------------------------
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},  # FastAPI runs sync routes in a thread pool
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Agent(Base):
    """An employee ('agent') who receives drills and earns a defense score."""

    __tablename__ = "agents"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(200), unique=True, nullable=False, index=True)
    department = Column(String(80), nullable=False)
    role = Column(String(20), nullable=False, default="Agent")  # Agent / Admin
    defense_score = Column(Float, nullable=False, default=100.0)
    drills_received = Column(Integer, nullable=False, default=0)
    baits_taken = Column(Integer, nullable=False, default=0)  # links clicked
    threats_reported = Column(Integer, nullable=False, default=0)


class Drill(Base):
    """A simulated email — either phishing bait or a legitimate message."""

    __tablename__ = "drills"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(160), nullable=False)
    sender = Column(String(200), nullable=False)
    subject = Column(String(240), nullable=False)
    body_text = Column(Text, nullable=False)
    simulated_url = Column(String(300), nullable=False, default=DEFAULT_URL)
    difficulty = Column(String(10), nullable=False, default="Medium")  # Easy/Medium/Hard
    is_suspicious = Column(Boolean, nullable=False, default=True)
    red_flags = Column(Text, nullable=False, default="")  # one flag per line
    created_at = Column(DateTime, nullable=False, default=utcnow)


class Interaction(Base):
    """One action an agent took on a drill."""

    __tablename__ = "interactions"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    drill_id = Column(Integer, ForeignKey("drills.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(20), nullable=False)  # opened / clicked_link / reported / marked_safe
    timestamp = Column(DateTime, nullable=False, default=utcnow)


class QuizSubmission(Base):
    """A graded quiz attempt."""

    __tablename__ = "quiz_submissions"
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    total = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=utcnow)


def get_db():
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
SEED_AGENTS = [
    dict(name="Mara Okafor", email="mara.okafor@nexacorp.com", department="Finance", role="Agent", defense_score=85.0),
    dict(name="Devon Reyes", email="devon.reyes@nexacorp.com", department="HR", role="Agent", defense_score=95.0),
    dict(name="Priya Nandakumar", email="priya.n@nexacorp.com", department="IT Ops", role="Agent", defense_score=70.0),
    dict(name="Sam Kowalczyk", email="sam.k@nexacorp.com", department="Security Admin", role="Admin", defense_score=100.0),
]

SEED_DRILLS = [
    # ---- Phishing #1: urgent account verification from a look-alike .biz domain
    dict(
        title="Urgent Account Verification",
        sender="NexaCorp IT Security <security-alerts@nexac0rp-secure.biz>",
        subject=f"{SIM_PREFIX} URGENT: Verify your account within 24 hours or lose access",
        body_text=(
            "Dear User,\n\n"
            "Our security system detected unusual sign-in activity on your NexaCorp account. "
            "To prevent permanent suspension, you must verify your identity within 24 HOURS.\n\n"
            "Click the secure link below and re-enter your username and password to confirm "
            "your account ownership. Failure to comply will result in immediate account lockout "
            "and loss of all mailbox data.\n\n"
            "Thank you for your cooperation,\nIT Security Team"
        ),
        simulated_url=f"https://{SAFE_DOMAIN}/verify",
        difficulty="Medium",
        is_suspicious=True,
        red_flags=(
            "Look-alike sender domain: nexac0rp-secure.biz (zero instead of 'o', .biz TLD) — real domain is nexacorp.com\n"
            "Artificial 24-hour deadline with a threat of account lockout\n"
            "Generic greeting ('Dear User') instead of your name\n"
            "Asks you to re-enter your password through an emailed link"
        ),
    ),
    # ---- Phishing #2: fake parcel delivery exception
    dict(
        title="Parcel Delivery Exception",
        sender="ParcelXpress Notifications <tracking@parcelxpress-delivery.info>",
        subject=f"{SIM_PREFIX} Delivery Exception: Action required for parcel #DX-48812",
        body_text=(
            "Hello,\n\n"
            "We attempted to deliver your parcel #DX-48812 today but no one was available to sign for it.\n\n"
            "Your package is being held at our depot. To reschedule delivery, please confirm your "
            "address and pay the redelivery fee of $1.99 using the link below. Parcels not claimed "
            "within 48 hours will be returned to sender.\n\n"
            "ParcelXpress Customer Care"
        ),
        simulated_url=f"https://{SAFE_DOMAIN}/parcel-reschedule",
        difficulty="Easy",
        is_suspicious=True,
        red_flags=(
            "Unexpected delivery you never ordered, sent to your work inbox\n"
            "Small 'redelivery fee' payment request — a classic card-harvesting lure\n"
            "Sender domain (parcelxpress-delivery.info) doesn't match any official carrier\n"
            "48-hour pressure deadline to make you act without thinking"
        ),
    ),
    # ---- Legitimate #1: all-hands meeting invite
    dict(
        title="Q4 All-Hands Meeting",
        sender="Office of the CEO <ceo-office@nexacorp.com>",
        subject="Q4 All-Hands Meeting — Thursday 3:00 PM, Main Auditorium",
        body_text=(
            "Hi team,\n\n"
            "Join us this Thursday at 3:00 PM in the Main Auditorium (or via the usual Teams link in "
            "your calendar) for our Q4 All-Hands. We'll cover the year in review, the 2027 roadmap, "
            "and recognise this quarter's outstanding contributors.\n\n"
            "The invite is already on your calendar — no action needed beyond accepting it.\n\n"
            "See you there,\nOffice of the CEO"
        ),
        simulated_url=f"https://{SAFE_DOMAIN}/calendar/all-hands",
        difficulty="Easy",
        is_suspicious=False,
        red_flags="",
    ),
    # ---- Legitimate #2: IT maintenance notice
    dict(
        title="Scheduled Email Maintenance",
        sender="IT Operations <it-ops@nexacorp.com>",
        subject="Scheduled Maintenance: Email services Saturday 22:00–02:00",
        body_text=(
            "Hello everyone,\n\n"
            "As announced in the IT change calendar (CHG-20931), email services will undergo "
            "planned maintenance this Saturday between 22:00 and 02:00. You may experience brief "
            "delays sending or receiving mail during this window.\n\n"
            "You do NOT need to take any action, and IT will never ask for your password. "
            "Status updates will be posted on the internal IT status page.\n\n"
            "Thanks,\nIT Operations"
        ),
        simulated_url=f"https://{SAFE_DOMAIN}/status",
        difficulty="Medium",
        is_suspicious=False,
        red_flags="",
    ),
]


def seed_database(db: Session) -> None:
    """Insert demo agents and drills if the tables are empty."""
    if db.query(Agent).count() == 0:
        for a in SEED_AGENTS:
            # Every seeded agent has already 'received' the seeded drills.
            db.add(Agent(**a, drills_received=len(SEED_DRILLS)))
    if db.query(Drill).count() == 0:
        for d in SEED_DRILLS:
            db.add(Drill(**d))
    db.commit()


# ---------------------------------------------------------------------------
# Adaptive training modules
# ---------------------------------------------------------------------------
MODULES = {
    "core": dict(
        id="core",
        title="Core Phishing Warning Signs",
        summary="The universal tells that give away most phishing emails — learn to spot them in seconds.",
        tips=[
            "Check the real sender address, not just the display name — look-alike domains (nexac0rp.biz) are the #1 tell.",
            "Be suspicious of urgency, threats or rewards that push you to act before you think.",
            "Legitimate IT, HR and banks never ask you to type your password through an emailed link.",
            "Unexpected attachments or generic greetings ('Dear User') deserve a second look.",
        ],
        reason="Assigned to every agent.",
    ),
    "links": dict(
        id="links",
        title="Safe Link & URL Inspection",
        summary="You've taken the bait before. This module drills how to read a URL before it reads you.",
        tips=[
            "Hover (or long-press on mobile) to preview the real destination before clicking.",
            "Read the domain right-to-left from the first single '/': login.microsoft.com.evil.biz belongs to evil.biz.",
            "Watch for typosquats: rn vs m, 0 vs o, 1 vs l, and extra hyphens or words like '-secure'.",
            "When in doubt, type the known address yourself or use a bookmark instead of the link.",
        ],
        reason="Assigned because you clicked at least one bait link.",
    ),
    "social": dict(
        id="social",
        title="Social Engineering & Urgency Tactics",
        summary="Attackers hack people, not machines. Recognise the pressure levers they pull.",
        tips=[
            "Authority + urgency + secrecy ('the CEO needs this now, don't tell anyone') is a classic BEC pattern.",
            "Verify unusual requests through a second, known channel — call the person, don't reply to the email.",
            "Never approve MFA prompts you didn't trigger; a flood of pushes means someone has your password.",
            "Slow down: a 60-second pause defeats most manufactured deadlines.",
        ],
        reason="Assigned because your defense score is below 80.",
    ),
}


def modules_for(agent: Agent) -> list:
    """Adaptive logic: pick modules from the agent's track record."""
    assigned = [MODULES["core"]]
    if agent.baits_taken > 0:
        assigned.append(MODULES["links"])
    if agent.defense_score < 80:
        assigned.append(MODULES["social"])
    return assigned


# ---------------------------------------------------------------------------
# Quiz bank (answers never leave the server until grading)
# ---------------------------------------------------------------------------
QUIZ_BANK = [
    dict(
        id=1, topic="HR Payroll Phishing",
        question="An email from 'HR Payroll <payroll@nexacorp-hrportal.net>' says your direct deposit will be paused unless you sign in within 2 hours. What should you do?",
        options=[
            "Sign in quickly so your salary isn't delayed",
            "Reply with your employee ID so HR can check",
            "Report it and contact HR through a known channel (intranet or phone)",
            "Forward it to colleagues so they can update their details too",
        ],
        answer=2,
        explanation="Payroll lures pair money with urgency. The domain isn't nexacorp.com — report it and verify with HR through a channel you already trust.",
    ),
    dict(
        id=2, topic="Link Hovering",
        question="Why should you hover over a link before clicking it?",
        options=[
            "It pre-loads the page so it opens faster",
            "It reveals the actual destination URL, which may differ from the displayed text",
            "It scans the link for viruses automatically",
            "It tells the sender you've read the email",
        ],
        answer=1,
        explanation="Link text can say anything. Hovering shows the real target so you can spot mismatched or look-alike domains.",
    ),
    dict(
        id=3, topic="Typosquatting",
        question="Which of these domains is a typosquat designed to impersonate Microsoft?",
        options=[
            "microsoft.com",
            "account.microsoft.com",
            "micros0ft-support.com",
            "login.microsoftonline.com",
        ],
        answer=2,
        explanation="'micros0ft' swaps the letter o for a zero and adds '-support' — a classic typosquat. The others are genuine Microsoft domains.",
    ),
    dict(
        id=4, topic="MFA Fatigue",
        question="At 2 AM your phone shows 15 MFA push requests you didn't trigger. What is happening and what should you do?",
        options=[
            "An app glitch — approve one so they stop",
            "MFA fatigue / push bombing — deny every prompt, report it and change your password",
            "IT is testing the system — ignore them",
            "Your phone has a virus — factory reset it",
        ],
        answer=1,
        explanation="Push bombing means an attacker already has your password and hopes you'll approve out of annoyance. Deny, report and reset your password.",
    ),
    dict(
        id=5, topic="CEO Gift-Card BEC",
        question="A message 'from the CEO' asks you to urgently buy $500 of gift cards for a client and keep it confidential. What's the right move?",
        options=[
            "Buy them — it's the CEO",
            "Buy them but ask for a receipt afterwards",
            "Verify through a known channel (call the CEO's office) and report the message",
            "Reply asking which gift-card brand they prefer",
        ],
        answer=2,
        explanation="Authority + urgency + secrecy + gift cards is textbook Business Email Compromise. Verify out-of-band, never through the same thread.",
    ),
    dict(
        id=6, topic="Double Extensions",
        question="You receive an attachment named 'Invoice_2026.pdf.exe'. What is it?",
        options=[
            "A PDF that's been compressed",
            "A PDF that needs a special reader",
            "An executable program disguised as a PDF — don't open it, report it",
            "A harmless file Windows renamed automatically",
        ],
        answer=2,
        explanation="Only the last extension counts. '.pdf.exe' is a program dressed up as a document — opening it would run code on your machine.",
    ),
    dict(
        id=7, topic="QR-Code Quishing",
        question="An email asks you to scan a QR code to 're-activate your parking permit'. What's the risk?",
        options=[
            "None — QR codes can't contain links",
            "QR codes hide the destination URL and bypass email link scanners (quishing)",
            "It might drain your phone battery",
            "QR codes only work on company phones",
        ],
        answer=1,
        explanation="Quishing hides a malicious URL inside an image so filters miss it. Check the URL preview your camera shows, or go to the official portal directly.",
    ),
    dict(
        id=8, topic="Legitimate Internal Email",
        question="Your manager emails from their usual @nexacorp.com address, with no links or attachments, reminding you about tomorrow's stand-up that's already on your calendar. Best classification?",
        options=[
            "Phishing — all reminders are suspicious",
            "Likely legitimate — mark it safe, no action needed",
            "Report it to be safe",
            "Delete it without reading",
        ],
        answer=1,
        explanation="Known sender, expected content, no requests for data and no links: this is normal business email. Over-reporting creates alert fatigue.",
    ),
    dict(
        id=9, topic="Tech-Support Scareware",
        question="A browser pop-up says 'VIRUS DETECTED! Call Microsoft Support at 1-800-…' and seems to lock your screen. What do you do?",
        options=[
            "Call the number immediately",
            "Download the 'cleaner' tool it offers",
            "Close the browser (Task Manager if needed), don't call, and tell IT",
            "Enter your password to unlock the screen",
        ],
        answer=2,
        explanation="Real vendors never put phone numbers in pop-ups. It's scareware designed to get remote access or payment. Close it and report.",
    ),
    dict(
        id=10, topic="After the Click",
        question="You clicked a link in a simulated phishing drill and landed on a training page. What should you do next?",
        options=[
            "Nothing — it was only a drill",
            "Delete the email and hope nobody noticed",
            "Report the email right away and review the training — fast reporting limits damage in a real attack",
            "Clear your browser history",
        ],
        answer=2,
        explanation="In a real attack, the first minutes matter. Reporting quickly lets security block the campaign and reset credentials before harm spreads.",
    ),
]
QUIZ_BY_ID = {q["id"]: q for q in QUIZ_BANK}


# ---------------------------------------------------------------------------
# AI email-risk classifier (TF-IDF + Logistic Regression)
# ---------------------------------------------------------------------------
TRAINING_TEXTS = [
    # --- phishing (label 1)
    "URGENT your account will be suspended immediately verify now or lose access",                 # urgency
    "Confirm your password and login credentials at this secure link to keep your mailbox active",  # credential
    "Congratulations you have won a prize claim your free gift card reward today click here",       # prize
    "Payroll update required your salary direct deposit is on hold sign in to confirm bank details", # payroll
    "Final notice overdue invoice payment required today to avoid penalty and legal action",        # invoice-penalty
    # --- benign (label 0)
    "Team meeting moved to Thursday at 3pm in conference room B agenda attached",                   # meeting
    "Product roadmap review for next quarter please add comments to the planning document",        # roadmap
    "Monthly company newsletter highlights employee spotlight and upcoming social events",         # newsletter
    "Sprint retrospective notes and action items from this week's engineering standup",            # sprint notes
    "Scheduled server maintenance this weekend no action needed services may be briefly slower",   # maintenance
]
TRAINING_LABELS = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
ALGORITHM_NAME = "TF-IDF Vectorizer + Logistic Regression (scikit-learn Pipeline)"


def build_classifier() -> Pipeline:
    """Train the tiny demo classifier once at startup."""
    model = Pipeline([
        ("tfidf", TfidfVectorizer(stop_words="english", lowercase=True)),
        ("clf", LogisticRegression()),
    ])
    model.fit(TRAINING_TEXTS, TRAINING_LABELS)
    return model


classifier = build_classifier()


# ---------------------------------------------------------------------------
# Pydantic request schemas
# ---------------------------------------------------------------------------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    email: str = Field(..., max_length=200)
    department: str = Field(..., min_length=1, max_length=80)
    role: Literal["Agent", "Admin"] = "Agent"

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        return v


class DrillCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=160)
    sender: str = Field(..., min_length=3, max_length=200)
    subject: str = Field(..., min_length=2, max_length=240)
    body_text: str = Field(..., min_length=5)
    simulated_url: str = DEFAULT_URL
    difficulty: Literal["Easy", "Medium", "Hard"] = "Medium"
    is_suspicious: bool = True
    red_flags: str = ""

    @field_validator("simulated_url")
    @classmethod
    def safe_url_only(cls, v: str) -> str:
        """Hard safety rail: links may only point at the training domain."""
        v = (v or DEFAULT_URL).strip()
        host = (urlparse(v).hostname or "").lower()
        if host != SAFE_DOMAIN and not host.endswith("." + SAFE_DOMAIN):
            raise ValueError(f"simulated_url must point to {SAFE_DOMAIN}")
        return v


class InteractRequest(BaseModel):
    agent_id: int
    drill_id: int
    action: Literal["opened", "clicked_link", "reported", "marked_safe"]


class QuizAnswer(BaseModel):
    question_id: int
    selected_index: int


class QuizSubmit(BaseModel):
    agent_id: int
    answers: List[QuizAnswer] = Field(..., min_length=1, max_length=10)


class EmailScan(BaseModel):
    subject: str = ""
    body: str = ""


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------
def agent_out(a: Agent) -> dict:
    return dict(
        id=a.id, name=a.name, email=a.email, department=a.department, role=a.role,
        defense_score=round(a.defense_score, 1), drills_received=a.drills_received,
        baits_taken=a.baits_taken, threats_reported=a.threats_reported,
    )


def split_flags(text: str) -> List[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def drill_out(d: Drill) -> dict:
    return dict(
        id=d.id, title=d.title, sender=d.sender, subject=d.subject, body_text=d.body_text,
        simulated_url=d.simulated_url, difficulty=d.difficulty, is_suspicious=d.is_suspicious,
        red_flags=split_flags(d.red_flags), created_at=iso(d.created_at),
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db)
    yield


app = FastAPI(title="BAITWATCH — Phishing Defense Simulator", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Frontend (React UMD + Babel Standalone, no build step)
# ---------------------------------------------------------------------------
INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#07090F" />
  <title>BAITWATCH — Phishing Defense Simulator</title>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='14' fill='none' stroke='%2339FF88' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%2339FF88' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%2339FF88'/%3E%3C/svg%3E" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="/style.css" />
</head>
<body>
  <div id="root"><p class="boot">&gt; booting baitwatch_os ...</p></div>
  <noscript>BAITWATCH needs JavaScript enabled.</noscript>
  <script crossorigin src="https://unpkg.com/react@18.3.1/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js"></script>
  <script src="https://unpkg.com/@babel/standalone@7.24.7/babel.min.js"></script>
  <script type="text/babel" data-presets="react" src="/App.jsx"></script>
</body>
</html>"""

NO_CACHE = {"Cache-Control": "no-store"}


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index():
    return HTMLResponse(INDEX_HTML, headers=NO_CACHE)


@app.get("/App.jsx", include_in_schema=False)
def app_jsx():
    return FileResponse(os.path.join(BASE_DIR, "App.jsx"), media_type="text/babel", headers=NO_CACHE)


@app.get("/style.css", include_in_schema=False)
def style_css():
    return FileResponse(os.path.join(BASE_DIR, "style.css"), media_type="text/css", headers=NO_CACHE)


# ---------------------------------------------------------------------------
# API: stats
# ---------------------------------------------------------------------------
@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    avg = db.query(func.avg(Agent.defense_score)).scalar()
    return dict(
        total_agents=db.query(Agent).count(),
        total_drills=db.query(Drill).count(),
        baits_taken=int(db.query(func.coalesce(func.sum(Agent.baits_taken), 0)).scalar()),
        threats_reported=int(db.query(func.coalesce(func.sum(Agent.threats_reported), 0)).scalar()),
        avg_defense_score=round(avg, 1) if avg is not None else 0.0,
    )


# ---------------------------------------------------------------------------
# API: agents
# ---------------------------------------------------------------------------
@app.get("/api/agents")
def list_agents(db: Session = Depends(get_db)):
    agents = db.query(Agent).order_by(Agent.defense_score.desc(), Agent.name).all()
    return [agent_out(a) for a in agents]


@app.post("/api/agents", status_code=201)
def create_agent(payload: AgentCreate, db: Session = Depends(get_db)):
    if db.query(Agent).filter(Agent.email == payload.email).first():
        raise HTTPException(409, "An agent with that email already exists")
    agent = Agent(**payload.model_dump(), defense_score=100.0)
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent_out(agent)


# ---------------------------------------------------------------------------
# API: drills
# ---------------------------------------------------------------------------
@app.get("/api/drills")
def list_drills(db: Session = Depends(get_db)):
    return [drill_out(d) for d in db.query(Drill).order_by(Drill.created_at.desc(), Drill.id.desc()).all()]


@app.post("/api/drills", status_code=201)
def create_drill(payload: DrillCreate, db: Session = Depends(get_db)):
    data = payload.model_dump()
    # Safety rail: every phishing drill is clearly labelled as a simulation.
    if data["is_suspicious"] and not data["subject"].startswith(SIM_PREFIX):
        data["subject"] = f"{SIM_PREFIX} {data['subject']}"
    drill = Drill(**data)
    db.add(drill)
    # Every agent "receives" the new drill.
    db.query(Agent).update({Agent.drills_received: Agent.drills_received + 1})
    db.commit()
    db.refresh(drill)
    return drill_out(drill)


# ---------------------------------------------------------------------------
# API: interactions
# ---------------------------------------------------------------------------
@app.get("/api/interactions")
def list_interactions(
    agent_id: Optional[int] = Query(None, description="Filter to one agent"),
    limit: int = Query(20, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Latest interactions joined with agent names and drill subjects."""
    q = (
        db.query(Interaction, Agent.name, Drill.subject, Drill.is_suspicious)
        .join(Agent, Interaction.agent_id == Agent.id)
        .join(Drill, Interaction.drill_id == Drill.id)
    )
    if agent_id is not None:
        q = q.filter(Interaction.agent_id == agent_id)
    rows = q.order_by(Interaction.timestamp.desc(), Interaction.id.desc()).limit(limit).all()
    return [
        dict(
            id=i.id, agent_id=i.agent_id, agent_name=name, drill_id=i.drill_id,
            drill_subject=subject, is_suspicious=susp, action=i.action, timestamp=iso(i.timestamp),
        )
        for i, name, subject, susp in rows
    ]


@app.post("/api/agent/interact")
def interact(req: InteractRequest, db: Session = Depends(get_db)):
    """Record an agent's action on a drill and apply the scoring rules."""
    agent = db.get(Agent, req.agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    drill = db.get(Drill, req.drill_id)
    if not drill:
        raise HTTPException(404, "Drill not found")

    prior = {
        a for (a,) in db.query(Interaction.action)
        .filter(Interaction.agent_id == agent.id, Interaction.drill_id == drill.id)
        .all()
    }
    flags = split_flags(drill.red_flags)

    def respond(ftype, title, message, delta=0.0, effect=None, logged=True, show_flags=False):
        return dict(
            logged=logged, action=req.action, feedback_type=ftype, title=title, message=message,
            red_flags=flags if show_flags else [], score_delta=delta,
            new_score=round(agent.defense_score, 1), is_suspicious=drill.is_suspicious,
            effect=effect, agent=agent_out(agent),
        )

    # --- "opened" is informational only; log it once per drill.
    if req.action == "opened":
        if "opened" in prior:
            return respond("none", "", "", logged=False)
        db.add(Interaction(agent_id=agent.id, drill_id=drill.id, action="opened"))
        db.commit()
        return respond("none", "", "")

    # --- Anti-farming: only one verdict (report / mark safe) per drill, one click penalty per drill.
    if req.action in ("reported", "marked_safe") and prior & {"reported", "marked_safe"}:
        return respond("info", "Verdict already filed",
                       "You've already classified this message. Your original verdict stands.", logged=False)
    if req.action == "clicked_link" and "clicked_link" in prior:
        return respond("info", "Link already opened",
                       "This link was already logged — no additional penalty.", logged=False,
                       show_flags=drill.is_suspicious)

    delta, ftype, title, message, effect, show_flags = 0.0, "info", "", "", None, False

    if req.action == "clicked_link":
        if drill.is_suspicious:
            delta, ftype, effect, show_flags = -20.0, "warning", "breach", True
            agent.baits_taken += 1
            title = "BAIT TAKEN — you clicked a phishing link"
            message = "In a real attack this could have exposed your credentials. Here's what you missed:"
        else:
            ftype, title = "info", "Link opened"
            message = "This was a legitimate message, so opening its link is fine. No score change."

    elif req.action == "reported":
        if drill.is_suspicious:
            delta, ftype, effect, show_flags = 10.0, "success", "neutralised", True
            agent.threats_reported += 1
            title = "THREAT NEUTRALISED"
            message = "Great catch — reporting stops the campaign for everyone. Red flags you spotted:"
        else:
            delta, ftype = -5.0, "info"
            title = "False alarm"
            message = "This one was legitimate. Reporting is always better than clicking, but check the sender and context first."

    elif req.action == "marked_safe":
        if drill.is_suspicious:
            delta, ftype, show_flags = -15.0, "warning", True
            title = "MISSED THREAT — this was phishing"
            message = "You marked a phishing email as safe. Red flags to watch for:"
        else:
            delta, ftype = 5.0, "success"
            title = "Correct — legitimate email"
            message = "Known internal sender, expected content and no credential requests. Good judgement."

    agent.defense_score = clamp_score(agent.defense_score + delta)
    db.add(Interaction(agent_id=agent.id, drill_id=drill.id, action=req.action))
    db.commit()
    db.refresh(agent)
    return respond(ftype, title, message, delta=delta, effect=effect, show_flags=show_flags)


# ---------------------------------------------------------------------------
# API: training & quiz  (quiz route declared BEFORE /{agent_id})
# ---------------------------------------------------------------------------
@app.get("/api/training/quiz-questions")
def quiz_questions(count: int = Query(4, ge=1, le=len(QUIZ_BANK))):
    """Random questions WITHOUT answers or explanations."""
    picked = random.sample(QUIZ_BANK, count)
    return [dict(id=q["id"], topic=q["topic"], question=q["question"], options=q["options"]) for q in picked]


@app.post("/api/training/quiz")
def submit_quiz(payload: QuizSubmit, db: Session = Depends(get_db)):
    agent = db.get(Agent, payload.agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")

    review, correct, seen = [], 0, set()
    for ans in payload.answers:
        q = QUIZ_BY_ID.get(ans.question_id)
        if not q or q["id"] in seen:
            continue  # ignore unknown or duplicated questions
        seen.add(q["id"])
        ok = ans.selected_index == q["answer"]
        correct += ok
        review.append(dict(
            question_id=q["id"], topic=q["topic"], question=q["question"], options=q["options"],
            selected_index=ans.selected_index, correct_index=q["answer"],
            is_correct=ok, explanation=q["explanation"],
        ))
    total = len(review)
    if total == 0:
        raise HTTPException(400, "No valid answers submitted")

    bonus = round((correct / total) * QUIZ_MAX_BONUS, 1)
    agent.defense_score = clamp_score(agent.defense_score + bonus)
    db.add(QuizSubmission(agent_id=agent.id, score=correct, total=total))
    db.commit()
    db.refresh(agent)
    return dict(score=correct, total=total, bonus=bonus, new_score=agent.defense_score,
                review=review, agent=agent_out(agent))


@app.get("/api/training/{agent_id}")
def training_for(agent_id: int, db: Session = Depends(get_db)):
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    attempts = db.query(QuizSubmission).filter(QuizSubmission.agent_id == agent.id).count()
    return dict(agent=agent_out(agent), modules=modules_for(agent), quiz_attempts=attempts)


# ---------------------------------------------------------------------------
# API: AI classifier
# ---------------------------------------------------------------------------
@app.post("/api/ml/predict-email")
def predict_email(payload: EmailScan):
    text = f"{payload.subject} {payload.body}".strip()
    if not text:
        raise HTTPException(400, "Provide a subject and/or body to scan")
    p = float(classifier.predict_proba([text])[0][1])  # probability of class 1 (phishing)
    is_phishing = p >= 0.5
    return dict(
        is_phishing=is_phishing,
        risk_probability=round(p * 100, 1),
        label="Potential Phishing Risk" if is_phishing else "Likely Benign Communication",
        algorithm=ALGORITHM_NAME,
    )


# ---------------------------------------------------------------------------
# API: admin reset
# ---------------------------------------------------------------------------
@app.post("/api/admin/reset")
def admin_reset():
    """Wipe every table and restore the seed data."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_database(db)
    return {"status": "reset", "message": "Simulation restored to seed state."}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    print("\n  BAITWATCH online  ->  http://127.0.0.1:8000\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)
