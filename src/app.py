"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")
logger = logging.getLogger(__name__)

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}

TEACHERS_FILE = current_dir / "teachers.json"
SESSION_COOKIE = "teacher_session"
SESSION_TTL_SECONDS = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 600_000

configured_session_secret = os.environ.get("SESSION_SECRET")
if configured_session_secret:
    if len(configured_session_secret) < 32:
        raise RuntimeError("SESSION_SECRET must be at least 32 characters long")
    session_secret = configured_session_secret.encode("utf-8")
else:
    logger.warning(
        "SESSION_SECRET is not set; teacher sessions will be invalidated on restart"
    )
    session_secret = secrets.token_bytes(32)


class LoginRequest(BaseModel):
    username: str
    password: str


def load_teachers():
    """Load teacher password hashes from the local, untracked credentials file."""
    if not TEACHERS_FILE.exists():
        return []

    try:
        data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unable to read teacher credentials: {error}") from error

    if not isinstance(data, dict) or not isinstance(data.get("teachers"), list):
        raise RuntimeError("Teacher credentials must contain a 'teachers' list")

    for teacher in data["teachers"]:
        if not isinstance(teacher, dict) or not all(
            isinstance(teacher.get(field), str)
            for field in ("username", "salt", "password_hash")
        ):
            raise RuntimeError("Each teacher needs a username, salt, and password_hash")
        try:
            bytes.fromhex(teacher["salt"])
            bytes.fromhex(teacher["password_hash"])
        except ValueError as error:
            raise RuntimeError("Teacher credential hashes must be hexadecimal") from error

    return data["teachers"]


def create_session_token(username: str) -> str:
    payload = json.dumps(
        {"username": username, "expires": int(time.time()) + SESSION_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    signature = hmac.new(
        session_secret, encoded_payload.encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{encoded_payload}.{signature}"


def get_session_username(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None

    try:
        encoded_payload, supplied_signature = token.rsplit(".", 1)
        expected_signature = hmac.new(
            session_secret, encoded_payload.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return None

        padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(
            base64.urlsafe_b64decode(encoded_payload + padding)
        )
        username = payload.get("username")
        if not isinstance(username, str) or payload.get("expires", 0) < time.time():
            return None
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    if any(teacher["username"] == username for teacher in load_teachers()):
        return username
    return None


def require_teacher(request: Request):
    username = get_session_username(request)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/auth/session")
def get_auth_session(request: Request):
    username = get_session_username(request)
    return {"authenticated": username is not None, "username": username}


@app.post("/auth/login")
def login(credentials: LoginRequest, response: Response):
    teachers = load_teachers()
    if not teachers:
        raise HTTPException(
            status_code=503,
            detail="Teacher credentials are not configured. Run create_teacher.py.",
        )

    teacher = next(
        (item for item in teachers if item["username"] == credentials.username),
        None,
    )
    salt = bytes.fromhex(teacher["salt"]) if teacher else bytes(16)
    expected_hash = (
        bytes.fromhex(teacher["password_hash"]) if teacher else bytes(32)
    )
    supplied_hash = hashlib.pbkdf2_hmac(
        "sha256",
        credentials.password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    if teacher is None or not hmac.compare_digest(supplied_hash, expected_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session_token(teacher["username"]),
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=(os.environ.get("COOKIE_SECURE", "false").lower() == "true"),
        samesite="strict",
        path="/",
    )
    return {"message": "Teacher login successful"}


@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(
        key=SESSION_COOKIE,
        httponly=True,
        secure=(os.environ.get("COOKIE_SECURE", "false").lower() == "true"),
        samesite="strict",
        path="/",
    )
    return {"message": "Logged out"}


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, email: str, _teacher: str = Depends(require_teacher)
):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, _teacher: str = Depends(require_teacher)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
