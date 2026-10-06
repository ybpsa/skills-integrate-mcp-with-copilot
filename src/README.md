# Mergington High School Activities API

A super simple FastAPI application that allows students to view extracurricular activities and teachers to manage registrations.

## Features

- View all available extracurricular activities
- Teachers can sign students up for activities and remove registrations
- Teacher credentials are stored locally as salted password hashes

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Create a teacher account (you will be prompted for the password):

   ```
   python src/create_teacher.py
   ```

3. Set a persistent session-signing secret of at least 32 characters:

   ```
   export SESSION_SECRET="$(openssl rand -hex 32)"
   ```

   Set `COOKIE_SECURE=true` when serving the site over HTTPS.

4. Start the application from the `src` directory:

   ```
   cd src
   uvicorn app:app --reload
   ```

5. Open http://localhost:8000. Students can view registrations; only logged-in teachers can add or remove them. API documentation is available at `/docs`.

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities and their current participants                   |
| GET    | `/auth/session`                                                   | Get the current teacher login status                                 |
| POST   | `/auth/login`                                                     | Log in with a teacher username and password                          |
| POST   | `/auth/logout`                                                    | Log out the current teacher                                          |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | (Teacher only) Sign up a student                                     |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | (Teacher only) Remove a student's registration                    |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

Activities and registrations remain in memory, so they reset when the server restarts. Teacher credentials are kept in `src/teachers.json`, which is created by the setup command, excluded from Git, and stores PBKDF2 password hashes rather than plaintext passwords. Back up this file securely and do not commit it. `SESSION_SECRET` should be set in production; without it, a random secret is generated at startup and active sessions expire when the server restarts. Serve the application over HTTPS and set `COOKIE_SECURE=true` outside local development.
