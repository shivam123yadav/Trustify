# Trustify

Trustify is a Flask web application for classifying potentially fraudulent content. It uses MongoDB for data storage and the Google Gemini API for AI-powered classification.

## Requirements

- Python 3.11 or a compatible Python version supported by the project's dependencies
- MongoDB Atlas account or a compatible MongoDB instance
- Google Gemini API key
- Git

## 1. Clone or open the project

If you already have the project, open its directory in VS Code or Antigravity.

## 2. Create and activate a virtual environment

On Windows PowerShell:

```powershell
py -m venv env
.\env\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can invoke the environment's Python directly:

```powershell
.\env\Scripts\python.exe -m pip install --upgrade pip
```

## 3. Install dependencies

With the virtual environment activated:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Configure environment variables

Create a file named `.env` in the project root. **`.env` is a file, not a folder.**

Use `.env.example` as a reference and configure these variables:

| Variable | Purpose |
|---|---|
| `MONGODB_URI` | MongoDB connection URI for the Trustify database |
| `GOOGLE_API_KEY` | Google Gemini API key |
| `FLASK_SECRET_KEY` | Strong, private secret used to sign Flask sessions |
| `GEMINI_MODEL` | Gemini model identifier supported by your API account |

Example placeholders:

```dotenv
MONGODB_URI=mongodb+srv://<db_username>:<db_password>@<cluster-host>/trustify
GOOGLE_API_KEY=replace_with_your_api_key
FLASK_SECRET_KEY=replace_with_a_long_random_secret
GEMINI_MODEL=gemini-3.5-flash-lite
```

Replace every placeholder with the appropriate value. Do not commit `.env` or publish credentials.

Ensure your MongoDB user has the necessary database permissions and that the deployment environment can reach your MongoDB Atlas cluster.

## 5. Run locally

Activate the virtual environment and start the application using the project's supported entry point:

```powershell
python app.py
```

Use the local address printed by the application in your browser. For production, use Gunicorn rather than Flask's development server.

## 6. Production deployment on Render

The repository includes a `Procfile` and `render.yaml` for deployment configuration.

Configure these environment variables in Render:

- `FLASK_ENV=production`
- `FLASK_SECRET_KEY` — a strong secret value
- `MONGODB_URI` — your production MongoDB URI
- `GOOGLE_API_KEY` — your Gemini API key
- `GEMINI_MODEL=gemini-3.5-flash-lite`
- `SESSION_COOKIE_SECURE=True`

Never place actual secrets in `render.yaml`, source code, or Git.

Before deployment, verify MongoDB Atlas network access, dependency installation, environment variable names, and application startup logs.

## 7. Security notes

- Keep `.env` private and excluded from Git.
- Never commit API keys, passwords, database URIs containing credentials, or session-signing secrets.
- Keep production debug mode disabled.
- Use HTTPS in production.
- Review uploaded files and persistent storage requirements before relying on local filesystem uploads in a hosted environment.

## Troubleshooting

- **MongoDB connection failure:** Check the URI, database user permissions, and Atlas network access configuration.
- **Missing Gemini API key:** Confirm `GOOGLE_API_KEY` is set in the environment.
- **Missing Python package:** Activate the correct virtual environment and install `requirements.txt`.
- **Render startup failure:** Review build and application logs, verify the Gunicorn entry point, and check required environment variables.
