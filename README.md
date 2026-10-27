# Safe AI Mailroom — deployment starter

This package is a cleaned deployment starter based on the Python Flask implementation you supplied.
It is **not yet certified to pass the assignment**: the decision quality depends on the configured model, and the hosted database setting below is ephemeral on Render Free.

## Files
- `mailroom_agent.py` — Flask API implementation (`propose` and `commit`)
- `mailroom_selftest.py` — protocol/signature/replay self-test
- `requirements.txt` — Python dependencies
- `Procfile` / `render.yaml` — Render deployment configuration
- `.env.example` — environment-variable template

## Run locally on macOS

1. Open Terminal and enter this folder.
2. Create a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Configure a model API key and a model name supported by your provider. Do not commit your key to GitHub.

   ```bash
   export LLM_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai"
   export LLM_API_KEY="YOUR_REAL_API_KEY"
   export LLM_MODEL="YOUR_PROVIDER_SUPPORTED_MODEL"
   export DB_PATH="mailroom.db"
   export MAIL_PATH="/v1/mailroom/actions"
   ```

4. Start the service:

   ```bash
   python mailroom_agent.py
   ```

5. In another Terminal window, run the self-test:

   ```bash
   source .venv/bin/activate
   python mailroom_selftest.py http://127.0.0.1:8000/v1/mailroom/actions
   ```

The self-test submits local synthetic dossiers. It does not call the assignment grader, but it does call the configured AI provider through the agent. It may use model API credits.

## Deploy to Render

1. Create a private GitHub repository and upload the files in this folder.
2. In Render, create a **Web Service** from that repository.
3. Build command: `pip install -r requirements.txt`
4. Start command:

   ```bash
   gunicorn --workers 1 --threads 16 --timeout 120 --bind 0.0.0.0:$PORT mailroom_agent:app
   ```

5. Add these environment variables in Render:
   - `LLM_BASE_URL` = `https://generativelanguage.googleapis.com/v1beta/openai`
   - `LLM_API_KEY` = your real provider API key
   - `LLM_MODEL` = a model name currently supported by that provider
   - `DB_PATH` = `/tmp/mailroom.db` for a basic free-tier smoke test
   - `MAIL_PATH` = `/v1/mailroom/actions`

6. The endpoint URL to test will be:

   `https://YOUR-SERVICE.onrender.com/v1/mailroom/actions`

## Important limitations before submission

- **Render Free has an ephemeral filesystem.** A SQLite database stored at `/tmp/mailroom.db` can be lost on restart/redeploy. That is not a safe assumption for a task requiring persisted evaluation state and exact replay. For a final submission, use a persistent storage option or adapt the code to a managed persistent database, then test restart behavior.
- This package has not been run through your assignment grader. Do not spend any of the 10 daily Check/Save uses until local protocol tests, decision quality, persistence, and deployment are verified.
- A passing protocol self-test does not prove that the AI chose the correct action or minimal evidence for hidden cases.
- Never upload `.env`, API keys, receipts, private canary values, or local database files to GitHub.
- Keep the submitted URL free of credentials, query parameters, and fragments.
