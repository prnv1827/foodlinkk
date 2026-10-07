# FoodLink

Flask + SQLite app connecting food donors with evidence-verified NGOs. No new libraries beyond Flask (sqlite3, smtplib etc. are stdlib).

## Run
```bash
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```
First run creates `instance/foodlink.db` and (dev mode only) an admin: `admin@foodlink.local` / `Admin@12345`.
For real use set `ADMIN_EMAIL` and `ADMIN_PASSWORD` before the first start. Production: `gunicorn app:app`.

## Environment variables (all optional)
| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Session signing key (otherwise auto-generated in `instance/secret_key`) |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Creates the first admin if none exists |
| `DATABASE_PATH` | SQLite file location |
| `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM` | SMTP for reset/verification emails. Without them links are printed to the console (and shown on screen in dev mode) |
| `REQUIRE_EMAIL_VERIFICATION=1` | Donors/NGOs must verify email before posting/requesting |
| `DEFAULT_TZ_OFFSET` | Fallback browser offset in minutes if JS is off (default -330 = IST) |
| `SESSION_COOKIE_SECURE=1` | Set when served over HTTPS |

## Test
```bash
python -m unittest -v test_app     # uses a temporary database
```

## NGO verification model
NGO/Receiver accounts must submit both an NGO registration number, an NGO Darpan/government registration ID, and an official registration proof document. The document is stored outside the public `static/` directory. An admin can only verify when the required evidence exists and is expected to cross-check the registration ID against the relevant official government record before clicking **Verify evidence**. Email verification remains separate and does not by itself prove NGO legitimacy.
