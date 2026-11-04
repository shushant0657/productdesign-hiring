# Designer Fit Scorecard

Internal screening tool for FirstClub's Product Designer 2/3 hiring.

- `index.html` — the scorecard (no build step), opens behind a PIN screen
- `applicants.enc.json` — the applicant list, encrypted (AES-256-GCM, key derived from the PIN with PBKDF2-SHA256, 600k iterations). Nothing readable is in this repo.
- Ratings, status changes and added applicants are saved in each viewer's browser; select designers to send for review or create a sheet.

To change the PIN or update the list, regenerate `applicants.enc.json` and replace it.
