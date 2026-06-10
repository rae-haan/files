PowerShell one-liner (typed interactively, not a script)
powershellCopy-Item "C:\path\to\database.csv" "C:\backups\database_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
Run that in an interactive PowerShell session whenever you want a snapshot. No script file, just a typed command.

Automated without scripting: Task Scheduler (GUI)

Open Task Scheduler → Create Basic Task
Trigger: on a schedule (e.g. every 30 min)
Action: Start a program → robocopy
Arguments: "C:\path\to" "C:\backups" database.csv /DCOPY:T

No script file created. The scheduler runs a built-in binary directly.

Tamper detection: certutil (built-in, no install needed)
cmdcertutil -hashfile C:\path\to\database.csv SHA256 > C:\backups\database.csv.sha256
Verify later:
cmdcertutil -hashfile C:\path\to\database.csv SHA256
Compare manually against the saved hash. Store the .sha256 file somewhere separate from the CSV.
