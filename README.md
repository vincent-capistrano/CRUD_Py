# TaskDB App

A desktop CRUD application built with Python (Tkinter + pandas + pyodbc) that connects to a **SQL Server** database and manages project records with role-based access control.

---

## Features

- **Login / Register** — Users log in with a username and password stored in SQL Server. New accounts can be registered directly from the login window.
- **Role-Based Access** — `admin` users can add, edit, and delete records. `user` accounts have read-only access.
- **Projects Table** — Full CRUD on project records (title, sector, fund source, dates, payment, status, etc.)
- **Search** — Live keyword search across all columns.
- **Pagination** — Configurable page size (10 / 20 / 50 / 100 rows).
- **Export to Excel** — Export the current view to `.xlsx` via file dialog.
- **Input Validation** — Date auto-formatting (YYYY-MM-DD), numeric guards, and text-only fields.

---

## Requirements

### Runtime
- Windows (10 / 11)
- [ODBC Driver 17 for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)
- A running SQL Server instance (default config targets `MSI`)

### Development
- Python 3.12+
- Packages: `pandas`, `pyodbc`, `openpyxl`, `pyinstaller`

Install dependencies:
```bash
pip install pandas pyodbc openpyxl pyinstaller
```

---

## Database Setup

1. Open **SQL Server Management Studio (SSMS)** or run `sqlcmd`.
2. Execute the setup script against your SQL Server instance:

```bash
sqlcmd -S MSI -E -i setup_database.sql
```

This script will:
- Create the `TaskDB` database (if it doesn't exist)
- Create the `Users` table with a default **admin** account
- Create the `Projects` table with all required columns
- Insert two sample project records

> **Security:** Change the default admin password (`admin123`) immediately after running the script.

### Default Admin Credentials
| Username | Password  |
|----------|-----------|
| `admin`  | `admin123` |

---

## Configuration

Edit `test_py/config.ini` to match your SQL Server setup:

```ini
[SQL]
SERVER = MSI
DATABASE = TaskDB
DRIVER = ODBC Driver 17 for SQL Server
TRUSTED_CONNECTION = no
USERNAME =
PASSWORD =
```

- Set `TRUSTED_CONNECTION = yes` to use Windows Authentication (leave `USERNAME`/`PASSWORD` blank).
- Set `TRUSTED_CONNECTION = no` and provide `USERNAME` / `PASSWORD` for SQL Authentication.

---

## Database Schema

### `[dbo].[Users]`
| Column         | Type          | Notes                    |
|----------------|---------------|--------------------------|
| `Id`           | INT IDENTITY  | Primary key              |
| `Username`     | NVARCHAR(100) | Unique                   |
| `PasswordHash` | NVARCHAR(255) |                          |
| `Role`         | NVARCHAR(50)  | `admin` or `user`        |

### `[dbo].[Projects]`
| Column              | Type          | Notes                        |
|---------------------|---------------|------------------------------|
| `Id`                | INT IDENTITY  | Primary key                  |
| `Item`              | NVARCHAR(255) | Short description            |
| `SourceOfFund`      | NVARCHAR(100) | e.g. Government, Donor       |
| `Sector`            | NVARCHAR(100) | e.g. Transportation, Health  |
| `ProjectTitle`      | NVARCHAR(500) | Full project title           |
| `Payment`           | DECIMAL(18,2) | Contract amount              |
| `NoOfCalendarDays`  | INT           | Duration in days             |
| `BiddingDate`       | DATE          | YYYY-MM-DD                   |
| `NOA`               | DATE          | Notice of Award              |
| `NTP`               | DATE          | Notice to Proceed            |
| `TargetCompletion`  | DATE          | Expected end date            |
| `COC`               | DATE          | Certificate of Completion    |
| `ProjectType`       | NVARCHAR(100) | e.g. Road, Bridge, Building  |
| `TypeOfConstruction`| NVARCHAR(100) | e.g. New, Rehab              |
| `Status`            | NVARCHAR(100) | e.g. Ongoing, Done, Pending  |
| `Remarks`           | NVARCHAR(MAX) | Optional notes               |
| `LastModifiedDate`  | DATETIME      | Auto-set on save             |

---

## Building the Executable

```bash
pyinstaller --noconfirm TaskDB_App.spec
```

The output is placed in `dist/TaskDB_App.exe` — a single-file Windows executable that bundles all dependencies. The `config.ini` file is embedded and read at runtime.

---

## Running the App

**From source:**
```bash
python test_py/test_py.py
```

**From the built executable:**
```
dist\TaskDB_App.exe
```

---

## Project Structure

```
CRUD_Py/
├── test_py/
│   ├── test_py.py        # Main application source
│   └── config.ini        # SQL Server connection settings
├── setup_database.sql    # Database + table creation script
├── TaskDB_App.spec       # PyInstaller build spec
└── README.md
```

---

## Author

[@vincent-capistrano](https://github.com/vincent-capistrano)
