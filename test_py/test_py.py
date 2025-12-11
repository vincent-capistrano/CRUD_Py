import pandas as pd
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyodbc
import configparser
import sys
import os
from datetime import datetime

# ---------------- SQL CONFIG ----------------
config = configparser.ConfigParser()
if getattr(sys, 'frozen', False):
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(__file__)
config.read(os.path.join(base_path, "config.ini"))

# Read required SQL settings and optional credentials
SQL_SERVER = config["SQL"].get("SERVER", "")
SQL_DATABASE = config["SQL"].get("DATABASE", "")
SQL_DRIVER = config["SQL"].get("DRIVER", "")
# Optional DB credentials: if provided, use SQL authentication; otherwise use trusted connection
SQL_USERNAME = config["SQL"].get("USERNAME", "").strip()
SQL_PASSWORD = config["SQL"].get("PASSWORD", "").strip()
SQL_TRUSTED_CONNECTION = config["SQL"].get("TRUSTED_CONNECTION", "yes").strip().lower() in ("1", "true", "yes", "y")

# ---------------- SQL CONNECTION ----------------
def connect_sql():
    try:
        # Build connection string depending on authentication method
        if SQL_USERNAME and SQL_PASSWORD:
            auth_part = f"UID={SQL_USERNAME};PWD={SQL_PASSWORD};"
        elif SQL_TRUSTED_CONNECTION:
            auth_part = "Trusted_Connection=yes;"
        else:
            # fallback to trusted connection if nothing specified
            auth_part = "Trusted_Connection=yes;"

        conn_str = (
            f"DRIVER={{{SQL_DRIVER}}};"
            f"SERVER={SQL_SERVER};"
            f"DATABASE={SQL_DATABASE};"
            f"{auth_part}"
        )
        conn = pyodbc.connect(conn_str)
        return conn
    except Exception as e:
        messagebox.showerror("SQL Connection Error", str(e))
        return None

# ---------------- GLOBALS ----------------
TABLE_NAME = "Projects"
CURRENT_USER_ROLE = None
CURRENT_USERNAME = None
master_df = pd.DataFrame()
current_df = pd.DataFrame()

# Pagination globals
PAGE_SIZE = 20
current_page = 1
total_pages = 1

# UI styling
button_font = ('Segoe UI', 9, 'bold')
label_font = ('Segoe UI', 10)
title_font = ('Segoe UI', 11, 'bold')

def make_button(parent, text, command=None, bg=None, fg='white', **kwargs):
    opts = {
        'font': button_font,
        'relief': tk.FLAT,
        'bd': 0,
        'highlightthickness': 0,
        'activebackground': '#cfe8ff'
    }
    if bg:
        opts['bg'] = bg
    if fg:
        opts['fg'] = fg
    if command:
        opts['command'] = command
    opts.update(kwargs)
    return tk.Button(parent, text=text, **opts)

# ---------------- LOGIN & REGISTER ----------------
def login():
    login_win = tk.Toplevel(root)
    login_win.title("Login / Register")
    login_win.geometry("420x230")
    login_win.configure(bg="#eef6ff")

    tk.Label(login_win, text="Username", bg="#eef6ff", fg="#08306b", font=label_font).grid(row=0, column=0, padx=8, pady=8, sticky='w')
    tk.Label(login_win, text="Password", bg="#eef6ff", fg="#08306b", font=label_font).grid(row=1, column=0, padx=8, pady=8, sticky='w')

    username_entry = tk.Entry(login_win, bg='white', fg='#0b2e4a', font=label_font)
    username_entry.grid(row=0, column=1, padx=8, pady=8, sticky='ew', columnspan=2)
    password_entry = tk.Entry(login_win, show="*", bg='white', fg='#0b2e4a', font=label_font)
    password_entry.grid(row=1, column=1, padx=8, pady=8, sticky='ew', columnspan=2)

    show_password_var = tk.BooleanVar(value=False)
    def toggle_login_password():
        password_entry.config(show="" if show_password_var.get() else "*")
    tk.Checkbutton(login_win, text="Show password", variable=show_password_var, command=toggle_login_password, bg="#eef6ff").grid(row=2, column=1, padx=8, pady=4, sticky='w')

    def do_login():
        username = username_entry.get()
        password = password_entry.get()
        conn = connect_sql()
        if not conn:
            return
        try:
            df = pd.read_sql(
                "SELECT * FROM [dbo].[Users] WHERE Username=? AND PasswordHash=?",
                conn,
                params=(username, password)
            )
            if df.empty:
                messagebox.showerror("Login Failed", "Invalid credentials")
                return
            global CURRENT_USER_ROLE, CURRENT_USERNAME
            # Normalize role to avoid case/whitespace mismatches (e.g. 'Admin', ' admin ')
            try:
                CURRENT_USER_ROLE = str(df.iloc[0].get('Role', '')).strip().lower()
            except Exception:
                try:
                    CURRENT_USER_ROLE = str(df.iloc[0]['Role']).strip().lower()
                except Exception:
                    CURRENT_USER_ROLE = ''
            # prefer the Username column if present, otherwise use the entered username
            try:
                CURRENT_USERNAME = df.iloc[0].get('Username', username) or username
            except Exception:
                CURRENT_USERNAME = username
            # update welcome label before showing dashboard
            try:
                update_welcome_label()
            except Exception:
                pass
            login_win.destroy()
            # reveal main window after successful login
            root.deiconify()
            apply_role_permissions()
            display_sql_data()
        finally:
            conn.close()

    def open_register_dialog():
        reg = tk.Toplevel(root)
        reg.title("Register")
        reg.geometry("420x260")
        reg.configure(bg="#eef6ff")

        tk.Label(reg, text="Username", bg="#eef6ff", fg="#08306b", font=label_font).grid(row=0, column=0, padx=8, pady=8, sticky='w')
        tk.Label(reg, text="Password", bg="#eef6ff", fg="#08306b", font=label_font).grid(row=1, column=0, padx=8, pady=8, sticky='w')
        tk.Label(reg, text="Confirm Password", bg="#eef6ff", fg="#08306b", font=label_font).grid(row=2, column=0, padx=8, pady=8, sticky='w')

        username_reg = tk.Entry(reg, bg='white', fg='#0b2e4a', font=label_font)
        username_reg.grid(row=0, column=1, padx=8, pady=8, sticky='ew', columnspan=2)
        password_reg = tk.Entry(reg, show="*", bg='white', fg='#0b2e4a', font=label_font)
        password_reg.grid(row=1, column=1, padx=8, pady=8, sticky='ew', columnspan=2)
        password_confirm = tk.Entry(reg, show="*", bg='white', fg='#0b2e4a', font=label_font)
        password_confirm.grid(row=2, column=1, padx=8, pady=8, sticky='ew', columnspan=2)

        # Checkbox to toggle password visibility in register dialog
        show_reg_pass = tk.BooleanVar(value=False)
        def toggle_reg_password():
            show = "" if show_reg_pass.get() else "*"
            password_reg.config(show=show)
            password_confirm.config(show=show)
        tk.Checkbutton(reg, text="Show password", variable=show_reg_pass, command=toggle_reg_password, bg="#eef6ff").grid(row=3, column=1, padx=8, pady=4, sticky='w')

        def do_register_submit():
            username = username_reg.get().strip()
            p1 = password_reg.get()
            p2 = password_confirm.get()
            if not username or not p1 or not p2:
                messagebox.showerror("Error", "All fields are required")
                return
            if p1 != p2:
                messagebox.showerror("Error", "Passwords do not match")
                return
            conn = connect_sql()
            if not conn:
                return
            try:
                df = pd.read_sql("SELECT * FROM [dbo].[Users] WHERE Username=?", conn, params=(username,))
                if not df.empty:
                    messagebox.showerror("Error", "Username already exists")
                    return
                conn.execute(
                    "INSERT INTO [dbo].[Users] (Username, PasswordHash, Role) VALUES (?, ?, ?)",
                    (username, p1, "user")
                )
                conn.commit()
                messagebox.showinfo("Success", f"User '{username}' registered successfully with role 'user'")
                reg.destroy()
            finally:
                conn.close()

        make_button(reg, text="Submit", command=do_register_submit, bg="#0d6efd").grid(row=4, column=0, pady=12, padx=8, sticky='ew')
        make_button(reg, text="Cancel", command=reg.destroy, bg="#6c757d").grid(row=4, column=1, pady=12, padx=8, sticky='ew')

        reg.grab_set()
        root.wait_window(reg)

    # Use flat bold buttons for login/register
    make_button(login_win, text="Login", command=do_login, bg="#0d6efd").grid(row=5, column=0, pady=12, padx=8, sticky='ew')
    make_button(login_win, text="Register", command=open_register_dialog, bg="#6c757d").grid(row=5, column=1, pady=12, padx=8, sticky='ew')

    login_win.grab_set()
    root.wait_window(login_win)

# Helper to check admin role consistently
def is_admin():
    try:
        return str(CURRENT_USER_ROLE or "").strip().lower() == "admin"
    except Exception:
        return False

# ---------------- ROLE PERMISSIONS ----------------
def apply_role_permissions():
    # show or hide Add button based on role
    try:
        if is_admin():
            # ensure button is visible
            try:
                if not add_button.winfo_ismapped():
                    add_button.pack(side=tk.LEFT, padx=5)
            except Exception:
                # if widget not yet created or has no method, ignore
                pass
        else:
            # hide button for non-admin users
            try:
                if add_button.winfo_ismapped():
                    add_button.pack_forget()
            except Exception:
                pass
    except Exception:
        pass


def logout():
    """Log out the current user: clear state, hide dashboard, and show login dialog."""
    global CURRENT_USER_ROLE, master_df, current_df, current_page, total_pages
    CURRENT_USER_ROLE = None
    master_df = pd.DataFrame()
    current_df = pd.DataFrame()
    current_page = 1
    total_pages = 1
    try:
        tree.delete(*tree.get_children())
    except Exception:
        pass
    try:
        # hide Add button instead of disabling it
        if add_button.winfo_ismapped():
            add_button.pack_forget()
    except Exception:
        pass
    try:
        search_entry.delete(0, tk.END)
    except Exception:
        pass
    # hide main window and show login again
    root.withdraw()
    login()

# ---------------- CRUD ----------------
def read_sql_table():
    conn = connect_sql()
    if not conn:
        return pd.DataFrame()
    try:
        df = pd.read_sql(f"SELECT * FROM [dbo].[{TABLE_NAME}]", conn)
        df.columns = [str(c).strip() for c in df.columns]
        return df
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return pd.DataFrame()
    finally:
        conn.close()

def create_record(data: dict):
    conn = connect_sql()
    if not conn:
        return
    try:
        now = datetime.now()
        data["LastModifiedDate"] = now
        for k in list(data.keys()):
            v = data[k]
            if v == "":
                data[k] = None
                continue
            if isinstance(v, str):
                s = v.strip()
                try:
                    f = float(s)
                except Exception:
                    continue
                if f.is_integer():
                    data[k] = int(f)
                else:
                    data[k] = f
        cols = ", ".join(data.keys())
        placeholders = ", ".join("?" for _ in data)
        query = f"INSERT INTO [dbo].[{TABLE_NAME}] ({cols}) VALUES ({placeholders})"
        conn.execute(query, tuple(data.values()))
        conn.commit()
        display_sql_data()
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        conn.close()

def update_record(record_id, data: dict):
    conn = connect_sql()
    if not conn:
        return
    try:
        data["LastModifiedDate"] = datetime.now()
        for k in ["Id", "LastModifiedDate"]:
            if k in data:
                del data[k]
        for k in list(data.keys()):
            v = data[k]
            if v == "":
                data[k] = None
                continue
            if isinstance(v, str):
                s = v.strip()
                try:
                    f = float(s)
                except Exception:
                    continue
                if f.is_integer():
                    data[k] = int(f)
                else:
                    data[k] = f
        set_stmt = ", ".join([f"{k}=?" for k in data.keys()])
        query = f"UPDATE [dbo].[{TABLE_NAME}] SET {set_stmt} WHERE Id=?"
        conn.execute(query, tuple(data.values()) + (record_id,))
        conn.commit()
        display_sql_data()
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        conn.close()

# ---------------- DISPLAY ----------------
def display_sql_data(df=None):
    global current_df, master_df, current_page, total_pages
    if df is None:
        master_df = read_sql_table()
        df = master_df
    cols = [c for c in list(df.columns) if c != "Edit"]
    df = df.reindex(columns=cols, fill_value="")

    current_df = df
    tree["columns"] = cols
    for col in tree["columns"]:
        tree.heading(col, text=col)
        tree.column(col, width=120, anchor="w")
    total_rows = len(df)
    total_pages = max(1, (total_rows + PAGE_SIZE - 1) // PAGE_SIZE)
    current_page = 1
    show_page(current_page)


def show_page(page: int):
    """Display one page of current_df in the treeview."""
    global current_page, total_pages
    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages
    current_page = page
    tree.delete(*tree.get_children())
    if current_df.empty:
        update_pagination_controls()
        return
    start = (current_page - 1) * PAGE_SIZE
    end = start + PAGE_SIZE
    page_df = current_df.iloc[start:end]
    for _, row in page_df.iterrows():
        values = list(row)
        tree.insert("", tk.END, values=values)
    update_pagination_controls()


def prev_page():
    global current_page
    if current_page > 1:
        show_page(current_page - 1)


def next_page():
    global current_page, total_pages
    if current_page < total_pages:
        show_page(current_page + 1)


def update_pagination_controls():
    try:
        page_label.config(text=f"Page {current_page}/{total_pages}")
        if current_page <= 1:
            prev_button.config(state=tk.DISABLED)
        else:
            prev_button.config(state=tk.NORMAL)
        if current_page >= total_pages:
            next_button.config(state=tk.DISABLED)
        else:
            next_button.config(state=tk.NORMAL)
    except Exception:
        pass

def change_page_size(event=None):
    """Update PAGE_SIZE based on the combobox and refresh pagination."""
    global PAGE_SIZE
    try:
        PAGE_SIZE = int(page_size_var.get())
    except Exception:
        return
    df = current_df if not current_df.empty else master_df
    if df.empty:
        update_pagination_controls()
        return
    display_sql_data(df)

# ---------------- SEARCH ----------------
def search_data(event=None):
    global master_df
    if master_df.empty:
        return
    keyword = search_entry.get().strip()
    if not keyword:
        display_sql_data(master_df)
        return
    df = master_df.copy()
    mask = pd.Series(False, index=df.index)
    for col in df.columns:
        mask |= df[col].astype(str).str.contains(keyword, case=False, na=False)
    filtered = df[mask]
    if filtered.empty:
        display_sql_data(master_df)
    else:
        display_sql_data(filtered)

# ---------------- EXPORT ----------------
def export_to_excel():
    if current_df.empty:
        messagebox.showerror("Error", "No data to export")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".xlsx",
                                             filetypes=[("Excel files", "*.xlsx")])
    if not file_path:
        return
    try:
        current_df.to_excel(file_path, index=False)
        messagebox.showinfo("Export Success", f"Data exported to {file_path}")
    except Exception as e:
        messagebox.showerror("Export Error", str(e))

def get_hint_for_column(col_name: str) -> str:
    """Return a short hint string for a given column name.

    Specific hints for known Project table columns are provided; otherwise fall back
    to previously used heuristics or an empty hint.
    """
    name = col_name.lower()
    # Exact-column hints (case-insensitive)
    exact_hints = {
        'item': 'short description',
        'sourceoffund': 'e.g. Government, Donor',
        'sector': 'e.g. Transportation, Health',
        'projecttitle': 'Full project title',
        'payment': 'numeric, e.g. 12345.67',
        'noofcalendardays': 'integer (days)',
        'biddingdate': 'e.g. 2025-12-31',
        'noa': 'e.g. 2025-12-31',
        'ntp': 'e.g. 2025-12-31',
        'targetcompletion': 'e.g. 2025-12-31',
        'coc': 'e.g. 2025-12-31',
        'lastmodifieddate': 'auto (leave blank)',
        'projecttype': 'e.g. Road, Bridge',
        'typeofconstruction': 'e.g. New, Rehab',
        'status': "e.g. Done, Pending",
        'remarks': 'optional notes',
        'id': 'integer'
    }
    key = name.replace(' ', '').replace('_', '')
    if key in exact_hints:
        return exact_hints[key]

    # Fallback heuristics
    if any(x in name for x in ["date", "time", "dob"]):
        return "e.g. 2025-12-31"
    if any(x in name for x in ["email", "e-mail"]):
        return "e.g. user@example.com"
    if any(x in name for x in ["phone", "mobile", "tel"]):
        return "digits only"
    if any(x in name for x in ["amount", "price", "cost", "budget", "payment"]):
        return "numeric"
    if any(x in name for x in ["noof", "count", "qty", "number", "id"]):
        return "integer"
    if any(x in name for x in ["url", "link"]):
        return "e.g. https://..."
    # default short hint
    return ""

# ---------------- FORM UI ----------------
def open_form(title, create=True, record_id=None, current_data=None):
    form = tk.Toplevel(root)
    form.title(title)
    form.geometry("550x600")
    form.configure(bg="#ffffff")
    entries = {}

    # Validators factory functions
    def _make_numeric_validator(allow_float: bool):
        def _validate(p):
            if p == "":
                return True
            try:
                if allow_float:
                    float(p)
                else:
                    # allow leading minus for negative ints
                    if p.lstrip('-').isdigit():
                        pass
                    else:
                        return False
                return True
            except Exception:
                return False
        return _validate

    def _make_text_validator():
        def _validate(p):
            # allow empty; otherwise disallow digits
            if p == "":
                return True
            return not any(ch.isdigit() for ch in p)
        return _validate

    def _date_focusout_validate(entry, col_name):
        val = entry.get().strip()
        if val == "":
            return
        try:
            # Accept ISO date YYYY-MM-DD
            datetime.strptime(val, "%Y-%m-%d")
        except Exception:
            messagebox.showerror("Invalid Date", f"Column '{col_name}' expects a date in YYYY-MM-DD format.")
            entry.focus_set()

    cols = [c for c in tree["columns"] if c not in ["Id", "DateModified"]]

    for i, col in enumerate(cols):
        tk.Label(form, text=col, bg="#ffffff").grid(row=i, column=0, padx=5, pady=5, sticky="w")
        entry = tk.Entry(form, width=40)
        entry.grid(row=i, column=1, padx=5, pady=5, sticky="w")
        hint_text = get_hint_for_column(col)
        hint_label = tk.Label(form, text=hint_text, bg="#ffffff", fg="#6c757d")
        hint_label.grid(row=i, column=2, padx=5, pady=5, sticky="w")

        lname = col.lower()
        try:
            if any(x in lname for x in ["date", "time", "dob", "biddingdate", "noa", "ntp", "targetcompletion", "coc"]):
                def _format_digits_to_date(s: str) -> str:
                    digits = ''.join(ch for ch in str(s) if ch.isdigit())[:8]
                    if not digits:
                        return ''
                    formatted = digits
                    if len(digits) >= 4:
                        formatted = digits[:4]
                        if len(digits) >= 6:
                            formatted += '-' + digits[4:6]
                            if len(digits) > 6:
                                formatted += '-' + digits[6:8]
                        else:
                            formatted += '-' + digits[4:]
                    return formatted

                def _date_validate_key(p):
                    if p == "":
                        return True
                    if len(p) > 10:
                        return False
                    return all(ch.isdigit() or ch == '-' for ch in p)

                var = tk.StringVar()
                entry.config(textvariable=var)
                entry._formatting = False
                # mark this entry as driven by a StringVar so prefill can use var.set

                def _calc_cursor_pos_from_digits(digits_before: int, formatted: str) -> int:
                    if digits_before <= 0:
                        return 0
                    count = 0
                    for i, ch in enumerate(formatted):
                        if ch.isdigit():
                            count += 1
                        if count == digits_before:
                            pos = i + 1
                            if pos < len(formatted) and formatted[pos] == '-':
                                return pos + 1
                            return pos
                    return len(formatted)

                def _on_var_change(*args, en=entry, sv=var):
                    if getattr(en, '_formatting', False):
                        return
                    try:
                        s = sv.get()
                        try:
                            cur = en.index(tk.INSERT)
                        except Exception:
                            cur = len(s)
                        digits_before = sum(1 for ch in s[:cur] if ch.isdigit())
                        formatted = _format_digits_to_date(s)
                        if s != formatted:
                            try:
                                en._formatting = True
                                sv.set(formatted)
                                new_pos = _calc_cursor_pos_from_digits(digits_before, formatted)
                                if new_pos < 0:
                                    new_pos = 0
                                if new_pos > len(formatted):
                                    new_pos = len(formatted)
                                en.after(0, lambda pos=new_pos, w=en: w.icursor(pos))
                            finally:
                                en._formatting = False
                    except Exception:
                        pass

                try:
                    var.trace_add('write', _on_var_change)
                except Exception:
                    var.trace('w', _on_var_change)

                entry.bind('<FocusOut>', lambda e, en=entry, cn=col: (_on_var_change(), _date_focusout_validate(en, cn)))

            elif any(x in lname for x in ["noof", "count", "qty", "number", "id"]):
                vcmd = form.register(_make_numeric_validator(False))
                entry.config(validate='key', validatecommand=(vcmd, '%P'))
            elif any(x in lname for x in ["amount", "price", "cost", "budget", "payment"]):
                vcmd = form.register(_make_numeric_validator(True))
                entry.config(validate='key', validatecommand=(vcmd, '%P'))
            elif 'item' in lname:

                pass
            else:
                vcmd = form.register(_make_text_validator())
                entry.config(validate='key', validatecommand=(vcmd, '%P'))
        except Exception:
            pass

        if current_data:
            val = current_data.get(col, "")
            if pd.isna(val):
                val = ""
            if any(x in lname for x in ["date", "time", "dob", "biddingdate", "noa", "ntp", "targetcompletion", "coc"]):
                try:
                    try:
                        var.set(_format_digits_to_date(val))
                    except Exception:
                        val = _format_digits_to_date(val)
                except Exception:
                    pass
            else:
                # programmatic insert can be blocked by validate='key'; disable briefly
                try:
                    cur_validate = entry.cget('validate')
                except Exception:
                    cur_validate = ''
                try:
                    entry.config(validate='none')
                    entry.delete(0, tk.END)
                    entry.insert(0, str(val))
                finally:
                    try:
                        if cur_validate:
                            entry.config(validate=cur_validate)
                    except Exception:
                        pass
        entries[col] = entry

    try:
        if not create and not is_admin():
            for ent in entries.values():
                try:
                    ent.config(state='readonly')
                except Exception:
                    pass
    except Exception:
        pass

    def submit():
        data = {col: entries[col].get() for col in cols}
        if create:
            create_record(data)
        else:
            update_record(record_id, data)
        form.destroy()

    def confirm_and_delete():
        if not is_admin():
            messagebox.showerror("Permission Denied", "Only admins can delete records.")
            return
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to permanently delete this record?"):
            return
        try:
            conn = connect_sql()
            if not conn:
                return
            try:
                conn.execute(f"DELETE FROM [dbo].[{TABLE_NAME}] WHERE Id=?", (int(record_id),))
                conn.commit()
                messagebox.showinfo("Deleted", "Record deleted successfully")
                display_sql_data()
            finally:
                conn.close()
        except Exception as e:
            messagebox.showerror("Delete Error", str(e))
        finally:
            form.destroy()

    tk.Button(form, text="Back", command=form.destroy, bg="#FFC90E", fg="black").grid(row=len(cols), column=2, padx=5, pady=10)

    if not create:
        try:
            if CURRENT_USER_ROLE == "admin":
                tk.Button(form, text="Submit", command=submit, bg="#28a745", fg="white").grid(row=len(cols), column=0, padx=5, pady=10)
                tk.Button(form, text="Delete", command=confirm_and_delete, bg="#dc3545", fg="white").grid(row=len(cols), column=1, padx=5, pady=10)
        except Exception:
            pass

    form.grab_set()

# ---------------- EVENTS ----------------
def on_treeview_double_click(event):
    item = tree.selection()
    if not item:
        return
    item_id = tree.item(item, "values")[0]
    df = current_df
    try:
        record = df[df["Id"] == int(item_id)]
    except Exception:
        record = df[df["Id"] == item_id]
    if not record.empty:
        current_data = record.iloc[0].to_dict()
        if CURRENT_USER_ROLE == "admin":
            open_form("Edit Record", create=False, record_id=item_id, current_data=current_data)
        else:
            open_form("View Record", create=False, record_id=item_id, current_data=current_data)

# ---------------- TUTORIAL ----------------
def show_tutorial():
    """Show a simple tutorial/help popup."""
    try:
        tut = tk.Toplevel(root)
        tut.title("Tutorial")
        tut.geometry("600x400")
        tut.configure(bg="#ffffff")
        txt = (
            "Welcome to the Dashboard!\n\n"
            "- Use 'Search' to filter projects.\n"
            "- 'Add New Record' opens the form (admin only).\n"
            "- Double-click a row to edit (admin only).\n"
            "- Use 'Export to Excel' to save current view.\n\n"
        )
        label = tk.Label(tut, text=txt, justify="left", bg="#ffffff", font=label_font, wraplength=560)
        label.pack(padx=12, pady=12, fill="both", expand=True)
        tk.Button(tut, text="Close", command=tut.destroy, bg="#6c757d", fg="white").pack(pady=8)
        tut.grab_set()
    except Exception as e:
        messagebox.showerror("Tutorial Error", str(e))

# ---------------- WELCOME LABEL ----------------
def update_welcome_label():
    try:
        if CURRENT_USERNAME:
            welcome_label.config(text=f"Welcome {CURRENT_USERNAME}!")
        else:
            welcome_label.config(text="Welcome!")
    except Exception:
        pass

# ---------------- MAIN UI ----------------
root = tk.Tk()
# start hidden until user logs in
root.withdraw()
root.title("Dashboard")
root.geometry("900x600")

# Header: welcome label (left) and logout button (right)
header_frame = tk.Frame(root, bg="#f7fafc")
header_frame.pack(fill="x", padx=10, pady=(6, 0))

welcome_label = tk.Label(header_frame, text="Welcome!", bg="#f7fafc", font=title_font, anchor='w')
welcome_label.pack(side=tk.LEFT, anchor='w')

logout_button = make_button(header_frame, text="Logout", command=logout, bg="#fd7e14", fg='white')
logout_button.pack(side=tk.RIGHT)

# Search bar and buttons in one horizontal line
root.configure(bg="#f7fafc")
button_frame = tk.Frame(root, bg="#f7fafc")
button_frame.pack(pady=5, fill="x")

# Search entry
search_entry = tk.Entry(button_frame)
search_entry.pack(side=tk.LEFT, padx=5)

# Search button
search_button = make_button(button_frame, text="Search", command=search_data, bg="#17a2b8")
search_button.pack(side=tk.LEFT, padx=5)

# Export button
export_button = make_button(button_frame, text="Export to Excel", command=export_to_excel, bg="#6c757d")
export_button.pack(side=tk.LEFT, padx=5)

# Add button
add_button = make_button(button_frame, text="Add New Record", command=lambda: open_form("Add New Record", create=True), bg="#007bff", fg='white')

# Tutorial button
tutorial_button = make_button(button_frame, text="Help", command=show_tutorial, bg="#6f42c1")
tutorial_button.pack(side=tk.LEFT, padx=5)

# Pagination controls (Prev / Page / Next)
next_button = make_button(button_frame, text="Next", command=next_page, bg="#e2e6ea", fg='#0b2e4a')
next_button.pack(side=tk.RIGHT, padx=5)
prev_button = make_button(button_frame, text="Prev", command=prev_page, bg="#e2e6ea", fg='#0b2e4a')
prev_button.pack(side=tk.RIGHT, padx=5)

# Page size selector (dropdown) - placed before page label
page_size_var = tk.IntVar(value=PAGE_SIZE)
page_size_combo = ttk.Combobox(button_frame, textvariable=page_size_var, values=[10, 20, 50, 100], width=5, state='readonly', font=label_font)
page_size_combo.pack(side=tk.RIGHT, padx=5)
page_size_combo.bind('<<ComboboxSelected>>', change_page_size)

page_label = tk.Label(button_frame, text=f"Page {current_page}/{total_pages}", bg="#f7fafc", font=label_font)
page_label.pack(side=tk.RIGHT, padx=5)

# Treeview for displaying data
cols = []
tree = ttk.Treeview(root, columns=cols, show="headings")
tree.pack(expand=True, fill="both")
tree.bind("<Double-1>", on_treeview_double_click)

try:
    login()
    try:
        display_sql_data()
    except Exception as inner_exc:
        import traceback
        tb = traceback.format_exc()
        messagebox.showerror("Dashboard Error", f"An error occurred while loading data:\n{inner_exc}")
        with open(os.path.join(base_path, "error.log"), "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat()} - Dashboard load error\n{tb}\n")
        raise
except Exception as e:
    import traceback
    tb = traceback.format_exc()
    try:
        messagebox.showerror("Unhandled Error", f"An unexpected error occurred:\n{e}")
    except Exception:
        print("Unhandled Error:", e)
    with open(os.path.join(base_path, "error.log"), "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} - Unhandled exception during startup\n{tb}\n")
    sys.exit(1)

search_entry.bind('<KeyRelease>', search_data)


root.mainloop()
