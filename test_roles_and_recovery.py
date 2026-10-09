import os
import json
import base64
import sys

# Ensure clean imports from local dir
sys.path.insert(0, os.path.dirname(__file__))

from app import (
    app, load_users, save_users, hash_password,
    save_bill_file, read_bill_file, read_bill_metadata,
    ADMIN_RECOVERY_PIN, MASTER_SYSTEM_KEY, BILLS_FOLDER,
    get_admin_recovery_pin, get_recent_security_events,
    clear_failed_attempts, FAILED_LOGIN_ATTEMPTS
)

client = app.test_client()

print("--- 1. Testing Default Accounts & Login ---")
users = load_users()
assert "admin" in users, "Admin missing from users.json"
assert "staff" in users, "Staff missing from users.json"
assert users["admin"]["role"] == "admin"
assert users["staff"]["role"] == "staff"
assert users["admin"]["password"] == "admin123"
assert users["staff"]["password"] == "staff123"

# Test Admin login
resp = client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
assert resp.status_code == 200
assert b"Admin Command Center" in resp.data
print("[OK] Admin login & redirection to Admin Dashboard passed.")

# Test Staff login
client.get("/logout")
resp = client.post("/login", data={"username": "staff", "password": "staff123"}, follow_redirects=True)
assert resp.status_code == 200
assert b"Staff & Cashier Dashboard" in resp.data or b"Start New Bill" in resp.data
print("[OK] Staff login & redirection to Staff Dashboard passed.")

# Test Role Restriction (Staff cannot access /admin)
resp = client.get("/admin", follow_redirects=True)
assert resp.status_code == 200
assert b"Admin privileges required" in resp.data or b"Access denied" in resp.data
print("[OK] Role protection verified: Staff blocked from Admin Dashboard.")

print("\n--- 2. Testing Staff Creation & Role Assignment (Admin Only) ---")
# Attempt to create user as Staff -> Must be denied
resp = client.post("/admin/staff/add", data={
    "name": "Unauthorized Staff",
    "username": "hacker1",
    "password": "hackpassword",
    "role": "admin"
}, follow_redirects=True)
assert b"Admin privileges required" in resp.data or b"Access denied" in resp.data
users = load_users()
assert "hacker1" not in users, "Staff should NOT be able to create users!"
print("[OK] Staff user creation blocked as required.")

# Attempt to change role as Staff -> Must be denied
resp = client.post("/admin/users/update-role", data={
    "username": "staff",
    "role": "admin"
}, follow_redirects=True)
assert b"Admin privileges required" in resp.data or b"Access denied" in resp.data
users = load_users()
assert users["staff"]["role"] == "staff", "Staff should NOT be able to change roles!"
print("[OK] Staff role change blocked as required.")

# Login as Admin to perform user management
client.get("/logout")
client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)

# Admin creates a new staff user
test_cashier = "testcashier99"
resp = client.post("/admin/staff/add", data={
    "name": "Kiran Shrestha",
    "username": test_cashier,
    "password": "kiranpass123",
    "role": "staff"
}, follow_redirects=True)
assert resp.status_code == 200
users = load_users()
assert test_cashier in users
assert users[test_cashier]["role"] == "staff"
assert users[test_cashier]["password"] == "kiranpass123"
print("[OK] Admin successfully created new staff user with password stored.")

# Admin creates a new admin user
test_subadmin = "testadmin99"
resp = client.post("/admin/users/add", data={
    "name": "Sub Admin Person",
    "username": test_subadmin,
    "password": "subadminpass123",
    "role": "admin"
}, follow_redirects=True)
assert resp.status_code == 200
users = load_users()
assert test_subadmin in users
assert users[test_subadmin]["role"] == "admin"
assert users[test_subadmin]["password"] == "subadminpass123"
print("[OK] Admin successfully created new admin user with role assignment.")

# Admin changes role of testcashier99 to admin
resp = client.post("/admin/users/update-role", data={
    "username": test_cashier,
    "role": "admin"
}, follow_redirects=True)
assert resp.status_code == 200
users = load_users()
assert users[test_cashier]["role"] == "admin", "Role promotion failed!"
print("[OK] Admin successfully promoted user role to ADMIN.")

# Admin changes role back to staff
resp = client.post("/admin/users/update-role", data={
    "username": test_cashier,
    "role": "staff"
}, follow_redirects=True)
assert resp.status_code == 200
users = load_users()
assert users[test_cashier]["role"] == "staff", "Role demotion failed!"
print("[OK] Admin successfully assigned role back to STAFF.")

# Safeguard check: primary admin cannot be demoted
resp = client.post("/admin/users/update-role", data={
    "username": "admin",
    "role": "staff"
}, follow_redirects=True)
users = load_users()
assert users["admin"]["role"] == "admin", "Primary admin must not be demoted!"
print("[OK] Primary admin protected from role change.")

# Check Password Visibility on Admin Dashboard HTML
resp = client.get("/admin")
assert resp.status_code == 200
assert b"kiranpass123" in resp.data
assert b"subadminpass123" in resp.data
assert b"admin123" in resp.data
assert b"togglePasswordVisibility" in resp.data
print("[OK] Password visibility on Admin Dashboard confirmed.")

print("\n--- 3. Testing Bill Password Recovery & Visibility (Admin Only) ---")
test_bid = "RECOVERYTEST01"
test_secret = "SecretBillPass2026!"
test_text = "====================================================\n         SHOP MANAGEMENT -- RECEIPT\n====================================================\n  Bill ID  : RECOVERYTEST01\n  Date     : 2026-10-09 10:00:00\n  Total    : Rs. 100.00\n"

save_bill_file(
    test_bid,
    test_text,
    password=test_secret,
    customer_name="Alice Wonderland",
    customer_address="100 Secret Lane",
    created_by="staff",
    total_amount=100.00
)

# Admin checks dashboard and sees bill password
meta = read_bill_metadata(test_bid)
assert meta["bill_password"] == test_secret, f"Bill password not saved: {meta.get('bill_password')}"

resp = client.get("/admin")
assert resp.status_code == 200
assert test_secret.encode() in resp.data
print("[OK] Bill password visible to Admin in Password Recovery Center.")

# Staff tries to view without bill password
client.get("/logout")
client.post("/login", data={"username": "staff", "password": "staff123"}, follow_redirects=True)
text, err = read_bill_file(test_bid, password="", is_admin=False)
assert err == "PASSWORD_REQUIRED"

# Staff views /bills list: password is NOT in page
resp = client.get("/bills")
assert test_secret.encode() not in resp.data
print("[OK] Bill password is NOT visible to Staff in bills list.")

# Admin Master Recovery: Admin unlocks WITHOUT knowing password
text, err = read_bill_file(test_bid, password="", is_admin=True)
assert err is None
assert "SHOP MANAGEMENT" in text
print("[OK] Admin Master Recovery successfully unlocked protected bill.")

# Admin Resets Bill Password via endpoint
client.get("/logout")
client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
resp = client.post(f"/bills/{test_bid}/reset-password", data={"action": "remove"}, follow_redirects=True)
assert resp.status_code == 200
meta_after = read_bill_metadata(test_bid)
assert meta_after["protected"] is False, "Password protection should be removed"
print("[OK] Admin reset/remove password operation succeeded.")

print("\n--- 4. Testing Admin Account Password Reset (Forgotten Admin Password) ---")
client.get("/logout")
resp = client.post("/forgot-password", data={
    "username": "admin",
    "recovery_pin": get_admin_recovery_pin(),
    "new_password": "newadminpass2026"
}, follow_redirects=True)
assert resp.status_code == 200

# Verify login with new password
resp = client.post("/login", data={"username": "admin", "password": "newadminpass2026"}, follow_redirects=True)
assert resp.status_code == 200
assert b"Admin Command Center" in resp.data
print("[OK] Admin account password reset using Master Security PIN passed.")

# Reset back to default admin123
client.post("/forgot-password", data={
    "username": "admin",
    "recovery_pin": get_admin_recovery_pin(),
    "new_password": "admin123"
})

print("\n--- 5. Testing Comprehensive Security Controls ---")
# A. HTTP Security Headers
resp = client.get("/login")
assert resp.headers.get("X-Content-Type-Options") == "nosniff", "Missing X-Content-Type-Options header"
assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN", "Missing X-Frame-Options header"
assert resp.headers.get("X-XSS-Protection") == "1; mode=block", "Missing X-XSS-Protection header"
print("[OK] HTTP security headers (nosniff, SAMEORIGIN, XSS-Protection) active.")

# B. Path Traversal Defense
res, err = read_bill_file("../../../etc/passwd")
assert res is None, "Path traversal should not read files outside bills"
res, err = read_bill_file("..\\..\\windows\\win.ini")
assert res is None, "Windows directory traversal blocked"
print("[OK] Path traversal defenses verified.")

# C. Password Length Policy
client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
resp = client.post("/admin/staff/add", data={
    "name": "Short Pass User",
    "username": "shortuser",
    "password": "123",
    "role": "staff"
}, follow_redirects=True)
assert b"at least 6 characters" in resp.data or b"danger" in resp.data
users = load_users()
assert "shortuser" not in users, "Weak password account must be rejected"
print("[OK] Password policy enforcement verified (minimum 6 characters).")

# D. Brute-Force Lockout & Account Unlock
client.get("/logout")
dummy_user = "brutetarget"
# Clear any prior state for test isolation
clear_failed_attempts(dummy_user, FAILED_LOGIN_ATTEMPTS)

# 5 failed login attempts
for i in range(5):
    resp = client.post("/login", data={"username": dummy_user, "password": "wrongpassword"}, follow_redirects=True)

# 6th attempt should be blocked by active lockout
resp = client.post("/login", data={"username": dummy_user, "password": "wrongpassword"}, follow_redirects=True)
assert b"locked" in resp.data.lower(), "Expected account lockout message"
print("[OK] Brute-force lockout triggered after 5 failed login attempts.")

# Admin clears the lockout via security endpoint
client.post("/login", data={"username": "admin", "password": "admin123"}, follow_redirects=True)
resp = client.post("/admin/security/unlock-account", data={"target": dummy_user}, follow_redirects=True)
assert resp.status_code == 200
assert b"cleared successfully" in resp.data or b"success" in resp.data
print("[OK] Admin successfully unlocked account via Security Center.")

# E. Master Security PIN Customization
resp = client.post("/admin/security/update-pin", data={"new_pin": "887766"}, follow_redirects=True)
assert resp.status_code == 200
assert get_admin_recovery_pin() == "887766"
print("[OK] Master Security Recovery PIN successfully updated by Admin.")

# Reset PIN back to default 778899
client.post("/admin/security/update-pin", data={"new_pin": "778899"}, follow_redirects=True)
assert get_admin_recovery_pin() == "778899"

# F. Security Audit Trail
events = get_recent_security_events(10)
assert len(events) > 0, "Security events should be logged"
assert any(ev["event"] in ("LOGIN_SUCCESS", "LOGIN_FAILED", "USER_CREATED", "PIN_UPDATED") for ev in events)
print("[OK] Real-time Security Audit Log active with recorded events.")

# Clean up test accounts and bill
users = load_users()
if test_cashier in users:
    del users[test_cashier]
if test_subadmin in users:
    del users[test_subadmin]
save_users(users)

test_file = os.path.join(BILLS_FOLDER, f"bill_{test_bid}.txt")
if os.path.exists(test_file):
    os.remove(test_file)

print("\n==========================================")
print("ALL TESTS (INCLUDING FULL SECURITY SUITE) PASSED WITH 100% SUCCESS!")
print("==========================================")
