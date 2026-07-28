"""
One-off script to bootstrap the first Admin account.
Public /auth/register deliberately refuses role='admin', so this is the
only way an admin account gets created -- run it once, locally.

Usage: python create_admin.py
"""
from database import SessionLocal, Base, engine
from models import User, UserRole
from security import hash_password

Base.metadata.create_all(bind=engine)
db = SessionLocal()

username = input("Admin username: ").strip()
email = input("Admin email: ").strip()
password = input("Admin password (min 8 chars): ").strip()

if db.query(User).filter(User.username == username).first():
    print("That username already exists.")
elif len(password) < 8:
    print("Password too short.")
else:
    admin = User(username=username, email=email, password_hash=hash_password(password), role=UserRole.ADMIN)
    db.add(admin)
    db.commit()
    print(f"Admin '{username}' created.")

db.close()