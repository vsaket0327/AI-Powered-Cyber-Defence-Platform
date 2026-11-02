import getpass
import sys

from sqlalchemy import or_

from app.database import SessionLocal
from app.models import User
from app.security import hash_password


def create_admin():
    print("=== Cyber Defence Platform: Admin Setup ===")

    username = input("Admin username: ").strip().lower()
    email = input("Admin email: ").strip().lower()

    if len(username) < 3:
        print("Username must contain at least 3 characters.")
        return

    if "@" not in email:
        print("Enter a valid email address.")
        return

    password = getpass.getpass("Admin password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if len(password) < 12:
        print("Admin password must contain at least 12 characters.")
        return

    if password != confirm_password:
        print("Passwords do not match.")
        return

    db = SessionLocal()

    try:
        existing_user = db.query(User).filter(
            or_(
                User.username == username,
                User.email == email,
            )
        ).first()

        if existing_user:
            print("Username or email already exists.")
            return

        admin = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True,
        )

        db.add(admin)
        db.commit()

        print("Administrator account created successfully.")

    except Exception:
        db.rollback()
        print("Admin account creation failed.")
        raise

    finally:
        db.close()


if __name__ == "__main__":
    create_admin()