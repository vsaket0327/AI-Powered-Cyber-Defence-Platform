
from getpass import getpass

from app.database import SessionLocal
from app.models import User
from app.security import hash_password


def create_viewer():
    db = SessionLocal()

    try:
        username = input("Viewer username: ").strip().lower()
        email = input("Viewer email: ").strip().lower()

        if not username or not email or "@" not in email:
            print("Invalid username or email.")
            return

        existing = db.query(User).filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing:
            print("Username or email already exists.")
            return

        password = getpass("Viewer password (minimum 12 characters): ")

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return

        confirm = getpass("Confirm password: ")

        if password != confirm:
            print("Passwords do not match.")
            return

        viewer = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role="viewer",
            is_active=True,
        )

        db.add(viewer)
        db.commit()

        print(f"Viewer account '{username}' created successfully.")

    except Exception as error:
        db.rollback()
        print("Account creation failed:", error)

    finally:
        db.close()


if __name__ == "__main__":
    create_viewer()
