"""PyInstaller entry point for poisonhound-service.exe (Windows Service)."""

from poisonhound.win_service import main

if __name__ == "__main__":
    main()
