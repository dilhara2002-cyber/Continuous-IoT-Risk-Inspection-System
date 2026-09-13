import sys
import uvicorn

if __name__ == "__main__":
    print("=" * 70)
    print(" Secure IoT Device Discovery and Risk Management System ")
    print(" IE3092 - Information Security Project | Group 14")
    print("=" * 70)
    print(" Dashboard URL: http://127.0.0.1:8000")
    print(" API Documentation: http://127.0.0.1:8000/docs")
    print(" Default Admin: admin / AdminPassword123!")
    print(" Default Viewer: viewer / ViewerPassword123!")
    print("=" * 70)
    
    uvicorn.run("backend.app.main:app", host="127.0.0.1", port=8000, reload=True)
