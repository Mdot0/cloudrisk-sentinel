from fastapi import FastAPI

app = FastAPI() # Creates a FastAPI application instance

@app.get("/health") # Defines a GET endpoint at the path "/heath"
def health():
    """Health check endpoint."""
    return {"status": "ok"}