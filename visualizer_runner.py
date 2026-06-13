import multiprocessing
import uvicorn
from tools.visualizer.app import app

if __name__ == "__main__":
    multiprocessing.freeze_support()
    uvicorn.run(app, host="127.0.0.1", port=8081)
