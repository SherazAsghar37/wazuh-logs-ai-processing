from fastapi import FastAPI
from app.routes import wazuh
from app.config import TRUSTED_WAZUH_IP, HOST, PORT, RELOAD
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI()
app.include_router(wazuh)

app.add_middleware(
    CORSMiddleware,
    allow_origins=TRUSTED_WAZUH_IP,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"Hello": "World"}

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT, reload=RELOAD)