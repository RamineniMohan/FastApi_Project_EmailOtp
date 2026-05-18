from fastapi import FastAPI
from core.database import Base, engine
from api.v1.routers.auth import router as auth_router
from middleware.auth_middleware import AuthMiddleware

app = FastAPI(title="Auth API")

app.add_middleware(AuthMiddleware)
app.include_router(auth_router)

@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)