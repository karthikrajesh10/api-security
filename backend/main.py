

# # from fastapi import FastAPI
# # from fastapi.middleware.cors import CORSMiddleware
# # from app.core.config import settings
# # from app.ml.factory import model_provider
# # from app.api import traffic, schema

# # app = FastAPI(
# #     title="API Security Platform",
# #     description="ML-based API monitoring and active security testing",
# #     version="0.1.0"
# # )

# # app.add_middleware(
# #     CORSMiddleware,
# #     allow_origins=["http://localhost:5173"],
# #     allow_credentials=True,
# #     allow_methods=["*"],
# #     allow_headers=["*"],
# # )

# # app.include_router(traffic.router)
# # app.include_router(schema.router)

# # @app.on_event("startup")
# # async def startup():
# #     print(f"Starting API Security Platform [{settings.APP_ENV}]")
# #     print(f"Model provider: {settings.MODEL_PROVIDER}")

# # @app.get("/health")
# # async def health():
# #     ml_ok = await model_provider.is_available()
# #     return {
# #         "status": "ok",
# #         "version": "0.1.0",
# #         "env": settings.APP_ENV,
# #         "model_provider": settings.MODEL_PROVIDER,
# #         "ml_available": ml_ok
# #     }


# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# from app.core.config import settings
# from app.ml.factory import model_provider
# from app.api import traffic, schema, anomaly

# app = FastAPI(
#     title="API Security Platform",
#     description="ML-based API monitoring and active security testing",
#     version="0.1.0"
# )

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:5173"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# app.include_router(traffic.router)
# app.include_router(schema.router)
# app.include_router(anomaly.router)

# @app.on_event("startup")
# async def startup():
#     print(f"Starting API Security Platform [{settings.APP_ENV}]")
#     print(f"Model provider: {settings.MODEL_PROVIDER}")

# @app.get("/health")
# async def health():
#     ml_ok = await model_provider.is_available()
#     return {
#         "status": "ok",
#         "version": "0.1.0",
#         "env": settings.APP_ENV,
#         "model_provider": settings.MODEL_PROVIDER,
#         "ml_available": ml_ok
#     }

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.ml.factory import model_provider
from app.api import traffic, schema, anomaly, rules

app = FastAPI(
    title="API Security Platform",
    description="ML-based API monitoring and active security testing",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(traffic.router)
app.include_router(schema.router)
app.include_router(anomaly.router)
app.include_router(rules.router)

@app.on_event("startup")
async def startup():
    print(f"Starting API Security Platform [{settings.APP_ENV}]")
    print(f"Model provider: {settings.MODEL_PROVIDER}")

@app.get("/health")
async def health():
    ml_ok = await model_provider.is_available()
    return {
        "status": "ok",
        "version": "0.1.0",
        "env": settings.APP_ENV,
        "model_provider": settings.MODEL_PROVIDER,
        "ml_available": ml_ok
    }