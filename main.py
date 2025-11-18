import os
from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict
from datetime import date, datetime, timezone
import hashlib
import hmac
import secrets
import requests
from urllib.parse import urlparse

from database import db, create_document, get_documents

app = FastAPI(title="Modern Cookbook API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Helpers ----------------------

def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
    return f"{salt}:{pwd_hash.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, hexhash = stored.split(":", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 100_000)
        return hmac.compare_digest(test.hex(), hexhash)
    except Exception:
        return False


def collection(name: str):
    return db[name]


# ---------------------- Auth ----------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    user_id: str
    email: EmailStr
    name: Optional[str] = None
    token: str


@app.post("/auth/register", response_model=AuthResponse)
def register(body: RegisterRequest):
    col = collection("user")
    if col.find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "email": body.email,
        "password_hash": hash_password(body.password),
        "name": body.name,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = col.insert_one(user_doc)
    token = secrets.token_hex(24)
    return AuthResponse(user_id=str(res.inserted_id), email=body.email, name=body.name, token=token)


@app.post("/auth/login", response_model=AuthResponse)
def login(body: LoginRequest):
    col = collection("user")
    user = col.find_one({"email": body.email})
    if not user or not verify_password(body.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(24)
    return AuthResponse(user_id=str(user["_id"]), email=user["email"], name=user.get("name"), token=token)


# ---------------------- Profiles ----------------------

class ProfileIn(BaseModel):
    user_id: str
    name: str
    caloric_intake: Optional[int] = None
    allergies: List[str] = []
    macro_goals: Optional[Dict[str, float]] = None
    likes: List[str] = []
    dislikes: List[str] = []


@app.post("/profiles")
def create_profile(body: ProfileIn):
    pid = create_document("profile", body.model_dump())
    return {"id": pid, "message": "Profile created"}


@app.get("/profiles")
def list_profiles(user_id: str = Query(...)):
    docs = get_documents("profile", {"user_id": user_id})
    # stringify ids
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- Ingredients ----------------------

class IngredientIn(BaseModel):
    name: str
    unit: Optional[str] = None
    calories_per_unit: Optional[float] = None
    tags: List[str] = []


@app.post("/ingredients")
def create_ingredient(body: IngredientIn):
    iid = create_document("ingredient", body.model_dump())
    return {"id": iid}


@app.get("/ingredients")
def list_ingredients(q: Optional[str] = None, limit: int = 100):
    flt: Dict = {}
    if q:
        flt = {"name": {"$regex": q, "$options": "i"}}
    docs = get_documents("ingredient", flt, limit)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- Products ----------------------

class ProductIn(BaseModel):
    name: str
    brand: Optional[str] = None
    ingredient_id: Optional[str] = None
    unit_size: Optional[str] = None
    calories_total: Optional[float] = None
    link: Optional[str] = None


@app.post("/products")
def create_product(body: ProductIn):
    pid = create_document("product", body.model_dump())
    return {"id": pid}


@app.get("/products")
def list_products(q: Optional[str] = None, limit: int = 100):
    flt: Dict = {}
    if q:
        flt = {"name": {"$regex": q, "$options": "i"}}
    docs = get_documents("product", flt, limit)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- Recipes ----------------------

class RecipeIngredientIn(BaseModel):
    ingredient_id: Optional[str] = None
    name: Optional[str] = None
    quantity: Optional[float] = None
    unit: Optional[str] = None


class RecipeIn(BaseModel):
    title: str
    description: Optional[str] = None
    type: Optional[str] = None
    tags: List[str] = []
    allergy_rating: Optional[str] = None
    ingredients: List[RecipeIngredientIn] = []
    steps: List[str] = []
    calories: Optional[float] = None
    author_user_id: Optional[str] = None


@app.post("/recipes")
def create_recipe(body: RecipeIn):
    rid = create_document("recipe", body.model_dump())
    return {"id": rid}


@app.get("/recipes")
def list_recipes(q: Optional[str] = None, tag: Optional[str] = None, type: Optional[str] = None, limit: int = 100):
    flt: Dict = {}
    if q:
        flt["title"] = {"$regex": q, "$options": "i"}
    if tag:
        flt["tags"] = tag
    if type:
        flt["type"] = type
    docs = get_documents("recipe", flt, limit)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- Meal Plans ----------------------

class MealPlanIn(BaseModel):
    user_id: str
    profile_id: Optional[str] = None
    date: date
    meals: Dict[str, List[str]] = {}


@app.post("/mealplans")
def create_mealplan(body: MealPlanIn):
    mid = create_document("mealplan", body.model_dump())
    return {"id": mid}


@app.get("/mealplans")
def list_mealplans(user_id: str = Query(...), start: Optional[date] = None, end: Optional[date] = None):
    flt: Dict = {"user_id": user_id}
    if start or end:
        rng: Dict = {}
        if start:
            rng["$gte"] = start.isoformat()
        if end:
            rng["$lte"] = end.isoformat()
        flt["date"] = rng
    docs = get_documents("mealplan", flt)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- Shopping List ----------------------

class ShoppingItemIn(BaseModel):
    user_id: str
    profile_id: Optional[str] = None
    name: str
    quantity: Optional[float] = None
    unit: Optional[str] = None
    checked: bool = False


@app.post("/shopping")
def add_shopping_item(body: ShoppingItemIn):
    sid = create_document("shoppinglistitem", body.model_dump())
    return {"id": sid}


@app.get("/shopping")
def list_shopping_items(user_id: str = Query(...), profile_id: Optional[str] = None):
    flt: Dict = {"user_id": user_id}
    if profile_id:
        flt["profile_id"] = profile_id
    docs = get_documents("shoppinglistitem", flt)
    for d in docs:
        d["id"] = str(d.pop("_id"))
    return docs


# ---------------------- AI Recipe from URL (basic) ----------------------

class AIRecipeResponse(BaseModel):
    title: Optional[str] = None
    ingredients: List[str] = []
    steps: List[str] = []
    notes: Optional[str] = None


@app.get("/ai/parse-recipe", response_model=AIRecipeResponse)
def ai_parse_recipe(url: str = Query(..., description="Social media or blog URL")):
    # Very light-weight heuristic parser (no external AI). Extracts page title and lines that look like ingredients.
    try:
        parsed = urlparse(url)
        if not parsed.scheme.startswith("http"):
            raise HTTPException(status_code=400, detail="Invalid URL")
        r = requests.get(url, timeout=10)
        text = r.text
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {e}")

    title = None
    if "<title>" in text and "</title>" in text:
        try:
            title = text.split("<title>", 1)[1].split("</title>", 1)[0].strip()
        except Exception:
            title = None

    # crude extraction of ingredient-like lines
    possible = []
    for line in text.splitlines():
        l = line.strip()
        if len(l) > 200:
            continue
        if any(unit in l.lower() for unit in ["g ", " ml", "cup", "tbsp", "tsp", "kg", "oz", "gram", "slice", "pinch"]) and \
           any(ch.isdigit() for ch in l):
            # remove html tags roughly
            cleaned = (
                l.replace("<li>", "").replace("</li>", "").replace("<span>", "").replace("</span>", "")
                .replace("&nbsp;", " ")
            )
            possible.append(cleaned)
        if len(possible) >= 20:
            break

    steps: List[str] = []
    # simple heuristic for steps using ordered list items
    if "<ol" in text and "</ol>" in text:
        try:
            ol = text.split("<ol", 1)[1].split("</ol>", 1)[0]
            parts = [p for p in ol.split("<li>") if "</li>" in p]
            for p in parts[:10]:
                steps.append(p.split("</li>", 1)[0])
        except Exception:
            steps = []

    return AIRecipeResponse(title=title, ingredients=possible, steps=steps, notes="Heuristic extraction. Refine manually if needed.")


# ---------------------- Root & Health ----------------------

@app.get("/")
def read_root():
    return {"message": "Modern Cookbook API running"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
