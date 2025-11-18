"""
Database Schemas for Modern Cookbook

Each Pydantic model represents a collection in MongoDB. The collection name is the lowercase of the class name.

Use these schemas for validation and as a source of truth for the database viewer.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import date


class User(BaseModel):
    email: str = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Hashed password")
    name: Optional[str] = Field(None, description="Display name")


class Profile(BaseModel):
    user_id: str = Field(..., description="Owner user id")
    name: str = Field(..., description="Profile name (e.g., Alex, Bulking)")
    caloric_intake: Optional[int] = Field(None, ge=0, description="Daily calorie target")
    allergies: List[str] = Field(default_factory=list, description="Allergy list")
    macro_goals: Optional[Dict[str, float]] = Field(
        default=None,
        description="Optional macros per day: protein, carbs, fat (grams)",
    )
    likes: List[str] = Field(default_factory=list, description="Liked ingredients/foods")
    dislikes: List[str] = Field(default_factory=list, description="Disliked ingredients/foods")


class Ingredient(BaseModel):
    name: str = Field(..., description="Ingredient name")
    unit: Optional[str] = Field(None, description="Default unit, e.g., g, ml")
    calories_per_unit: Optional[float] = Field(
        None, ge=0, description="Calories per unit (kcal)"
    )
    tags: List[str] = Field(default_factory=list, description="Tags like vegan, gluten-free")


class Product(BaseModel):
    name: str = Field(..., description="Product name, e.g., Clever Frischkäse")
    brand: Optional[str] = Field(None, description="Brand name")
    ingredient_id: Optional[str] = Field(
        None, description="Linked base ingredient id if applicable"
    )
    unit_size: Optional[str] = Field(None, description="Package size, e.g., 200g")
    calories_total: Optional[float] = Field(None, ge=0, description="Total calories")
    link: Optional[str] = Field(None, description="Store/product URL")


class RecipeIngredient(BaseModel):
    ingredient_id: Optional[str] = Field(
        None, description="Reference to ingredient"
    )
    name: Optional[str] = Field(
        None, description="Free-text ingredient name if no reference"
    )
    quantity: Optional[float] = Field(None, ge=0)
    unit: Optional[str] = None


class Recipe(BaseModel):
    title: str
    description: Optional[str] = None
    type: Optional[str] = Field(None, description="Meal type: Breakfast, Lunch, Dinner, Snack")
    tags: List[str] = Field(default_factory=list)
    allergy_rating: Optional[str] = Field(
        None, description="Compatibility rating vs. user allergies"
    )
    ingredients: List[RecipeIngredient] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    calories: Optional[float] = Field(None, ge=0)
    author_user_id: Optional[str] = None


class MealPlan(BaseModel):
    user_id: str
    profile_id: Optional[str] = None
    date: date
    meals: Dict[str, List[str]] = Field(
        default_factory=dict, description="Map meal type -> list of recipe ids"
    )


class ShoppingListItem(BaseModel):
    user_id: str
    profile_id: Optional[str] = None
    name: str
    quantity: Optional[float] = None
    unit: Optional[str] = None
    checked: bool = False
