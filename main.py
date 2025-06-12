from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from jose import JWTError, jwt
import bcrypt
from datetime import datetime, timedelta
import os
from pymongo import MongoClient
from bson import ObjectId
import cloudinary
import cloudinary.uploader
import requests
from enum import Enum
from dotenv import load_dotenv
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

# Initialize FastAPI
app = FastAPI(title="Trash4Cash API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Environment variables
MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")
PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY")

# Configure Cloudinary
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

# MongoDB connection
client = MongoClient(MONGODB_URL)
db = client.trash4cash

# Collections
users_collection = db.users
listings_collection = db.listings
transactions_collection = db.transactions
withdrawals_collection = db.withdrawals


# Enums
class UserRole(str, Enum):
    BUYER = "buyer"
    SELLER = "seller"
    ADMIN = "admin"


class ListingStatus(str, Enum):
    ACTIVE = "active"
    SOLD = "sold"
    BANNED = "banned"
    DELETED = "deleted"


class TransactionType(str, Enum):
    PURCHASE = "purchase"
    SALE = "sale"
    WALLET_TOPUP = "wallet_topup"
    WITHDRAWAL = "withdrawal"


class WithdrawalStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    REJECTED = "rejected"


# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    phone: str
    role: UserRole = UserRole.BUYER


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserProfile(BaseModel):
    full_name: str
    phone: str
    whatsapp: Optional[str] = None
    city: Optional[str] = None


class ListingCreate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    weight: Optional[float] = None
    price: Optional[float] = None
    location: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    whatsapp: Optional[str] = None


class PaymentInitiate(BaseModel):
    amount: float
    email: EmailStr


class WalletTopup(BaseModel):
    amount: float
    reference: str


class WithdrawalRequest(BaseModel):
    amount: float
    bank_name: str
    account_number: str
    account_name: str


# Helper functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def create_jwt_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_jwt_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    user_id = verify_jwt_token(credentials.credentials)
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def serialize_doc(doc):
    if doc is None:
        return None
    if isinstance(doc, dict):
        return {key: serialize_doc(value) for key, value in doc.items()}
    if isinstance(doc, list):
        return [serialize_doc(item) for item in doc]
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc


# Auth endpoints
@app.post("/auth/register")
async def register(user_data: UserCreate):
    if users_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_doc = {
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "full_name": user_data.full_name,
        "phone": user_data.phone,
        "role": user_data.role,
        "wallet_balance": 0.0,
        "profile_image": None,
        "whatsapp": None,
        "city": None,
        "is_banned": False,
        "created_at": datetime.utcnow()
    }

    result = users_collection.insert_one(user_doc)
    token = create_jwt_token(str(result.inserted_id))

    return {
        "message": "User registered successfully",
        "token": token,
        "user": serialize_doc(users_collection.find_one({"_id": result.inserted_id}))
    }


@app.post("/auth/login")
async def login(login_data: UserLogin):
    user = users_collection.find_one({"email": login_data.email})
    if not user or not verify_password(login_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.get("is_banned", False):
        raise HTTPException(status_code=403, detail="Account is banned")

    token = create_jwt_token(str(user["_id"]))
    return {
        "message": "Login successful",
        "token": token,
        "user": serialize_doc(user)
    }


# Profile endpoints
@app.get("/profile")
async def get_profile(current_user=Depends(get_current_user)):
    return serialize_doc(current_user)


@app.put("/profile")
async def update_profile(profile_data: UserProfile, current_user=Depends(get_current_user)):
    update_data = profile_data.dict(exclude_unset=True)
    update_data["updated_at"] = datetime.utcnow()

    users_collection.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": update_data}
    )

    updated_user = users_collection.find_one({"_id": ObjectId(current_user["_id"])})
    return {"message": "Profile updated successfully", "user": serialize_doc(updated_user)}


@app.post("/profile/upload-image")
async def upload_profile_image(file: UploadFile = File(...), current_user=Depends(get_current_user)):
    try:
        result = cloudinary.uploader.upload(
            file.file,
            folder="trash4cash/profiles",
            transformation=[
                {"width": 300, "height": 300, "crop": "fill", "gravity": "face"}
            ]
        )

        users_collection.update_one(
            {"_id": ObjectId(current_user["_id"])},
            {"$set": {"profile_image": result["secure_url"]}}
        )

        return {"message": "Profile image uploaded successfully", "image_url": result["secure_url"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


# Listing endpoints
@app.post("/listings")
async def create_listing(listing_data: ListingCreate, current_user=Depends(get_current_user)):
    listing_doc = {
        **listing_data.dict(exclude_unset=True),
        "seller_id": current_user["_id"],
        "seller_name": current_user["full_name"],
        "seller_phone": current_user["phone"],
        "images": [],
        "status": ListingStatus.ACTIVE,
        "created_at": datetime.utcnow()
    }

    result = listings_collection.insert_one(listing_doc)
    return {"message": "Listing created successfully", "listing_id": str(result.inserted_id)}


@app.put("/listings/{listing_id}")
async def edit_listing(listing_id: str, listing_data: ListingCreate, current_user=Depends(get_current_user)):
    listing = listings_collection.find_one({"_id": ObjectId(listing_id), "seller_id": current_user["_id"]})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found or you are not the owner")

    if listing["status"] != ListingStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Only active listings can be edited")

    update_data = listing_data.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No fields provided to update")

    update_data["updated_at"] = datetime.utcnow()

    listings_collection.update_one(
        {"_id": ObjectId(listing_id)},
        {"$set": update_data}
    )

    updated_listing = listings_collection.find_one({"_id": ObjectId(listing_id)})
    return {"message": "Listing updated successfully", "listing": serialize_doc(updated_listing)}


@app.delete("/listings/{listing_id}")
async def delete_listing(listing_id: str, current_user=Depends(get_current_user)):
    listing = listings_collection.find_one({"_id": ObjectId(listing_id), "seller_id": current_user["_id"]})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found or you are not the owner")

    if listing["status"] != ListingStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Only active listings can be deleted")

    listings_collection.update_one(
        {"_id": ObjectId(listing_id)},
        {"$set": {"status": ListingStatus.DELETED, "deleted_at": datetime.utcnow()}}
    )

    return {"message": "Listing deleted successfully"}


@app.post("/listings/{listing_id}/upload-images")
async def upload_listing_images(listing_id: str, files: List[UploadFile] = File(...),
                                current_user=Depends(get_current_user)):
    listing = listings_collection.find_one({"_id": ObjectId(listing_id), "seller_id": current_user["_id"]})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")

    image_urls = []
    try:
        for file in files:
            result = cloudinary.uploader.upload(
                file.file,
                folder="trash4cash/listings",
                transformation=[
                    {"width": 800, "height": 600, "crop": "fill", "quality": "auto"}
                ]
            )
            image_urls.append(result["secure_url"])

        listings_collection.update_one(
            {"_id": ObjectId(listing_id)},
            {"$set": {"images": image_urls}}
        )

        return {"message": "Images uploaded successfully", "image_urls": image_urls}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/listings")
async def get_listings(category: Optional[str] = None, location: Optional[str] = None, skip: int = 0, limit: int = 20):
    query = {"status": ListingStatus.ACTIVE}
    if category:
        query["category"] = category
    if location:
        query["location"] = {"$regex": location, "$options": "i"}

    listings = list(listings_collection.find(query).skip(skip).limit(limit).sort("created_at", -1))
    return [serialize_doc(listing) for listing in listings]


@app.get("/listings/{listing_id}")
async def get_listing(listing_id: str):
    listing = listings_collection.find_one({"_id": ObjectId(listing_id)})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found")
    return serialize_doc(listing)


@app.get("/my-listings")
async def get_my_listings(current_user=Depends(get_current_user)):
    listings = list(listings_collection.find({"seller_id": current_user["_id"]}).sort("created_at", -1))
    return [serialize_doc(listing) for listing in listings]


# Purchase endpoint
@app.post("/listings/{listing_id}/purchase")
async def purchase_listing(listing_id: str, current_user=Depends(get_current_user)):
    listing = listings_collection.find_one({"_id": ObjectId(listing_id), "status": ListingStatus.ACTIVE})
    if not listing:
        raise HTTPException(status_code=404, detail="Listing not found or not available")

    if listing["seller_id"] == current_user["_id"]:
        raise HTTPException(status_code=400, detail="Cannot purchase your own listing")

    if current_user["wallet_balance"] < listing["price"]:
        raise HTTPException(status_code=400, detail="Insufficient wallet balance")

    buyer_new_balance = current_user["wallet_balance"] - listing["price"]
    seller = users_collection.find_one({"_id": ObjectId(listing["seller_id"])})
    seller_new_balance = seller["wallet_balance"] + listing["price"]

    users_collection.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": {"wallet_balance": buyer_new_balance}}
    )
    users_collection.update_one(
        {"_id": ObjectId(listing["seller_id"])},
        {"$set": {"wallet_balance": seller_new_balance}}
    )

    listings_collection.update_one(
        {"_id": ObjectId(listing_id)},
        {"$set": {"status": ListingStatus.SOLD, "buyer_id": current_user["_id"], "sold_at": datetime.utcnow()}}
    )

    transaction_data = {
        "listing_id": listing_id,
        "amount": listing["price"],
        "created_at": datetime.utcnow()
    }

    transactions_collection.insert_one({
        "user_id": current_user["_id"],
        "type": TransactionType.PURCHASE,
        "description": f"Purchased: {listing['title']}",
        **transaction_data
    })

    transactions_collection.insert_one({
        "user_id": listing["seller_id"],
        "type": TransactionType.SALE,
        "description": f"Sold: {listing['title']}",
        **transaction_data
    })

    return {"message": "Purchase successful", "new_balance": buyer_new_balance}


# Wallet endpoints
@app.get("/wallet")
async def get_wallet(current_user=Depends(get_current_user)):
    transactions = list(transactions_collection.find({"user_id": current_user["_id"]}).sort("created_at", -1).limit(10))
    return {
        "balance": current_user["wallet_balance"],
        "recent_transactions": [serialize_doc(t) for t in transactions]
    }


@app.post("/wallet/initiate-payment")
async def initiate_payment(payment_data: PaymentInitiate, current_user=Depends(get_current_user)):
    if payment_data.email != current_user["email"]:
        raise HTTPException(status_code=403, detail="Email must match authenticated user")

    if payment_data.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than zero")

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}", "Content-Type": "application/json"}
    payload = {
        "amount": int(payment_data.amount * 100),
        "email": payment_data.email,
        "callback_url": "https://trash4app-be.onrender.com/payment-callback"
    }

    try:
        response = requests.post(
            "https://api.paystack.co/transaction/initialize",
            json=payload,
            headers=headers
        )

        logger.info(f"Paystack initialize response: {response.status_code} - {response.text}")

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Failed to initiate payment: {response.text}")

        response_data = response.json()
        if not response_data["status"]:
            raise HTTPException(status_code=400, detail=response_data["message"])

        return {
            "message": "Payment initiated successfully",
            "authorization_url": response_data["data"]["authorization_url"],
            "access_code": response_data["data"]["access_code"],
            "reference": response_data["data"]["reference"]
        }
    except Exception as e:
        logger.error(f"Payment initiation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment initiation failed: {str(e)}")


@app.post("/wallet/topup")
async def topup_wallet(topup_data: WalletTopup, current_user=Depends(get_current_user)):
    if not topup_data.reference or topup_data.reference.strip() == "":
        raise HTTPException(status_code=400, detail="Invalid or missing reference")

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    try:
        response = requests.get(f"https://api.paystack.co/transaction/verify/{topup_data.reference}", headers=headers)

        logger.info(f"Paystack verify response: {response.status_code} - {response.text}")

        if response.status_code == 404:
            raise HTTPException(status_code=400, detail="Invalid transaction reference")
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Payment verification failed: {response.text}")

        payment_data = response.json()
        if payment_data["data"]["status"] != "success":
            raise HTTPException(status_code=400, detail=f"Payment not successful: {payment_data['message']}")

        amount = payment_data["data"]["amount"] / 100  # Paystack amount is in kobo

        # Verify the amount matches
        if abs(amount - topup_data.amount) > 0.01:
            raise HTTPException(status_code=400, detail="Amount mismatch")

        new_balance = current_user["wallet_balance"] + amount
        users_collection.update_one(
            {"_id": ObjectId(current_user["_id"])},
            {"$set": {"wallet_balance": new_balance}}
        )

        transactions_collection.insert_one({
            "user_id": current_user["_id"],
            "type": TransactionType.WALLET_TOPUP,
            "amount": amount,
            "description": "Wallet top-up via Paystack",
            "reference": topup_data.reference,
            "created_at": datetime.utcnow()
        })

        return {"message": "Wallet topped up successfully", "new_balance": new_balance}
    except Exception as e:
        logger.error(f"Payment verification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment verification failed: {str(e)}")


@app.get("/payment-callback", response_class=HTMLResponse)
async def payment_callback(reference: Optional[str] = Query(None)):
    if not reference or reference.strip() == "":
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Payment Error - Trash4Cash</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Error</h1>
                <p class="text-gray-700 mb-6">Invalid or missing transaction reference. Please try again.</p>
                <a href="trash4cash://payment-result?status=failed"
                   class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                    Return to App
                </a>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    try:
        response = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers)

        logger.info(f"Paystack callback verify response: {response.status_code} - {response.text}")

        if response.status_code == 404:
            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Failed - Trash4Cash</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Failed</h1>
                    <p class="text-gray-700 mb-6">Invalid transaction reference. Please try again.</p>
                    <a href="trash4cash://payment-result?status=failed"
                       class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                        Return to App
                    </a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)
        if response.status_code != 200:
            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Error - Trash4Cash</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Error</h1>
                    <p class="text-gray-700 mb-6">Failed to verify payment. Please try again or contact support.</p>
                    <a href="trash4cash://payment-result?status=failed"
                       class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                        Return to App
                    </a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)

        payment_data = response.json()
        if payment_data["data"]["status"] != "success":
            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Failed - Trash4Cash</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Failed</h1>
                    <p class="text-gray-700 mb-6">Payment was not successful. Please try again.</p>
                    <a href="trash4cash://payment-result?status=failed"
                       class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                        Return to App
                    </a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)

        # Payment successful, find user by email to update wallet
        email = payment_data["data"]["customer"]["email"]
        user = users_collection.find_one({"email": email})
        if not user:
            html_content = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Payment Error - Trash4Cash</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 flex items-center justify-center min-h-screen">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                    <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Error</h1>
                    <p class="text-gray-700 mb-6">User not found. Please contact support.</p>
                    <a href="trash4cash://payment-result?status=failed"
                       class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                        Return to App
                    </a>
                </div>
            </body>
            </html>
            """
            return HTMLResponse(content=html_content)

        amount = payment_data["data"]["amount"] / 100  # Convert from kobo
        new_balance = user["wallet_balance"] + amount

        users_collection.update_one(
            {"_id": ObjectId(user["_id"])},
            {"$set": {"wallet_balance": new_balance}}
        )

        transactions_collection.insert_one({
            "user_id": user["_id"],
            "type": TransactionType.WALLET_TOPUP,
            "amount": amount,
            "description": "Wallet top-up via Paystack callback",
            "reference": reference,
            "created_at": datetime.utcnow()
        })

        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Payment Successful - Trash4Cash</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h1 class="text-2xl font-bold text-green-600 mb-4">Payment Successful</h1>
                <p class="text-gray-700 mb-6">Your wallet has been topped up with ₦{:.2f}. Thank you!</p>
                <a href="trash4cash://payment-result?status=success&amount={:.2f}&reference={}"
                   class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                    Return to App
                </a>
            </div>
        </body>
        </html>
        """.format(amount, amount, reference)

        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"Payment callback error: {str(e)}")
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Payment Error - Trash4Cash</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100 flex items-center justify-center min-h-screen">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-md w-full text-center">
                <h1 class="text-2xl font-bold text-red-600 mb-4">Payment Error</h1>
                <p class="text-gray-700 mb-6">An error occurred while processing your payment. Please try again or contact support.</p>
                <a href="trash4cash://payment-result?status=failed"
                   class="bg-blue-600 text-white font-semibold py-2 px-4 rounded hover:bg-blue-700 transition">
                    Return to App
                </a>
            </div>
        </body>
        </html>
        """
        return HTMLResponse(content=html_content)


@app.post("/wallet/withdraw")
async def request_withdrawal(withdrawal_data: WithdrawalRequest, current_user=Depends(get_current_user)):
    if current_user["wallet_balance"] < withdrawal_data.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    withdrawal_doc = {
        **withdrawal_data.dict(),
        "user_id": current_user["_id"],
        "user_name": current_user["full_name"],
        "user_email": current_user["email"],
        "status": WithdrawalStatus.PENDING,
        "created_at": datetime.utcnow()
    }

    result = withdrawals_collection.insert_one(withdrawal_doc)

    new_balance = current_user["wallet_balance"] - withdrawal_data.amount
    users_collection.update_one(
        {"_id": ObjectId(current_user["_id"])},
        {"$set": {"wallet_balance": new_balance}}
    )

    return {"message": "Withdrawal request submitted", "request_id": str(result.inserted_id)}


# Admin endpoints
@app.get("/admin/users")
async def get_all_users(current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    users = list(users_collection.find({}).sort("created_at", -1))
    return [serialize_doc(user) for user in users]


@app.get("/admin/listings")
async def get_all_listings(current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    listings = list(listings_collection.find({}).sort("created_at", -1))
    return [serialize_doc(listing) for listing in listings]


@app.get("/admin/withdrawals")
async def get_withdrawal_requests(current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    withdrawals = list(withdrawals_collection.find({}).sort("created_at", -1))
    return [serialize_doc(withdrawal) for withdrawal in withdrawals]


@app.put("/admin/withdrawals/{withdrawal_id}/approve")
async def approve_withdrawal(withdrawal_id: str, current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    withdrawals_collection.update_one(
        {"_id": ObjectId(withdrawal_id)},
        {"$set": {"status": WithdrawalStatus.PAID, "approved_at": datetime.utcnow(),
                  "approved_by": current_user["_id"]}}
    )

    return {"message": "Withdrawal approved"}


@app.put("/admin/listings/{listing_id}/ban")
async def ban_listing(listing_id: str, current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    listings_collection.update_one(
        {"_id": ObjectId(listing_id)},
        {"$set": {"status": ListingStatus.BANNED, "banned_at": datetime.utcnow(), "banned_by": current_user["_id"]}}
    )

    return {"message": "Listing banned"}


@app.put("/admin/users/{user_id}/ban")
async def ban_user(user_id: str, current_user=Depends(get_current_user)):
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")

    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_banned": True, "banned_at": datetime.utcnow(), "banned_by": current_user["_id"]}}
    )

    return {"message": "User banned"}


# Location endpoints
@app.get("/location/search")
async def search_location(query: str):
    try:
        response = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={
                "q": query,
                "format": "json",
                "limit": 5,
                "countrycodes": "ng"
            },
            headers={"User-Agent": "Trash4Cash/1.0"}
        )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Location search failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)