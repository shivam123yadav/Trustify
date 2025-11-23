from database.db_connection import users_collection, records_collection

print("✅ Connection successful!")

test_user = {"name": "Test User", "email": "test@example.com"}
result = users_collection.insert_one(test_user)
print("Inserted user with ID:", result.inserted_id)

user = users_collection.find_one({"_id": result.inserted_id})
print("Fetched from DB:", user)
