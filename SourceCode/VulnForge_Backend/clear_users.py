import asyncio
from utils.database import users_collection

async def clear():
    result = await users_collection.delete_many({})
    print(f"Success! Deleted {result.deleted_count} user accounts.")

asyncio.run(clear())
