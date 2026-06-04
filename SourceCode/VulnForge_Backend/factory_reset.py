import asyncio
from utils.database import users_collection, scans_collection

async def clear():
    users = await users_collection.delete_many({})
    scans = await scans_collection.delete_many({})
    # If you have a targets collection, add it here too!
    
    print(f"Factory Reset Complete!")
    print(f"Deleted {users.deleted_count} Users")
    print(f"Deleted {scans.deleted_count} Scans")

asyncio.run(clear())
