"""Database configuration and client initialization."""

import os
from typing import Union
from dotenv import load_dotenv
from supabase import create_client, Client

# Load environment variables
load_dotenv()

# Get Supabase credentials from environment
SUPABASE_URL: Union[str, None] = os.getenv("SUPABASE_URL")
SUPABASE_KEY: Union[str, None] = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing required Supabase environment variables")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
