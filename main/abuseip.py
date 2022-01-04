import os
from dotenv import load_dotenv

load_dotenv()

vt = os.getenv("VT_API")
gsb = os.getenv("GSB_API")
abuse = os.getenv("ABUSE_API")
