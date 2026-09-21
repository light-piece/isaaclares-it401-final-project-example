import os

from dotenv import load_dotenv


load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
    DATA_DIR = os.path.join(BASE_DIR, "data")

    # External API keys / service config
    API_KEY = os.environ.get("API_KEY")
    NVD_API_KEY = os.environ.get("NVD_API_KEY")
    NVD_API_URL = os.environ.get(
        "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )
    CISA_KEV_URL = os.environ.get(
        "CISA_KEV_URL",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
    AI_SERVICE_API_KEY = os.environ.get("AI_SERVICE_API_KEY")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
