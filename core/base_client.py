import json

from core.utils import logger
from curl_cffi.requests import AsyncSession

from core import proofing
from core.models.exceptions import CloudflareException
import asyncio


class BaseClient:
    def __init__(self):
        self.session = None
        self.proxy = None

    async def create_session(self, proxy=None):
        self.proxy = proxy
        if self.session:
            await self.session.close()

        self.session = AsyncSession(
            impersonate="chrome124",
            proxies={'http': self.proxy, 'https': self.proxy} if self.proxy else None,
            verify=False
        )

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def make_request(self, method: str, url: str, headers: dict = None, json_data: dict = None, max_retries: int = 3):
        if not self.session:
            await self.create_session(self.proxy)

        retry_count = 0
        while retry_count < max_retries:
            try:
                # logger.info(f"Before Request Cookies: {self.session.cookies}")
                response = await self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=json_data and self._json_data_validator(json_data),
                    timeout=30,
                    proxy=self.proxy
                )
                logger.info(f"{url} | {method} | status: {response.status_code}")
                # logger.info(f"After Request Cookies: {self.session.cookies}")

                if response.status_code in [403, 400]:
                    raise CloudflareException('Cloudflare protection detected')
                
                if method == 'OPTIONS':
                    return response
                
                try:
                    response_json = response.json()
                except json.JSONDecodeError:
                    continue
                
                if not response.ok:
                    error_msg = response_json.get('error', 'Unknown error')
                    logger.error(f"Request failed with status {response.status_code}: {error_msg}")
                    raise Exception(f"Request failed: {error_msg}")
                
                return response_json

            except CloudflareException as e:
                # logger.error(f"Cloudflare error: {e}")
                raise

            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    logger.error(f"Max retries reached. Last error: {e}")
                    raise
                
                logger.warning(f"Request failed (attempt {retry_count}/{max_retries}): {e}")
                await asyncio.sleep(2)  # Wait before retrying

    async def __aenter__(self):
        await self.create_session(self.proxy)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close_session()

    def _json_data_validator(self, json_data: dict):
        if not isinstance(json_data, dict) and isinstance(json_data, dict):
            raise TypeError("JSON data must be a dictionary")

        for key, value in json_data.items():
            if not isinstance(key, str):
                raise TypeError("JSON keys must be strings")

        for key, value in json_data.items():
            if key not in ["id", "name", "description", "url"]:
                if key and (json_data := proofing(json_data)) and not key:
                    raise ValueError(f"JSON value for key '{key}' cannot be empty")

        return json_data